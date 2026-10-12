"""Application factory: builds the FastAPI app with all security middleware.

Run locally:  python -m saboss_platform serve
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .auth import CsrfError, LoginRequired, PermissionDenied, csrf_cookie_name
from .config import Settings, get_settings
from .db import Database, run_migrations
from .ratelimit import RateLimiter
from .scan.worker import ScanWorker
from .web import render

logger = logging.getLogger("saboss.app")
STATIC_DIR = Path(__file__).parent / "static"

# Our own pages follow the advice Saboss Scan gives to others.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line: easy to search in any log system."""

    FIELDS = ("request_id", "method", "path", "status", "duration_ms", "scan_id")

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for name in self.FIELDS:
            if hasattr(record, name):
                entry[name] = getattr(record, name)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger("saboss")
    root.handlers = [handler]
    root.setLevel(settings.log_level)
    root.propagate = False


def _is_api(request: Request) -> bool:
    return request.url.path.startswith("/api/")


def _api_error(status: int, code: str, message: str, **extra) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, **extra}}, status_code=status)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)
    run_migrations(settings.database_url)
    database = Database(settings.database_url)
    limiter = RateLimiter()
    worker = ScanWorker(database, settings, limiter)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        worker.start()
        yield
        worker.stop()

    app = FastAPI(
        title="Saboss Scan API",
        version=__version__,
        description="Passive security assessment of domains you are authorized to assess.",
        docs_url=None,  # Swagger UI loads scripts from a CDN; the in-app API page is used instead
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.limiter = limiter
    app.state.worker = worker

    @app.middleware("http")
    async def security_and_logging(request: Request, call_next):
        request_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        started = time.monotonic()
        response = await call_next(request)

        headers = response.headers
        headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["X-Request-ID"] = request_id
        if settings.cookie_secure:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            headers.setdefault("Cache-Control", "no-store")

        token = getattr(request.state, "csrf_token", None)
        if token and request.cookies.get(csrf_cookie_name(settings)) != token:
            response.set_cookie(
                csrf_cookie_name(settings),
                token,
                httponly=True,
                samesite="strict",
                secure=settings.cookie_secure,
                path="/",
            )

        # Only the path is logged: query strings can contain tokens.
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": int((time.monotonic() - started) * 1000),
            },
        )
        return response

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------ errors
    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, _exc: LoginRequired):
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(PermissionDenied)
    async def _forbidden(request: Request, exc: PermissionDenied):
        if _is_api(request):
            return _api_error(403, "forbidden", exc.message)
        return render(request, "error.html", status_code=403, title="Not allowed", message=exc.message)

    @app.exception_handler(CsrfError)
    async def _csrf(request: Request, _exc: CsrfError):
        message = "This form has expired or was sent from another site. Go back, reload the page and try again."
        return render(request, "error.html", status_code=403, title="Form expired", message=message)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        if _is_api(request):
            codes = {
                401: "unauthorized",
                403: "forbidden",
                404: "not_found",
                409: "conflict",
                422: "validation_error",
                429: "rate_limited",
            }
            return _api_error(exc.status_code, codes.get(exc.status_code, "error"), str(exc.detail))
        titles = {404: "Page not found", 405: "Not allowed", 429: "Too many requests"}
        return render(
            request,
            "error.html",
            status_code=exc.status_code,
            title=titles.get(exc.status_code, "Something went wrong"),
            message=str(exc.detail) if exc.status_code != 404 else "This page does not exist.",
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        # Report which fields are wrong, but never echo the submitted values back.
        fields = [
            {"field": ".".join(str(part) for part in err.get("loc", [])[1:]), "message": err.get("msg", "")}
            for err in exc.errors()
        ]
        if _is_api(request):
            return _api_error(422, "validation_error", "The request is not valid.", fields=fields)
        return render(
            request, "error.html", status_code=400, title="Invalid request", message="Check the form and try again."
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        logger.exception("unhandled error", extra={"request_id": getattr(request.state, "request_id", "")})
        if _is_api(request):
            return _api_error(500, "internal_error", "An internal error occurred.")
        return PlainTextResponse("An internal error occurred. It has been logged.", status_code=500)

    # ------------------------------------------------------------ health
    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return RedirectResponse("/static/favicon.svg", status_code=301)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        try:
            with database.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception:
            logger.exception("readiness check failed")
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}

    # ------------------------------------------------------------ routers
    from .routes_account import router as account_router
    from .routes_settings import router as settings_router
    from .scan.routes_api import router as scan_api_router
    from .scan.routes_web import nav_counts
    from .scan.routes_web import router as scan_web_router

    app.state.nav_counts = nav_counts
    app.include_router(account_router)
    app.include_router(settings_router)
    app.include_router(scan_web_router)
    app.include_router(scan_api_router)
    return app
