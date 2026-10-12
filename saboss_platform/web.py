"""Helpers for server-rendered pages: templates, flash messages, redirects."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import __version__
from .auth import CSRF_FIELD, WebContext, ensure_csrf_token

TEMPLATE_DIR = Path(__file__).parent / "templates"
FLASH_COOKIE = "saboss_flash"
FLASH_LEVELS = {"success", "error", "info"}

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))  # autoescaping is on for .html


def _datetime(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return value.strftime(fmt) + " UTC" if value else "—"


def _query(request: Request, **changes: Any) -> str:
    """Current query string with some parameters replaced (for filters/pagination)."""
    params = dict(request.query_params)
    for key, value in changes.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = str(value)
    return "?" + urlencode(params) if params else "?"


def _asset_version() -> str:
    """Changes whenever a static file changes, so browsers fetch the new version."""
    static = Path(__file__).parent / "static"
    return str(max(int(f.stat().st_mtime) for f in static.iterdir() if f.is_file()))


templates.env.filters["dt"] = _datetime
templates.env.globals["asset_version"] = _asset_version()
templates.env.globals["query"] = _query
templates.env.globals["version"] = __version__
templates.env.globals["CSRF_FIELD"] = CSRF_FIELD


def render(
    request: Request,
    template: str,
    context: WebContext | None = None,
    status_code: int = 200,
    **values: Any,
) -> HTMLResponse:
    settings = request.app.state.settings
    flash = None
    raw_flash = request.cookies.get(FLASH_COOKIE)
    if raw_flash:
        try:
            data = json.loads(raw_flash)
            if data.get("level") in FLASH_LEVELS:
                flash = {"level": data["level"], "message": str(data.get("message", ""))[:300]}
        except (ValueError, AttributeError):
            flash = None
    # Products can add counters to the navigation (e.g. unread alerts).
    nav_counts = {}
    provider = getattr(request.app.state, "nav_counts", None)
    if context is not None and provider is not None:
        nav_counts = provider(request, context)
    response = templates.TemplateResponse(
        request,
        template,
        {
            **nav_counts,
            "ctx": context,
            "csrf_token": ensure_csrf_token(request, settings),
            "flash": flash,
            "path": request.url.path,
            **values,
        },
        status_code=status_code,
    )
    if raw_flash:
        response.delete_cookie(FLASH_COOKIE, path="/")
    return response


def redirect(request: Request, url: str, message: str | None = None, level: str = "success") -> RedirectResponse:
    response = RedirectResponse(url, status_code=303)
    if message:
        response.set_cookie(
            FLASH_COOKIE,
            json.dumps({"level": level, "message": message[:300]}),
            max_age=60,
            httponly=True,
            samesite="lax",
            secure=request.app.state.settings.cookie_secure,
            path="/",
        )
    return response


def safe_next(value: str | None) -> str:
    """Only allow redirects to our own pages (prevents open redirects)."""
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/dashboard"
