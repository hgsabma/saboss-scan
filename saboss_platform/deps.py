"""FastAPI dependencies shared by all routers."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .auth import ApiContext, LoginRequired, WebContext, load_api_context, load_web_context, verify_csrf
from .config import Settings


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    yield from request.app.state.database.sessions()


def optional_user(request: Request, db: Session = Depends(get_db)) -> WebContext | None:
    return load_web_context(request, db, request.app.state.settings)


def current_user(request: Request, db: Session = Depends(get_db)) -> WebContext:
    context = load_web_context(request, db, request.app.state.settings)
    if context is None:
        raise LoginRequired()
    return context


async def csrf_protect(request: Request) -> None:
    await verify_csrf(request, request.app.state.settings)


def api_client(request: Request, db: Session = Depends(get_db)) -> ApiContext:
    context = load_api_context(request, db)
    if context is None:
        raise HTTPException(status_code=401, detail="A valid API key is required (Authorization: Bearer sbk_...).")
    return context
