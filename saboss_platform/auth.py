"""Authentication, authorization and CSRF protection.

Web pages use a session cookie. API clients use an organization API key in the
Authorization header (no cookies, so the API is not exposed to CSRF).

CSRF protection for forms uses two layers:
1. A random token in a cookie that must match a hidden form field
   ("double submit"). In production the cookie uses the __Host- prefix so it
   cannot be set by other subdomains.
2. If the browser sends an Origin header, it must be our own origin.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import utcnow
from .models import ApiKey, Membership, Organization, User, UserSession, role_at_least
from .security import constant_time_equal, hash_token, new_token

CSRF_FIELD = "csrf_token"


def session_cookie_name(settings: Settings) -> str:
    return "__Host-saboss_session" if settings.cookie_secure else "saboss_session"


def csrf_cookie_name(settings: Settings) -> str:
    return "__Host-saboss_csrf" if settings.cookie_secure else "saboss_csrf"


class LoginRequired(Exception):
    """Raised by page handlers; the app turns it into a redirect to /login."""


class PermissionDenied(Exception):
    def __init__(self, message: str = "You do not have permission to do that."):
        super().__init__(message)
        self.message = message


class CsrfError(Exception):
    pass


@dataclass
class WebContext:
    user: User
    organization: Organization
    role: str
    session: UserSession

    def can(self, minimum_role: str) -> bool:
        return role_at_least(self.role, minimum_role)

    def require(self, minimum_role: str) -> None:
        if not self.can(minimum_role):
            raise PermissionDenied()

    @property
    def actor(self) -> str:
        return self.user.email


@dataclass
class ApiContext:
    organization: Organization
    role: str
    api_key: ApiKey

    def can(self, minimum_role: str) -> bool:
        return role_at_least(self.role, minimum_role)

    @property
    def actor(self) -> str:
        return f"api-key:{self.api_key.prefix}"


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ------------------------------------------------------------------ sessions


def create_session(db: Session, settings: Settings, user: User, organization_id: int | None, user_agent: str) -> str:
    """Create a new session and return the raw token for the cookie."""
    token = new_token()
    now = utcnow()
    db.add(
        UserSession(
            token_hash=hash_token(token),
            user_id=user.id,
            organization_id=organization_id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=settings.session_max_age_hours),
            user_agent=user_agent[:200],
        )
    )
    return token


def end_all_sessions(db: Session, user_id: int) -> None:
    for session in db.scalars(select(UserSession).where(UserSession.user_id == user_id)):
        db.delete(session)


def load_web_context(request: Request, db: Session, settings: Settings) -> WebContext | None:
    token = request.cookies.get(session_cookie_name(settings))
    if not token:
        return None
    session = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if session is None:
        return None

    now = utcnow()
    idle_limit = session.last_seen_at + timedelta(hours=settings.session_idle_hours)
    if now >= session.expires_at or now >= idle_limit or not session.user.is_active:
        db.delete(session)
        db.commit()
        return None

    memberships = {m.organization_id: m for m in session.user.memberships}
    membership = memberships.get(session.organization_id) if session.organization_id else None
    if membership is None and memberships:
        membership = sorted(memberships.values(), key=lambda m: m.id)[0]
        session.organization_id = membership.organization_id
    if membership is None:
        return None

    # Only write last_seen occasionally to avoid a database write per request.
    if now - session.last_seen_at > timedelta(minutes=5):
        session.last_seen_at = now
    db.commit()
    return WebContext(user=session.user, organization=membership.organization, role=membership.role, session=session)


def membership_for(db: Session, user_id: int, organization_id: int) -> Membership | None:
    return db.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.organization_id == organization_id)
    )


# ------------------------------------------------------------------ API keys


def load_api_context(request: Request, db: Session) -> ApiContext | None:
    header = request.headers.get("authorization", "")
    scheme, _, key = header.partition(" ")
    if scheme.lower() != "bearer" or not key.strip():
        return None
    api_key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(key.strip())))
    if api_key is None or api_key.revoked_at is not None:
        return None
    organization = db.get(Organization, api_key.organization_id)
    if organization is None:
        return None
    now = utcnow()
    if api_key.last_used_at is None or now - api_key.last_used_at > timedelta(minutes=5):
        api_key.last_used_at = now
        db.commit()
    return ApiContext(organization=organization, role=api_key.role, api_key=api_key)


# ---------------------------------------------------------------------- CSRF


def ensure_csrf_token(request: Request, settings: Settings) -> str:
    """Return the CSRF token for this browser, creating one if needed."""
    token = getattr(request.state, "csrf_token", None)
    if token:
        return token
    token = request.cookies.get(csrf_cookie_name(settings)) or new_token()
    request.state.csrf_token = token
    return token


async def verify_csrf(request: Request, settings: Settings) -> None:
    origin = request.headers.get("origin")
    if origin and origin != "null":
        allowed = {settings.base_url, f"{request.url.scheme}://{request.url.netloc}"}
        if origin.rstrip("/") not in allowed:
            raise CsrfError()
    elif origin == "null":
        raise CsrfError()

    cookie_token = request.cookies.get(csrf_cookie_name(settings), "")
    form = await request.form()
    form_token = str(form.get(CSRF_FIELD, ""))
    if not cookie_token or not form_token or not constant_time_equal(cookie_token, form_token):
        raise CsrfError()
