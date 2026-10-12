"""Registration, login, logout and password reset."""

from __future__ import annotations

import logging
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import record
from .auth import WebContext, client_ip, create_session, end_all_sessions, session_cookie_name
from .db import utcnow
from .deps import csrf_protect, current_user, get_db, optional_user
from .models import OWNER, Membership, Organization, PasswordResetToken, User
from .notifications import send_email
from .security import (
    hash_password,
    hash_token,
    new_token,
    password_needs_rehash,
    password_problem,
    verify_password,
)
from .web import redirect, render, safe_next

router = APIRouter()
logger = logging.getLogger("saboss.account")

EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
RESET_TOKEN_HOURS = 1


def _clean_email(value: str) -> str:
    return value.strip().lower()[:254]


def _set_session_cookie(request: Request, response: RedirectResponse, token: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(
        session_cookie_name(settings),
        token,
        max_age=settings.session_max_age_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def _limited(request: Request, key: str, limit: int, seconds: int) -> bool:
    return not request.app.state.limiter.hit(key, limit, seconds)


@router.get("/", include_in_schema=False)
def home(request: Request, ctx: WebContext | None = Depends(optional_user)):
    if ctx:
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "landing.html")


# ------------------------------------------------------------------ register


@router.get("/register", include_in_schema=False)
def register_form(request: Request, ctx: WebContext | None = Depends(optional_user)):
    if ctx:
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "auth/register.html", registration_open=request.app.state.settings.registration_open)


@router.post("/register", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def register(
    request: Request,
    name: str = Form(..., max_length=100),
    email: str = Form(..., max_length=254),
    organization: str = Form("", max_length=100),
    password: str = Form(..., max_length=200),
    db: Session = Depends(get_db),
):
    settings = request.app.state.settings
    email = _clean_email(email)
    form = {"name": name, "email": email, "organization": organization}

    def fail(message: str):
        return render(request, "auth/register.html", status_code=400, error=message, form=form, registration_open=True)

    if not settings.registration_open:
        return render(request, "auth/register.html", status_code=403, registration_open=False)
    if _limited(request, f"register:{client_ip(request)}", 5, 3600):
        return fail("Too many sign-ups from your network. Try again later.")
    if not name.strip():
        return fail("Enter your name.")
    if not EMAIL_PATTERN.match(email):
        return fail("Enter a valid e-mail address.")
    problem = password_problem(password, email)
    if problem:
        return fail(problem)
    if db.scalar(select(User).where(User.email == email)):
        return fail("An account with this e-mail address already exists. Log in instead.")

    user = User(email=email, name=name.strip(), password_hash=hash_password(password))
    org = Organization(name=organization.strip() or f"{name.strip()}'s organization")
    db.add_all([user, org])
    db.flush()
    db.add(Membership(user_id=user.id, organization_id=org.id, role=OWNER))
    record(db, "user.register", organization_id=org.id, user_id=user.id, actor=email, ip_address=client_ip(request))
    token = create_session(db, settings, user, org.id, request.headers.get("user-agent", ""))
    user.last_login_at = utcnow()
    db.commit()

    response = redirect(request, "/dashboard", "Welcome to Saboss Scan. Add your first domain to get started.")
    _set_session_cookie(request, response, token)
    return response


# --------------------------------------------------------------------- login


@router.get("/login", include_in_schema=False)
def login_form(request: Request, next: str = "", ctx: WebContext | None = Depends(optional_user)):
    if ctx:
        return RedirectResponse(safe_next(next), status_code=303)
    return render(request, "auth/login.html", next=safe_next(next) if next else "")


@router.post("/login", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def login(
    request: Request,
    email: str = Form(..., max_length=254),
    password: str = Form(..., max_length=200),
    next: str = Form(""),
    db: Session = Depends(get_db),
):
    settings = request.app.state.settings
    email = _clean_email(email)
    ip = client_ip(request)

    def fail(message: str, status: int = 400):
        return render(request, "auth/login.html", status_code=status, error=message, email=email, next=next)

    if _limited(request, f"login:ip:{ip}", 20, 900) or _limited(request, f"login:email:{email}", 5, 900):
        return fail("Too many login attempts. Wait 15 minutes and try again.", 429)

    user = db.scalar(select(User).where(User.email == email))
    # verify_password always does the same amount of work, even for unknown e-mails.
    if not verify_password(user.password_hash if user else None, password) or not user.is_active:
        record(db, "user.login_failed", actor=email, ip_address=ip)
        db.commit()
        return fail("The e-mail address or password is incorrect.")

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    membership = sorted(user.memberships, key=lambda m: m.id)[0] if user.memberships else None
    token = create_session(
        db, settings, user, membership.organization_id if membership else None, request.headers.get("user-agent", "")
    )
    user.last_login_at = utcnow()
    record(
        db,
        "user.login",
        organization_id=membership.organization_id if membership else None,
        user_id=user.id,
        actor=email,
        ip_address=ip,
    )
    db.commit()

    response = RedirectResponse(safe_next(next), status_code=303)
    _set_session_cookie(request, response, token)
    return response


@router.post("/logout", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def logout(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    record(
        db,
        "user.logout",
        organization_id=ctx.organization.id,
        user_id=ctx.user.id,
        actor=ctx.actor,
        ip_address=client_ip(request),
    )
    db.delete(db.merge(ctx.session))
    db.commit()
    response = redirect(request, "/login", "You have been logged out.", "info")
    response.delete_cookie(session_cookie_name(request.app.state.settings), path="/")
    return response


# ------------------------------------------------------------ password reset


GENERIC_RESET_MESSAGE = (
    "If an account exists for that e-mail address, a reset link has been sent. The link is valid for one hour."
)


@router.get("/forgot-password", include_in_schema=False)
def forgot_form(request: Request):
    return render(request, "auth/forgot.html", email_configured=request.app.state.settings.email_configured)


@router.post("/forgot-password", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def forgot(request: Request, email: str = Form(..., max_length=254), db: Session = Depends(get_db)):
    settings = request.app.state.settings
    email = _clean_email(email)
    ip = client_ip(request)
    allowed = not _limited(request, f"reset:ip:{ip}", 5, 3600) and not _limited(
        request, f"reset:email:{email}", 3, 3600
    )
    user = db.scalar(select(User).where(User.email == email)) if allowed else None

    if user and user.is_active:
        token = new_token()
        db.add(
            PasswordResetToken(
                token_hash=hash_token(token),
                user_id=user.id,
                expires_at=utcnow() + timedelta(hours=RESET_TOKEN_HOURS),
            )
        )
        record(db, "user.password_reset_requested", user_id=user.id, actor=email, ip_address=ip)
        db.commit()
        link = f"{settings.base_url}/reset-password?token={token}"
        result = send_email(
            settings,
            [user.email],
            "Reset your Saboss password",
            f"Someone asked to reset the password for your Saboss account.\n\n{link}\n\n"
            "The link is valid for one hour. If this was not you, ignore this e-mail.",
        )
        if not settings.email_configured and not settings.is_production:
            # Development convenience only. Never enabled in production.
            logger.warning("DEVELOPMENT ONLY - e-mail is not configured. Password reset link: %s", link)
        elif "sent" not in result:
            logger.warning("password reset e-mail not delivered: %s", result)

    # Same answer whether or not the account exists (no account enumeration).
    return render(
        request,
        "auth/forgot.html",
        sent=True,
        message=GENERIC_RESET_MESSAGE,
        email_configured=settings.email_configured,
    )


def _valid_reset_token(db: Session, token: str) -> PasswordResetToken | None:
    reset = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token)))
    if reset is None or reset.used_at is not None or reset.expires_at < utcnow():
        return None
    return reset


@router.get("/reset-password", include_in_schema=False)
def reset_form(request: Request, token: str = "", db: Session = Depends(get_db)):  # nosec B107 - empty default, not a password
    valid = bool(token) and _valid_reset_token(db, token) is not None
    return render(request, "auth/reset.html", token=token if valid else "", invalid=not valid)


@router.post("/reset-password", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def reset(
    request: Request,
    token: str = Form(..., max_length=200),
    password: str = Form(..., max_length=200),
    db: Session = Depends(get_db),
):
    reset_token = _valid_reset_token(db, token)
    if reset_token is None:
        return render(request, "auth/reset.html", status_code=400, invalid=True, token="")  # nosec B106 - empty value, not a password
    user = db.get(User, reset_token.user_id)
    problem = password_problem(password, user.email)
    if problem:
        return render(request, "auth/reset.html", status_code=400, token=token, error=problem)

    user.password_hash = hash_password(password)
    reset_token.used_at = utcnow()
    end_all_sessions(db, user.id)  # log out everywhere after a reset
    record(db, "user.password_reset", user_id=user.id, actor=user.email, ip_address=client_ip(request))
    db.commit()
    return redirect(request, "/login", "Your password has been changed. Log in with the new password.")
