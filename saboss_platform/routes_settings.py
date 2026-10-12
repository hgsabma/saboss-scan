"""Account, organization, members, API keys, notifications and audit log."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saboss_scan.http_client import FetchError
from saboss_scan.network_safety import resolve_public_ip
from saboss_scan.utils import InvalidTargetError, normalize_domain

from .audit import record
from .auth import WebContext, client_ip, create_session, end_all_sessions, membership_for, session_cookie_name
from .db import utcnow
from .deps import csrf_protect, current_user, get_db
from .models import ADMIN, MEMBER, OWNER, ROLES, VIEWER, ApiKey, AuditLog, Membership, Organization, User
from .notifications import send_webhook
from .security import hash_password, hash_token, new_api_key, password_problem, verify_password
from .web import redirect, render

router = APIRouter(prefix="/settings")
AUDIT_PAGE_SIZE = 50


def _audit(db: Session, request: Request, ctx: WebContext, action: str, target: str = "", **details) -> None:
    record(
        db,
        action,
        organization_id=ctx.organization.id,
        user_id=ctx.user.id,
        actor=ctx.actor,
        target=target,
        details=details,
        ip_address=client_ip(request),
    )


# ------------------------------------------------------------------- account


@router.get("", include_in_schema=False)
def account(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    organizations = [m for m in ctx.user.memberships]
    return render(request, "settings/account.html", ctx, memberships=organizations, tab="account")


@router.post("/profile", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def update_profile(
    request: Request,
    name: str = Form(..., max_length=100),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not name.strip():
        return redirect(request, "/settings", "Enter a name.", "error")
    ctx.user.name = name.strip()
    db.commit()
    return redirect(request, "/settings", "Profile updated.")


@router.post("/password", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def change_password(
    request: Request,
    current_password: str = Form(..., max_length=200),
    new_password: str = Form(..., max_length=200),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    settings = request.app.state.settings
    if not request.app.state.limiter.hit(f"password:{ctx.user.id}", 5, 900):
        return redirect(request, "/settings", "Too many attempts. Try again in 15 minutes.", "error")
    if not verify_password(ctx.user.password_hash, current_password):
        return redirect(request, "/settings", "The current password is incorrect.", "error")
    problem = password_problem(new_password, ctx.user.email)
    if problem:
        return redirect(request, "/settings", problem, "error")

    ctx.user.password_hash = hash_password(new_password)
    end_all_sessions(db, ctx.user.id)  # sign out other devices
    token = create_session(db, settings, ctx.user, ctx.organization.id, request.headers.get("user-agent", ""))
    _audit(db, request, ctx, "user.password_changed")
    db.commit()
    response = redirect(request, "/settings", "Password changed. Other devices have been signed out.")
    response.set_cookie(
        session_cookie_name(settings),
        token,
        max_age=settings.session_max_age_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return response


@router.post("/switch-organization", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def switch_organization(
    request: Request,
    organization_id: int = Form(...),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    if membership_for(db, ctx.user.id, organization_id) is None:
        raise HTTPException(status_code=404, detail="Organization not found.")
    ctx.session.organization_id = organization_id
    db.commit()
    return redirect(request, "/dashboard", "Switched organization.")


@router.post("/organizations", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def create_organization(
    request: Request,
    name: str = Form(..., max_length=100),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not name.strip():
        return redirect(request, "/settings", "Enter an organization name.", "error")
    owned = db.scalar(
        select(func.count()).select_from(Membership).where(Membership.user_id == ctx.user.id, Membership.role == OWNER)
    )
    if (owned or 0) >= 10:
        return redirect(request, "/settings", "You can own at most 10 organizations.", "error")
    org = Organization(name=name.strip())
    db.add(org)
    db.flush()
    db.add(Membership(user_id=ctx.user.id, organization_id=org.id, role=OWNER))
    ctx.session.organization_id = org.id
    record(
        db,
        "org.create",
        organization_id=org.id,
        user_id=ctx.user.id,
        actor=ctx.actor,
        target=org.name,
        ip_address=client_ip(request),
    )
    db.commit()
    return redirect(request, "/dashboard", f"Created {org.name}.")


# -------------------------------------------------------------- organization


@router.get("/organization", include_in_schema=False)
def organization(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    members = list(
        db.scalars(select(Membership).where(Membership.organization_id == ctx.organization.id).order_by(Membership.id))
    )
    return render(request, "settings/organization.html", ctx, members=members, roles=ROLES, tab="organization")


@router.post("/organization", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def rename_organization(
    request: Request,
    name: str = Form(..., max_length=100),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    if not name.strip():
        return redirect(request, "/settings/organization", "Enter a name.", "error")
    ctx.organization.name = name.strip()
    _audit(db, request, ctx, "org.rename", name.strip())
    db.commit()
    return redirect(request, "/settings/organization", "Organization renamed.")


@router.post("/members", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def add_member(
    request: Request,
    email: str = Form(..., max_length=254),
    role: str = Form(MEMBER),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    if role not in (ADMIN, MEMBER, VIEWER) or (role == ADMIN and ctx.role != OWNER):
        return redirect(request, "/settings/organization", "You cannot give that role.", "error")
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None:
        return redirect(
            request,
            "/settings/organization",
            "No Saboss account uses that e-mail address. Ask the person to register first, then add them.",
            "error",
        )
    if membership_for(db, user.id, ctx.organization.id):
        return redirect(request, "/settings/organization", "That person is already a member.", "info")
    db.add(Membership(user_id=user.id, organization_id=ctx.organization.id, role=role))
    _audit(db, request, ctx, "org.member_added", user.email, role=role)
    db.commit()
    return redirect(request, "/settings/organization", f"Added {user.email} as {role}.")


def _owner_count(db: Session, organization_id: int) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.organization_id == organization_id, Membership.role == OWNER)
        )
        or 0
    )


@router.post("/members/{membership_id}/role", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def change_role(
    request: Request,
    membership_id: int,
    role: str = Form(...),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != ctx.organization.id:
        raise HTTPException(status_code=404, detail="Member not found.")
    if role not in ROLES:
        return redirect(request, "/settings/organization", "Unknown role.", "error")
    # Only owners can create or change owners and admins.
    if ctx.role != OWNER and (role in (OWNER, ADMIN) or membership.role in (OWNER, ADMIN)):
        return redirect(request, "/settings/organization", "Only an owner can change owners and admins.", "error")
    if membership.role == OWNER and role != OWNER and _owner_count(db, ctx.organization.id) <= 1:
        return redirect(request, "/settings/organization", "An organization needs at least one owner.", "error")
    membership.role = role
    _audit(db, request, ctx, "org.member_role_changed", membership.user.email, role=role)
    db.commit()
    return redirect(request, "/settings/organization", "Role updated.")


@router.post("/members/{membership_id}/remove", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def remove_member(
    request: Request, membership_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    ctx.require(ADMIN)
    membership = db.get(Membership, membership_id)
    if membership is None or membership.organization_id != ctx.organization.id:
        raise HTTPException(status_code=404, detail="Member not found.")
    if ctx.role != OWNER and membership.role in (OWNER, ADMIN):
        return redirect(request, "/settings/organization", "Only an owner can remove owners and admins.", "error")
    if membership.role == OWNER and _owner_count(db, ctx.organization.id) <= 1:
        return redirect(request, "/settings/organization", "An organization needs at least one owner.", "error")
    email = membership.user.email
    db.delete(membership)
    _audit(db, request, ctx, "org.member_removed", email)
    db.commit()
    if membership.user_id == ctx.user.id:
        return redirect(request, "/dashboard", "You left the organization.")
    return redirect(request, "/settings/organization", f"Removed {email}.")


# ------------------------------------------------------------------ API keys


@router.get("/api-keys", include_in_schema=False)
def api_keys(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    ctx.require(ADMIN)
    keys = list(
        db.scalars(select(ApiKey).where(ApiKey.organization_id == ctx.organization.id).order_by(ApiKey.id.desc()))
    )
    return render(request, "settings/api_keys.html", ctx, keys=keys, tab="api-keys")


@router.post("/api-keys", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def create_api_key(
    request: Request,
    name: str = Form(..., max_length=100),
    role: str = Form(MEMBER),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    if role not in (MEMBER, VIEWER):
        role = VIEWER
    active = db.scalar(
        select(func.count())
        .select_from(ApiKey)
        .where(ApiKey.organization_id == ctx.organization.id, ApiKey.revoked_at.is_(None))
    )
    if (active or 0) >= 20:
        return redirect(request, "/settings/api-keys", "Revoke unused keys first (maximum 20).", "error")
    key = new_api_key()
    api_key = ApiKey(
        organization_id=ctx.organization.id,
        name=name.strip() or "API key",
        prefix=key[:12],
        key_hash=hash_token(key),
        role=role,
        created_by_id=ctx.user.id,
    )
    db.add(api_key)
    _audit(db, request, ctx, "apikey.created", api_key.name, prefix=api_key.prefix, role=role)
    db.commit()
    keys = list(
        db.scalars(select(ApiKey).where(ApiKey.organization_id == ctx.organization.id).order_by(ApiKey.id.desc()))
    )
    # The full key is shown exactly once, in this response, and never stored.
    return render(request, "settings/api_keys.html", ctx, keys=keys, new_key=key, tab="api-keys")


@router.post("/api-keys/{key_id}/revoke", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def revoke_api_key(
    request: Request, key_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    ctx.require(ADMIN)
    api_key = db.get(ApiKey, key_id)
    if api_key is None or api_key.organization_id != ctx.organization.id:
        raise HTTPException(status_code=404, detail="API key not found.")
    if api_key.revoked_at is None:
        api_key.revoked_at = utcnow()
        _audit(db, request, ctx, "apikey.revoked", api_key.name, prefix=api_key.prefix)
        db.commit()
    return redirect(request, "/settings/api-keys", "API key revoked.")


# ------------------------------------------------------------- notifications


@router.get("/notifications", include_in_schema=False)
def notifications(request: Request, ctx: WebContext = Depends(current_user)):
    ctx.require(ADMIN)
    return render(
        request,
        "settings/notifications.html",
        ctx,
        tab="notifications",
        email_configured=request.app.state.settings.email_configured,
    )


def _validate_webhook(url: str) -> str | None:
    if not url.startswith("https://"):
        return "The webhook URL must start with https://."
    try:
        host = normalize_domain(url)  # rejects IPs, internal names, credentials, custom ports
        if resolve_public_ip(host) is None:  # rejects names pointing to private addresses
            return "The webhook host could not be resolved."
    except InvalidTargetError as exc:
        return f"This webhook address is not allowed: {exc}"
    return None


@router.post("/notifications", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def update_notifications(
    request: Request,
    notify_email: str = Form(""),
    webhook_url: str = Form("", max_length=500),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    webhook_url = webhook_url.strip()
    if webhook_url:
        problem = _validate_webhook(webhook_url)
        if problem:
            return redirect(request, "/settings/notifications", problem, "error")
    ctx.organization.notify_email = bool(notify_email)
    ctx.organization.webhook_url = webhook_url or None
    _audit(db, request, ctx, "notifications.updated", email=bool(notify_email), webhook=bool(webhook_url))
    db.commit()
    return redirect(request, "/settings/notifications", "Notification settings saved.")


@router.post("/notifications/test-webhook", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def test_webhook(request: Request, ctx: WebContext = Depends(current_user)):
    ctx.require(ADMIN)
    if not request.app.state.limiter.hit(f"webhook-test:{ctx.organization.id}", 5, 3600):
        return redirect(request, "/settings/notifications", "Too many test messages. Try again later.", "error")
    try:
        result = send_webhook(ctx.organization.webhook_url, {"event": "test", "message": "Saboss Scan webhook test"})
    except FetchError as exc:  # pragma: no cover - send_webhook already catches this
        result = str(exc)
    level = "success" if "delivered" in result else "error"
    return redirect(request, "/settings/notifications", f"Test result: {result}", level)


# ----------------------------------------------------------------- audit log


@router.get("/audit", include_in_schema=False)
def audit_log(
    request: Request,
    page: int = 1,
    action: str = "",
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(ADMIN)
    page = max(page, 1)
    query = select(AuditLog).where(AuditLog.organization_id == ctx.organization.id)
    if action:
        query = query.where(AuditLog.action == action)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    entries = list(
        db.scalars(query.order_by(AuditLog.id.desc()).offset((page - 1) * AUDIT_PAGE_SIZE).limit(AUDIT_PAGE_SIZE))
    )
    actions = list(
        db.scalars(
            select(AuditLog.action)
            .where(AuditLog.organization_id == ctx.organization.id)
            .distinct()
            .order_by(AuditLog.action)
        )
    )
    pages = max((total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE, 1)
    return render(
        request,
        "settings/audit.html",
        ctx,
        entries=entries,
        page=page,
        pages=pages,
        total=total,
        actions=actions,
        action=action,
        tab="audit",
    )


# ------------------------------------------------------------------- API docs


@router.get("/api", include_in_schema=False)
def api_docs(request: Request, ctx: WebContext = Depends(current_user)):
    return render(request, "settings/api_docs.html", ctx, tab="api", base_url=request.app.state.settings.base_url)
