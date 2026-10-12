"""Saboss Scan web pages: dashboard, domains, scans, reports and alerts."""

from __future__ import annotations

import json
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saboss_scan.html_report import render_html

from ..audit import record
from ..auth import WebContext, client_ip
from ..db import utcnow
from ..deps import csrf_protect, current_user, get_db
from ..models import ADMIN, MEMBER
from ..web import redirect, render
from .models import COMPLETED, MONITOR_INTERVALS, QUEUED, RUNNING, SCAN_STATES, Alert, Domain, Scan
from .pdf import render_pdf
from .service import (
    ScanError,
    add_domain,
    compare_reports,
    create_scan,
    previous_completed_scan,
    update_monitoring,
    verify_domain_ownership,
)

router = APIRouter()
PAGE_SIZE = 25
GRADES = ("A", "B", "C", "D", "E", "N/A")
SCAN_SORTS = {
    "newest": Scan.id.desc(),
    "oldest": Scan.id.asc(),
    "score_desc": Scan.score_percentage.desc(),
    "score_asc": Scan.score_percentage.asc(),
}
FINDING_STATUS_ORDER = ["fail", "warning", "not_checked", "pass", "not_applicable"]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CATEGORY_TITLES = {"tls": "HTTPS / TLS", "http_headers": "HTTP security", "dns": "DNS", "email": "E-mail security"}


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


def _domain(db: Session, ctx: WebContext, domain_id: int) -> Domain:
    domain = db.get(Domain, domain_id)
    # 404 (not 403) for other organizations' objects: do not reveal that they exist.
    if domain is None or domain.organization_id != ctx.organization.id:
        raise HTTPException(status_code=404, detail="Domain not found.")
    return domain


def _scan(db: Session, ctx: WebContext, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.organization_id != ctx.organization.id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def _latest_scans_by_domain(db: Session, organization_id: int) -> dict[int, Scan]:
    latest_ids = (
        select(func.max(Scan.id))
        .where(Scan.organization_id == organization_id, Scan.status == COMPLETED)
        .group_by(Scan.domain_id)
    )
    return {scan.domain_id: scan for scan in db.scalars(select(Scan).where(Scan.id.in_(latest_ids)))}


def _sparkline(scores: list[int], width: int = 240, height: int = 48) -> str:
    """SVG polyline points for a small score-history chart (scores 0-100)."""
    if len(scores) < 2:
        return ""
    step = width / (len(scores) - 1)
    return " ".join(f"{i * step:.1f},{height - (score / 100) * height:.1f}" for i, score in enumerate(scores))


def _safe_filename(hostname: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", hostname.lower())[:100]


# ----------------------------------------------------------------- dashboard


@router.get("/dashboard", include_in_schema=False)
def dashboard(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    org_id = ctx.organization.id
    domains = list(db.scalars(select(Domain).where(Domain.organization_id == org_id).order_by(Domain.hostname)))
    latest = _latest_scans_by_domain(db, org_id)
    recent = list(db.scalars(select(Scan).where(Scan.organization_id == org_id).order_by(Scan.id.desc()).limit(8)))
    since = utcnow() - timedelta(days=30)
    scans_30d = (
        db.scalar(
            select(func.count()).select_from(Scan).where(Scan.organization_id == org_id, Scan.created_at >= since)
        )
        or 0
    )
    unread_alerts = (
        db.scalar(
            select(func.count()).select_from(Alert).where(Alert.organization_id == org_id, Alert.read_at.is_(None))
        )
        or 0
    )
    scored = [scan.score_percentage for scan in latest.values() if scan.score_percentage is not None]
    attention = sorted(
        (scan for scan in latest.values() if scan.grade in ("D", "E")),
        key=lambda scan: scan.score_percentage or 0,
    )
    return render(
        request,
        "scan/dashboard.html",
        ctx,
        domains=domains,
        latest=latest,
        recent=recent,
        stats={
            "domains": len(domains),
            "verified": sum(1 for d in domains if d.verified_at),
            "monitored": sum(1 for d in domains if d.monitor_enabled),
            "scans_30d": scans_30d,
            "unread_alerts": unread_alerts,
            "average_score": round(sum(scored) / len(scored)) if scored else None,
            "scored_domains": len(scored),
        },
        attention=attention,
    )


# ------------------------------------------------------------------- domains


@router.get("/domains", include_in_schema=False)
def domains(
    request: Request,
    q: str = "",
    sort: str = "name",
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    query = select(Domain).where(Domain.organization_id == ctx.organization.id)
    if q:
        query = query.where(Domain.hostname.contains(q.strip().lower()[:100], autoescape=True))
    query = query.order_by(Domain.created_at.desc() if sort == "newest" else Domain.hostname)
    items = list(db.scalars(query))
    latest = _latest_scans_by_domain(db, ctx.organization.id)
    if sort == "score":
        items.sort(
            key=lambda d: (
                latest[d.id].score_percentage if d.id in latest and latest[d.id].score_percentage is not None else 101
            )
        )
    return render(request, "scan/domains.html", ctx, domains=items, latest=latest, q=q, sort=sort)


@router.post("/domains", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def create_domain(
    request: Request,
    hostname: str = Form(..., max_length=300),
    authorized: str = Form(""),
    scan_now: str = Form(""),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(MEMBER)
    if not authorized:
        return redirect(request, "/domains", "Confirm that you are authorized to assess this domain.", "error")
    try:
        domain = add_domain(db, ctx.organization, hostname, ctx.actor)
    except ScanError as exc:
        db.rollback()
        return redirect(request, "/domains", str(exc), "error")
    _audit(db, request, ctx, "domain.created", domain.hostname, authorization_confirmed=True)
    db.commit()
    if scan_now:
        return _start_scan(request, ctx, db, domain)
    return redirect(request, f"/domains/{domain.id}", f"Added {domain.hostname}.")


@router.get("/domains/{domain_id}", include_in_schema=False)
def domain_detail(
    request: Request, domain_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    domain = _domain(db, ctx, domain_id)
    scans = list(db.scalars(select(Scan).where(Scan.domain_id == domain.id).order_by(Scan.id.desc()).limit(50)))
    completed = [s for s in reversed(scans) if s.status == COMPLETED and s.score_percentage is not None]
    latest = next((s for s in scans if s.status == COMPLETED), None)
    return render(
        request,
        "scan/domain_detail.html",
        ctx,
        domain=domain,
        scans=scans,
        latest=latest,
        sparkline=_sparkline([s.score_percentage for s in completed][-20:]),
        intervals=MONITOR_INTERVALS,
        active=any(s.status in (QUEUED, RUNNING) for s in scans),
    )


@router.post("/domains/{domain_id}/verify", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def verify_domain(
    request: Request, domain_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    ctx.require(MEMBER)
    domain = _domain(db, ctx, domain_id)
    if not request.app.state.limiter.hit(f"verify:{domain.id}", 10, 3600):
        return redirect(request, f"/domains/{domain.id}", "Too many verification attempts. Try again later.", "error")
    verified, message = verify_domain_ownership(db, domain)
    if verified:
        _audit(db, request, ctx, "domain.verified", domain.hostname)
    db.commit()
    return redirect(request, f"/domains/{domain.id}", message, "success" if verified else "error")


@router.post("/domains/{domain_id}/monitoring", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def domain_monitoring(
    request: Request,
    domain_id: int,
    enabled: str = Form(""),
    interval: int = Form(24),
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    ctx.require(MEMBER)
    domain = _domain(db, ctx, domain_id)
    try:
        update_monitoring(domain, bool(enabled), interval)
    except ScanError as exc:
        return redirect(request, f"/domains/{domain.id}", str(exc), "error")
    _audit(db, request, ctx, "monitoring.updated", domain.hostname, enabled=bool(enabled), interval_hours=interval)
    db.commit()
    message = "Monitoring enabled." if domain.monitor_enabled else "Monitoring turned off."
    return redirect(request, f"/domains/{domain.id}", message)


@router.post("/domains/{domain_id}/delete", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def delete_domain(
    request: Request, domain_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    ctx.require(ADMIN)
    domain = _domain(db, ctx, domain_id)
    hostname = domain.hostname
    db.delete(domain)
    _audit(db, request, ctx, "domain.deleted", hostname)
    db.commit()
    return redirect(request, "/domains", f"Deleted {hostname} and its scan history.")


# --------------------------------------------------------------------- scans


def _start_scan(request: Request, ctx: WebContext, db: Session, domain: Domain):
    try:
        scan = create_scan(db, request.app.state.settings, request.app.state.limiter, domain, ctx.actor, "manual")
    except ScanError as exc:
        db.rollback()
        return redirect(request, f"/domains/{domain.id}", str(exc), "error")
    _audit(db, request, ctx, "scan.created", domain.hostname, scan_id=scan.id)
    db.commit()
    request.app.state.worker.submit(scan.id)
    return redirect(request, f"/scans/{scan.id}")


@router.post("/domains/{domain_id}/scan", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def scan_domain_now(
    request: Request, domain_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)
):
    ctx.require(MEMBER)
    return _start_scan(request, ctx, db, _domain(db, ctx, domain_id))


@router.get("/scans", include_in_schema=False)
def scans(
    request: Request,
    q: str = "",
    status: str = "",
    grade: str = "",
    sort: str = "newest",
    page: int = 1,
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    page = max(page, 1)
    query = select(Scan).where(Scan.organization_id == ctx.organization.id)
    if q:
        query = query.where(Scan.hostname.contains(q.strip().lower()[:100], autoescape=True))
    if status in SCAN_STATES:
        query = query.where(Scan.status == status)
    if grade in GRADES:
        query = query.where(Scan.grade == grade)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    order = SCAN_SORTS.get(sort, SCAN_SORTS["newest"])
    items = list(db.scalars(query.order_by(order, Scan.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)))
    pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    return render(
        request,
        "scan/scans.html",
        ctx,
        scans=items,
        total=total,
        page=page,
        pages=pages,
        q=q,
        status=status,
        grade_filter=grade,
        sort=sort,
        states=SCAN_STATES,
        grades=GRADES,
    )


@router.get("/scans/{scan_id}", include_in_schema=False)
def scan_detail(
    request: Request,
    scan_id: int,
    status: str = "",
    severity: str = "",
    category: str = "",
    ctx: WebContext = Depends(current_user),
    db: Session = Depends(get_db),
):
    scan = _scan(db, ctx, scan_id)
    report = scan.report
    findings, comparison = [], None
    if report:
        findings = report["findings"]
        if status:
            findings = [f for f in findings if f["status"] == status]
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if category:
            findings = [f for f in findings if f["category"] == category]
        findings = sorted(
            findings,
            key=lambda f: (FINDING_STATUS_ORDER.index(f["status"]), SEVERITY_ORDER.index(f["severity"])),
        )
        previous = previous_completed_scan(db, scan)
        if previous:
            comparison = compare_reports(previous.report, report)
            comparison.previous_scan_id = previous.id
    return render(
        request,
        "scan/scan_detail.html",
        ctx,
        scan=scan,
        report=report,
        findings=findings,
        comparison=comparison,
        filters={"status": status, "severity": severity, "category": category},
        categories=CATEGORY_TITLES,
        severities=SEVERITY_ORDER,
        statuses=FINDING_STATUS_ORDER,
    )


@router.get("/scans/{scan_id}/status", include_in_schema=False)
def scan_status(scan_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    scan = _scan(db, ctx, scan_id)
    return JSONResponse({"status": scan.status, "finished": scan.is_finished})


def _report_or_404(scan: Scan) -> dict:
    if scan.status != COMPLETED or not scan.report:
        raise HTTPException(status_code=404, detail="This scan has no report.")
    return scan.report


@router.get("/scans/{scan_id}/report.json", include_in_schema=False)
def export_json(scan_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    scan = _scan(db, ctx, scan_id)
    body = json.dumps(_report_or_404(scan), indent=2, ensure_ascii=False)
    filename = f"saboss-scan-{_safe_filename(scan.hostname)}-{scan.id}.json"
    return Response(
        body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/scans/{scan_id}/report.pdf", include_in_schema=False)
def export_pdf(scan_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    scan = _scan(db, ctx, scan_id)
    report = _report_or_404(scan)
    scope = (
        f"Requested by {scan.requested_by or 'unknown'} ({scan.source}). "
        f"Authorization to assess {scan.hostname} was confirmed by {scan.domain.authorization_confirmed_by} "
        f"on {scan.domain.authorization_confirmed_at:%Y-%m-%d}."
    )
    filename = f"saboss-scan-{_safe_filename(scan.hostname)}-{scan.id}.pdf"
    return Response(
        render_pdf(report, scope),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.html", include_in_schema=False)
def export_html(scan_id: int, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    scan = _scan(db, ctx, scan_id)
    response = HTMLResponse(render_html(_report_or_404(scan)))
    # The standalone report has inline styles and no scripts.
    response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return response


# -------------------------------------------------------------------- alerts


@router.get("/alerts", include_in_schema=False)
def alerts(request: Request, show: str = "all", ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    query = select(Alert).where(Alert.organization_id == ctx.organization.id)
    if show == "unread":
        query = query.where(Alert.read_at.is_(None))
    items = list(db.scalars(query.order_by(Alert.id.desc()).limit(100)))
    return render(request, "scan/alerts.html", ctx, alerts=items, show=show)


@router.post("/alerts/read", include_in_schema=False, dependencies=[Depends(csrf_protect)])
def mark_alerts_read(request: Request, ctx: WebContext = Depends(current_user), db: Session = Depends(get_db)):
    now = utcnow()
    for alert in db.scalars(select(Alert).where(Alert.organization_id == ctx.organization.id, Alert.read_at.is_(None))):
        alert.read_at = now
    db.commit()
    return redirect(request, "/alerts", "All alerts marked as read.")


def nav_counts(request: Request, ctx: WebContext) -> dict[str, int]:
    """Numbers shown in the navigation on every page."""
    with request.app.state.database.session() as db:
        unread = db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.organization_id == ctx.organization.id, Alert.read_at.is_(None))
        )
    return {"unread_alerts": unread or 0}
