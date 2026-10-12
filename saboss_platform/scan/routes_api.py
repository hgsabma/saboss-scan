"""Saboss Scan REST API (version 1).

Authentication: ``Authorization: Bearer sbk_...`` with an organization API key
(created under Settings > API keys). Keys with the "member" role can add
domains and start scans; "viewer" keys can only read.

Errors always look like: {"error": {"code": "...", "message": "..."}}
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import record
from ..auth import ApiContext, client_ip
from ..deps import api_client, get_db
from ..models import MEMBER
from .models import SCAN_STATES, Domain, Scan
from .pdf import render_pdf
from .service import ScanError, add_domain, create_scan

router = APIRouter(prefix="/api/v1", tags=["Saboss Scan"])
API_REQUESTS_PER_MINUTE = 120


def rate_limited_client(request: Request, client: ApiContext = Depends(api_client)) -> ApiContext:
    if not request.app.state.limiter.hit(f"api:{client.api_key.id}", API_REQUESTS_PER_MINUTE, 60):
        raise HTTPException(status_code=429, detail="Rate limit exceeded (120 requests per minute per key).")
    return client


def _require_member(client: ApiContext) -> None:
    if not client.can(MEMBER):
        raise HTTPException(status_code=403, detail="This API key is read-only.")


# ------------------------------------------------------------------- schemas


class DomainIn(BaseModel):
    hostname: str = Field(..., max_length=253, examples=["example.com"])
    authorized: bool = Field(
        ..., description="Must be true: you confirm that you own the domain or are authorized to assess it."
    )


class DomainOut(BaseModel):
    id: int
    hostname: str
    verified: bool
    monitoring: bool
    monitor_interval_hours: int
    created_at: datetime


class ScanIn(BaseModel):
    domain_id: int


class ScanOut(BaseModel):
    id: int
    domain_id: int
    hostname: str
    status: str
    source: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    grade: str | None
    score: int | None
    error: str | None
    report: dict[str, Any] | None = None


class Pagination(BaseModel):
    page: int
    per_page: int
    total: int


class DomainList(BaseModel):
    data: list[DomainOut]
    pagination: Pagination


class ScanList(BaseModel):
    data: list[ScanOut]
    pagination: Pagination


def _domain_out(domain: Domain) -> DomainOut:
    return DomainOut(
        id=domain.id,
        hostname=domain.hostname,
        verified=domain.verified_at is not None,
        monitoring=domain.monitor_enabled,
        monitor_interval_hours=domain.monitor_interval_hours,
        created_at=domain.created_at,
    )


def _scan_out(scan: Scan, include_report: bool = False) -> ScanOut:
    return ScanOut(
        id=scan.id,
        domain_id=scan.domain_id,
        hostname=scan.hostname,
        status=scan.status,
        source=scan.source,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        grade=scan.grade,
        score=scan.score_percentage,
        error=scan.error or None,
        report=scan.report if include_report else None,
    )


def _own_domain(db: Session, client: ApiContext, domain_id: int) -> Domain:
    domain = db.get(Domain, domain_id)
    if domain is None or domain.organization_id != client.organization.id:
        raise HTTPException(status_code=404, detail="Domain not found.")
    return domain


def _own_scan(db: Session, client: ApiContext, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.organization_id != client.organization.id:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


# ------------------------------------------------------------------- domains


@router.get("/domains", response_model=DomainList, summary="List domains")
def list_domains(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    client: ApiContext = Depends(rate_limited_client),
    db: Session = Depends(get_db),
):
    query = select(Domain).where(Domain.organization_id == client.organization.id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(Domain.hostname).offset((page - 1) * per_page).limit(per_page))
    return DomainList(
        data=[_domain_out(d) for d in items], pagination=Pagination(page=page, per_page=per_page, total=total)
    )


@router.post("/domains", response_model=DomainOut, status_code=201, summary="Add a domain")
def create_domain(
    body: DomainIn, request: Request, client: ApiContext = Depends(rate_limited_client), db: Session = Depends(get_db)
):
    _require_member(client)
    if not body.authorized:
        raise HTTPException(status_code=422, detail="Set authorized=true to confirm you may assess this domain.")
    try:
        domain = add_domain(db, client.organization, body.hostname, client.actor)
    except ScanError as exc:
        db.rollback()
        raise HTTPException(status_code=409 if "already" in str(exc) else 422, detail=str(exc)) from None
    record(
        db,
        "domain.created",
        organization_id=client.organization.id,
        actor=client.actor,
        target=domain.hostname,
        details={"authorization_confirmed": True, "via": "api"},
        ip_address=client_ip(request),
    )
    db.commit()
    return _domain_out(domain)


@router.get("/domains/{domain_id}", response_model=DomainOut, summary="Get a domain")
def get_domain(domain_id: int, client: ApiContext = Depends(rate_limited_client), db: Session = Depends(get_db)):
    return _domain_out(_own_domain(db, client, domain_id))


# --------------------------------------------------------------------- scans


@router.get("/scans", response_model=ScanList, summary="List scans")
def list_scans(
    domain_id: int | None = None,
    status: str | None = Query(None, description="queued, running, completed or failed"),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    client: ApiContext = Depends(rate_limited_client),
    db: Session = Depends(get_db),
):
    query = select(Scan).where(Scan.organization_id == client.organization.id)
    if domain_id is not None:
        query = query.where(Scan.domain_id == domain_id)
    if status:
        if status not in SCAN_STATES:
            raise HTTPException(status_code=422, detail=f"status must be one of: {', '.join(SCAN_STATES)}.")
        query = query.where(Scan.status == status)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    items = db.scalars(query.order_by(Scan.id.desc()).offset((page - 1) * per_page).limit(per_page))
    return ScanList(
        data=[_scan_out(s) for s in items], pagination=Pagination(page=page, per_page=per_page, total=total)
    )


@router.post("/scans", response_model=ScanOut, status_code=202, summary="Start a scan")
def start_scan(
    body: ScanIn, request: Request, client: ApiContext = Depends(rate_limited_client), db: Session = Depends(get_db)
):
    """Queue a scan. Poll GET /api/v1/scans/{id} until status is completed or failed."""
    _require_member(client)
    domain = _own_domain(db, client, body.domain_id)
    try:
        scan = create_scan(db, request.app.state.settings, request.app.state.limiter, domain, client.actor, "api")
    except ScanError as exc:
        db.rollback()
        code = 429 if "limit" in str(exc) else 409
        raise HTTPException(status_code=code, detail=str(exc)) from None
    record(
        db,
        "scan.created",
        organization_id=client.organization.id,
        actor=client.actor,
        target=domain.hostname,
        details={"scan_id": scan.id, "via": "api"},
        ip_address=client_ip(request),
    )
    db.commit()
    request.app.state.worker.submit(scan.id)
    db.refresh(scan)
    return _scan_out(scan)


@router.get("/scans/{scan_id}", response_model=ScanOut, summary="Get a scan and its report")
def get_scan(scan_id: int, client: ApiContext = Depends(rate_limited_client), db: Session = Depends(get_db)):
    return _scan_out(_own_scan(db, client, scan_id), include_report=True)


@router.get(
    "/scans/{scan_id}/report.pdf",
    summary="Download the PDF report",
    responses={200: {"content": {"application/pdf": {}}}},
)
def get_scan_pdf(scan_id: int, client: ApiContext = Depends(rate_limited_client), db: Session = Depends(get_db)):
    scan = _own_scan(db, client, scan_id)
    if not scan.report:
        raise HTTPException(status_code=404, detail="This scan has no report.")
    return Response(render_pdf(scan.report), media_type="application/pdf")
