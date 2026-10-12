"""Saboss Scan business logic: running scans, comparing results, alerts.

Kept separate from the web routes so it can be tested directly and reused by
the API, the web UI and the scheduler.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from saboss_scan import __version__ as engine_version
from saboss_scan.dns_checker import _safe_resolve
from saboss_scan.scanner import scan_domain
from saboss_scan.utils import InvalidTargetError, normalize_domain

from ..audit import record
from ..config import Settings
from ..db import utcnow
from ..models import ADMIN, Membership, Organization, User, role_at_least
from ..notifications import send_email, send_webhook
from ..ratelimit import RateLimiter
from ..security import new_token
from .models import COMPLETED, FAILED, QUEUED, RUNNING, Alert, Domain, Scan

logger = logging.getLogger("saboss.scan")

MAX_DOMAINS_PER_ORG = 100
STATUS_RANK = {"pass": 0, "not_applicable": 0, "not_checked": 0, "warning": 1, "fail": 2}


class ScanError(Exception):
    """A user-facing error (message is safe to show)."""


# ------------------------------------------------------------------- domains


def add_domain(db: Session, organization: Organization, raw_hostname: str, confirmed_by: str) -> Domain:
    """Add a domain the organization is authorized to assess."""
    try:
        hostname = normalize_domain(raw_hostname)
    except InvalidTargetError as exc:
        raise ScanError(str(exc)) from None

    existing = db.scalar(select(Domain).where(Domain.organization_id == organization.id, Domain.hostname == hostname))
    if existing:
        raise ScanError(f"{hostname} is already in this organization.")
    count = db.scalar(select(func.count()).select_from(Domain).where(Domain.organization_id == organization.id))
    if (count or 0) >= MAX_DOMAINS_PER_ORG:
        raise ScanError(f"An organization can have at most {MAX_DOMAINS_PER_ORG} domains.")

    domain = Domain(
        organization_id=organization.id,
        hostname=hostname,
        authorization_confirmed_by=confirmed_by,
        verification_token=new_token()[:32],
    )
    db.add(domain)
    db.flush()
    return domain


def verify_domain_ownership(db: Session, domain: Domain) -> tuple[bool, str]:
    """Check the DNS TXT record that proves control of the domain."""
    records, error = _safe_resolve(domain.verification_record_name, "TXT")
    if error:
        return False, f"DNS lookup failed: {error}"
    if domain.verification_record_value in records:
        domain.verified_at = utcnow()
        return True, "Ownership verified."
    return False, (
        f"The TXT record was not found. Add a TXT record at {domain.verification_record_name} "
        f"with the value {domain.verification_record_value}. DNS changes can take a few minutes."
    )


def update_monitoring(domain: Domain, enabled: bool, interval_hours: int) -> None:
    if enabled and domain.verified_at is None:
        raise ScanError("Verify ownership of the domain before enabling monitoring.")
    if interval_hours not in (24, 168):
        raise ScanError("Choose a daily or weekly interval.")
    domain.monitor_interval_hours = interval_hours
    if enabled and not domain.monitor_enabled:
        domain.next_scan_at = utcnow()
    domain.monitor_enabled = enabled
    if not enabled:
        domain.next_scan_at = None


# --------------------------------------------------------------------- scans


def create_scan(
    db: Session,
    settings: Settings,
    limiter: RateLimiter,
    domain: Domain,
    requested_by: str,
    source: str,
) -> Scan:
    """Queue a scan, enforcing per-organization limits."""
    active = db.scalar(select(Scan).where(Scan.domain_id == domain.id, Scan.status.in_((QUEUED, RUNNING))))
    if active is not None:
        raise ScanError(f"A scan of {domain.hostname} is already in progress.")
    if not limiter.hit(f"scan:org:{domain.organization_id}", settings.scans_per_org_per_hour, 3600):
        raise ScanError(
            f"Scan limit reached ({settings.scans_per_org_per_hour} per hour for an organization). Try again later."
        )
    scan = Scan(
        organization_id=domain.organization_id,
        domain_id=domain.id,
        hostname=domain.hostname,
        source=source,
        requested_by=requested_by,
        status=QUEUED,
    )
    db.add(scan)
    db.flush()
    return scan


def run_scan(db: Session, settings: Settings, scan_id: int) -> None:
    """Execute a queued scan and store the result. Never raises."""
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != QUEUED:
        return
    scan.status = RUNNING
    scan.started_at = utcnow()
    db.commit()

    started = time.monotonic()
    try:
        report = scan_domain(scan.hostname)
    except InvalidTargetError as exc:
        scan.status = FAILED
        scan.error = str(exc)[:500]
    except Exception:  # never leak internals into the UI; details go to the log
        logger.exception("scan %s failed unexpectedly", scan_id)
        scan.status = FAILED
        scan.error = "The scan failed because of an internal error. It has been logged."
    else:
        scan.status = COMPLETED
        scan.report_json = json.dumps(report, ensure_ascii=False)
        scan.score_percentage = report["score"]["percentage"]
        scan.grade = report["score"]["grade"]
        scan.engine_version = engine_version
    scan.finished_at = utcnow()
    db.commit()
    logger.info(
        "scan finished",
        extra={"scan_id": scan_id, "status": scan.status, "duration_ms": int((time.monotonic() - started) * 1000)},
    )

    if scan.status == COMPLETED:
        try:
            process_alerts(db, settings, scan)
            db.commit()
        except Exception:
            logger.exception("alert processing failed for scan %s", scan_id)
            db.rollback()


def previous_completed_scan(db: Session, scan: Scan) -> Scan | None:
    return db.scalar(
        select(Scan)
        .where(Scan.domain_id == scan.domain_id, Scan.status == COMPLETED, Scan.id < scan.id)
        .order_by(Scan.id.desc())
        .limit(1)
    )


# ------------------------------------------------------------ comparison


@dataclass
class Comparison:
    previous_scan_id: int | None
    score_change: int | None
    grade_before: str | None
    grade_after: str | None
    new_issues: list[dict[str, Any]] = field(default_factory=list)
    resolved: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_issues or self.resolved or self.score_change)


def compare_reports(previous: dict[str, Any] | None, current: dict[str, Any]) -> Comparison:
    """Compare two reports finding by finding.

    A finding is a "new issue" when its status got worse (for example pass ->
    fail, or warning -> fail). "not_checked" is never treated as a change,
    because it means the scanner could not tell.
    """
    if previous is None:
        return Comparison(None, None, None, current["score"]["grade"])

    before = {f["id"]: f for f in previous.get("findings", [])}
    comparison = Comparison(
        previous_scan_id=None,
        score_change=(
            current["score"]["percentage"] - previous["score"]["percentage"]
            if current["score"]["percentage"] is not None and previous["score"]["percentage"] is not None
            else None
        ),
        grade_before=previous["score"]["grade"],
        grade_after=current["score"]["grade"],
    )
    for finding in current.get("findings", []):
        old = before.get(finding["id"])
        if old is None or "not_checked" in (old["status"], finding["status"]):
            continue
        old_rank, new_rank = STATUS_RANK[old["status"]], STATUS_RANK[finding["status"]]
        entry = {
            "id": finding["id"],
            "title": finding["title"],
            "severity": finding["severity"],
            "before": old["status"],
            "after": finding["status"],
        }
        if new_rank > old_rank:
            comparison.new_issues.append(entry)
        elif new_rank < old_rank:
            comparison.resolved.append(entry)
    return comparison


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def process_alerts(db: Session, settings: Settings, scan: Scan) -> Alert | None:
    """Create (and deliver) an alert when a monitored domain got worse."""
    domain = scan.domain
    if not domain.monitor_enabled:
        return None
    previous = previous_completed_scan(db, scan)
    if previous is None:
        return None
    comparison = compare_reports(previous.report, scan.report)
    grade_dropped = (
        comparison.grade_before not in (None, "N/A")
        and comparison.grade_after not in (None, "N/A")
        and comparison.grade_after > comparison.grade_before
    )
    if not comparison.new_issues and not grade_dropped:
        return None

    severities = [issue["severity"] for issue in comparison.new_issues] or ["medium"]
    severity = min(severities, key=SEVERITY_ORDER.index)
    lines = [f"- {i['title']} ({i['severity']}): {i['before']} -> {i['after']}" for i in comparison.new_issues]
    if grade_dropped:
        lines.insert(0, f"- Grade changed from {comparison.grade_before} to {comparison.grade_after}")
    alert = Alert(
        organization_id=scan.organization_id,
        domain_id=domain.id,
        scan_id=scan.id,
        severity=severity,
        title=f"Security changes detected on {domain.hostname}",
        message="\n".join(lines),
    )
    db.add(alert)
    db.flush()
    alert.delivery = deliver_alert(db, settings, alert, scan)
    return alert


def deliver_alert(db: Session, settings: Settings, alert: Alert, scan: Scan) -> str:
    organization = db.get(Organization, alert.organization_id)
    results = []
    if organization.notify_email:
        recipients = list(
            db.scalars(
                select(User.email)
                .join(Membership, Membership.user_id == User.id)
                .where(Membership.organization_id == organization.id, User.is_active.is_(True))
                .where(Membership.role.in_(("owner", "admin")))
            )
        )
        body = (
            f"{alert.title}\n\n{alert.message}\n\n"
            f"Scan report: {settings.base_url}/scans/{scan.id}\n\n"
            "You receive this because monitoring is enabled for this domain in Saboss Scan."
        )
        results.append(send_email(settings, recipients, f"[Saboss Scan] {alert.title}", body))
    payload = {
        "event": "scan.alert",
        "alert_id": alert.id,
        "domain": scan.hostname,
        "severity": alert.severity,
        "title": alert.title,
        "message": alert.message,
        "scan_id": scan.id,
        "grade": scan.grade,
        "score": scan.score_percentage,
        "report_url": f"{settings.base_url}/scans/{scan.id}",
    }
    results.append(send_webhook(organization.webhook_url, payload))
    return "; ".join(results)[:500]


# ---------------------------------------------------------------- monitoring


def due_monitored_domains(db: Session, now=None) -> list[Domain]:
    now = now or utcnow()
    return list(
        db.scalars(
            select(Domain).where(
                Domain.monitor_enabled.is_(True),
                Domain.verified_at.is_not(None),
                Domain.next_scan_at.is_not(None),
                Domain.next_scan_at <= now,
            )
        )
    )


def schedule_due_scans(db: Session, settings: Settings, limiter: RateLimiter, now=None) -> list[int]:
    """Queue scans for monitored domains that are due. Returns new scan ids."""
    now = now or utcnow()
    scan_ids = []
    for domain in due_monitored_domains(db, now):
        domain.next_scan_at = now + timedelta(hours=domain.monitor_interval_hours)
        try:
            scan = create_scan(db, settings, limiter, domain, "monitoring", "schedule")
        except ScanError as exc:
            logger.info("scheduled scan skipped for domain %s: %s", domain.id, exc)
            continue
        record(
            db,
            "scan.scheduled",
            organization_id=domain.organization_id,
            actor="system",
            target=domain.hostname,
            details={"scan_id": scan.id},
        )
        scan_ids.append(scan.id)
    db.commit()
    return scan_ids


def recover_interrupted_scans(db: Session) -> list[int]:
    """After a restart: fail scans that were running, return queued ones to re-run."""
    for scan in db.scalars(select(Scan).where(Scan.status == RUNNING)):
        scan.status = FAILED
        scan.error = "The scan was interrupted by a server restart. Please run it again."
        scan.finished_at = utcnow()
    queued = [scan.id for scan in db.scalars(select(Scan).where(Scan.status == QUEUED))]
    db.commit()
    return queued


def can_manage_domains(role: str) -> bool:
    return role_at_least(role, ADMIN)
