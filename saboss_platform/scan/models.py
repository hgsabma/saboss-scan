"""Database models for Saboss Scan."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base, utcnow

# Scan states
QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
SCAN_STATES = (QUEUED, RUNNING, COMPLETED, FAILED)

MONITOR_INTERVALS = {24: "Daily", 168: "Weekly"}


class Domain(Base):
    """A domain an organization is authorized to assess."""

    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("organization_id", "hostname"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # The person who added the domain confirmed they are authorized to assess it.
    authorization_confirmed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    authorization_confirmed_by: Mapped[str] = mapped_column(String(254), default="")

    # Ownership proof through a DNS TXT record (required for monitoring).
    verification_token: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Scheduled monitoring
    monitor_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    monitor_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    scans: Mapped[list[Scan]] = relationship(back_populates="domain", cascade="all, delete-orphan")

    @property
    def verification_record_name(self) -> str:
        return f"_saboss-challenge.{self.hostname}"

    @property
    def verification_record_value(self) -> str:
        return f"saboss-verify={self.verification_token}"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(253), index=True)  # copy, so history survives renames
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual, api, schedule
    requested_by: Mapped[str] = mapped_column(String(254), default="")
    status: Mapped[str] = mapped_column(String(20), default=QUEUED, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str] = mapped_column(String(500), default="")
    score_percentage: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grade: Mapped[str | None] = mapped_column(String(3), nullable=True)
    engine_version: Mapped[str] = mapped_column(String(20), default="")
    report_json: Mapped[str] = mapped_column(Text, default="")

    domain: Mapped[Domain] = relationship(back_populates="scans")

    @property
    def report(self) -> dict[str, Any] | None:
        return json.loads(self.report_json) if self.report_json else None

    @property
    def is_finished(self) -> bool:
        return self.status in (COMPLETED, FAILED)


class Alert(Base):
    """A meaningful change detected between two scans of a monitored domain."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text, default="")
    delivery: Mapped[str] = mapped_column(String(500), default="")  # what happened with e-mail/webhook
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    domain: Mapped[Domain] = relationship()
