"""Configuration from environment variables (12-factor style).

Every setting has a safe default for local development. In production
(SABOSS_ENV=production) cookies are Secure by default and development-only
conveniences (such as printing password-reset links to the log) are off.
See docs/DEPLOYMENT.md for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


@dataclass(frozen=True)
class Settings:
    env: str = "development"
    database_url: str = "sqlite:///./data/saboss.db"
    base_url: str = "http://127.0.0.1:8000"
    cookie_secure: bool = False
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    registration_open: bool = True
    log_level: str = "INFO"

    # Sessions
    session_max_age_hours: int = 24 * 7
    session_idle_hours: int = 24 * 2

    # Scanning
    scan_workers: int = 2
    scan_executor: str = "thread"  # "thread" in the app, "inline" in tests
    scans_per_org_per_hour: int = 30
    scheduler_enabled: bool = True
    scheduler_poll_seconds: int = 60

    # E-mail (optional). Without SMTP_HOST, e-mail is not sent.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)


@lru_cache
def get_settings() -> Settings:
    env = os.environ.get("SABOSS_ENV", "development")
    production = env == "production"
    hosts = os.environ.get("SABOSS_ALLOWED_HOSTS", "127.0.0.1,localhost")
    return Settings(
        env=env,
        database_url=os.environ.get("SABOSS_DATABASE_URL", "sqlite:///./data/saboss.db"),
        base_url=os.environ.get("SABOSS_BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
        cookie_secure=_bool("SABOSS_COOKIE_SECURE", production),
        allowed_hosts=[host.strip() for host in hosts.split(",") if host.strip()],
        registration_open=_bool("SABOSS_REGISTRATION_OPEN", True),
        log_level=os.environ.get("SABOSS_LOG_LEVEL", "INFO"),
        session_max_age_hours=_int("SABOSS_SESSION_MAX_AGE_HOURS", 24 * 7),
        session_idle_hours=_int("SABOSS_SESSION_IDLE_HOURS", 24 * 2),
        scan_workers=_int("SABOSS_SCAN_WORKERS", 2),
        scan_executor=os.environ.get("SABOSS_SCAN_EXECUTOR", "thread"),
        scans_per_org_per_hour=_int("SABOSS_SCANS_PER_ORG_PER_HOUR", 30),
        scheduler_enabled=_bool("SABOSS_SCHEDULER_ENABLED", True),
        scheduler_poll_seconds=_int("SABOSS_SCHEDULER_POLL_SECONDS", 60),
        smtp_host=os.environ.get("SABOSS_SMTP_HOST", ""),
        smtp_port=_int("SABOSS_SMTP_PORT", 587),
        smtp_user=os.environ.get("SABOSS_SMTP_USER", ""),
        smtp_password=os.environ.get("SABOSS_SMTP_PASSWORD", ""),
        smtp_from=os.environ.get("SABOSS_SMTP_FROM", ""),
        smtp_starttls=_bool("SABOSS_SMTP_STARTTLS", True),
    )
