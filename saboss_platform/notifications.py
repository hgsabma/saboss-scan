"""Notification delivery (e-mail and webhooks).

Delivery only happens when it is configured:
- E-mail needs SABOSS_SMTP_HOST and SABOSS_SMTP_FROM.
- Webhooks need an https:// URL in the organization's settings. They are sent
  with the same SSRF protections as scans (public addresses only, pinned IP).

Each function returns a short, honest description of what happened, which is
stored with the alert ("sent", "not configured", or the error).
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from saboss_scan.http_client import FetchError, post_json
from saboss_scan.utils import InvalidTargetError

from .config import Settings

logger = logging.getLogger("saboss.notifications")


def send_email(settings: Settings, to: list[str], subject: str, body: str) -> str:
    if not settings.email_configured:
        return "e-mail not configured"
    if not to:
        return "e-mail: no recipients"
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(to)
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            if settings.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("e-mail delivery failed: %s", type(exc).__name__)
        return f"e-mail failed ({type(exc).__name__})"
    return f"e-mail sent to {len(to)} recipient(s)"


def send_webhook(url: str | None, payload: dict) -> str:
    if not url:
        return "webhook not configured"
    try:
        status = post_json(url, payload, timeout=5)
    except (FetchError, InvalidTargetError) as exc:
        return f"webhook failed ({exc})"
    if 200 <= status < 300:
        return f"webhook delivered (HTTP {status})"
    return f"webhook rejected (HTTP {status})"
