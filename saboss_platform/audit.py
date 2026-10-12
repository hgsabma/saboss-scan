"""Audit log: who did what, when, from where.

Never put passwords, tokens or API keys in ``details``.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditLog


def record(
    db: Session,
    action: str,
    *,
    organization_id: int | None = None,
    user_id: int | None = None,
    actor: str = "",
    target: str = "",
    details: dict[str, Any] | None = None,
    ip_address: str = "",
) -> None:
    db.add(
        AuditLog(
            action=action,
            organization_id=organization_id,
            user_id=user_id,
            actor=actor[:254],
            target=target[:254],
            details=json.dumps(details or {}, ensure_ascii=False)[:4000],
            ip_address=ip_address[:45],
        )
    )
