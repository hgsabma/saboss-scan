from __future__ import annotations

from .findings import FAIL, WARNING, Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
STATUS_ORDER = {FAIL: 0, WARNING: 1}


def build_recommendations(findings: list[Finding]) -> list[str]:
    """Return actionable advice, most important first."""
    actionable = [finding for finding in findings if finding.status in STATUS_ORDER and finding.recommendation]
    actionable.sort(key=lambda f: (SEVERITY_ORDER[f.severity], STATUS_ORDER[f.status]))
    return [f"[{f.severity.upper()}] {f.title}: {f.recommendation}" for f in actionable]
