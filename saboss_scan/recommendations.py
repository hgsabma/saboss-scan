from __future__ import annotations

from .findings import FAIL, WARNING, Finding

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
STATUS_ORDER = {FAIL: 0, WARNING: 1}


def build_recommendations(findings: list[Finding]) -> list[str]:
    """Return actionable advice, most important first."""
    actionable = [
        finding
        for finding in findings
        if finding.status in STATUS_ORDER and finding.recommendation
    ]
    actionable.sort(key=lambda f: (SEVERITY_ORDER[f.severity], STATUS_ORDER[f.status]))
    return [f"[{f.severity.upper()}] {f.title}: {f.recommendation}" for f in actionable]
