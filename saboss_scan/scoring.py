"""Saboss Security Score.

How the score works (kept simple so it can be explained to customers):

1. Every finding has a weight based on its severity:
   high = 10, medium = 5, low = 2, info = 0 (shown, but not scored).
2. pass earns the full weight, warning earns half, fail earns nothing.
3. Checks that could not run ("not_checked") are left out completely,
   so a timeout never counts as a security problem. The report shows how
   many checks actually ran.
4. percentage = earned points / possible points.
5. Any failed high-severity check caps the grade at D.
"""
from __future__ import annotations

from typing import Any

from .findings import FAIL, HIGH, NOT_CHECKED, Finding

SEVERITY_WEIGHTS = {"high": 10, "medium": 5, "low": 2, "info": 0}
STATUS_CREDIT = {"pass": 1.0, "warning": 0.5, "fail": 0.0}
GRADE_THRESHOLDS = [(85, "A"), (70, "B"), (55, "C"), (40, "D")]
HIGH_RISK_GRADE_CAP = "D"


def _points(value: float) -> int | float:
    """25.0 -> 25, 12.5 -> 12.5 (whole numbers read better in reports)."""
    rounded = round(value, 1)
    return int(rounded) if rounded.is_integer() else rounded


def _grade_for(percentage: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if percentage >= threshold:
            return grade
    return "E"


def calculate_score(findings: list[Finding]) -> dict[str, Any]:
    """Calculate the Saboss Security Score from a list of findings."""
    categories: dict[str, dict[str, float]] = {}
    earned = 0.0
    possible = 0

    for finding in findings:
        category = categories.setdefault(finding.category, {"earned": 0.0, "possible": 0})
        if finding.status == NOT_CHECKED:
            continue
        weight = SEVERITY_WEIGHTS[finding.severity]
        points = weight * STATUS_CREDIT[finding.status]
        category["earned"] += points
        category["possible"] += weight
        earned += points
        possible += weight

    checks_completed = sum(1 for finding in findings if finding.status != NOT_CHECKED)
    high_risk_failed = any(f.severity == HIGH and f.status == FAIL for f in findings)

    if possible == 0:
        percentage = None
        grade = "N/A"
    else:
        percentage = round(earned / possible * 100)
        grade = _grade_for(percentage)
        if high_risk_failed and grade in ("A", "B", "C"):
            grade = HIGH_RISK_GRADE_CAP

    return {
        "earned": _points(earned),
        "possible": possible,
        "percentage": percentage,
        "grade": grade,
        "high_risk_failed": high_risk_failed,
        "checks_completed": checks_completed,
        "checks_total": len(findings),
        "complete": checks_completed == len(findings),
        "categories": {
            name: {"earned": _points(values["earned"]), "possible": values["possible"]}
            for name, values in categories.items()
        },
    }
