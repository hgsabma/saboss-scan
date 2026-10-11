"""Saboss Security Score.

How the score works (kept simple so it can be explained to customers):

1. Every finding has a weight based on its severity:
   critical = 20, high = 10, medium = 5, low = 2, info = 0 (shown, not scored).
2. pass earns the full weight, warning earns half, fail earns nothing.
3. Checks that could not run ("not_checked") or had nothing to evaluate
   ("not_applicable") are left out completely, so a timeout never counts as a
   security problem. The report shows how many checks actually ran
   ("coverage"), which is the confidence of the score.
4. percentage = earned points / possible points.
5. Grade caps: a failed critical check caps the grade at E,
   a failed high-severity check caps it at D.

The same findings always give the same score (no randomness, no time input).
"""

from __future__ import annotations

from typing import Any

from .findings import CRITICAL, FAIL, HIGH, NOT_APPLICABLE, NOT_CHECKED, Finding

SEVERITY_WEIGHTS = {"critical": 20, "high": 10, "medium": 5, "low": 2, "info": 0}
STATUS_CREDIT = {"pass": 1.0, "warning": 0.5, "fail": 0.0}
GRADE_THRESHOLDS = [(85, "A"), (70, "B"), (55, "C"), (40, "D")]
GRADE_ORDER = ["A", "B", "C", "D", "E"]
UNSCORED_STATUSES = {NOT_CHECKED, NOT_APPLICABLE}


def _points(value: float) -> int | float:
    """25.0 -> 25, 12.5 -> 12.5 (whole numbers read better in reports)."""
    rounded = round(value, 1)
    return int(rounded) if rounded.is_integer() else rounded


def _grade_for(percentage: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if percentage >= threshold:
            return grade
    return "E"


def _cap(grade: str, cap: str) -> str:
    return grade if GRADE_ORDER.index(grade) >= GRADE_ORDER.index(cap) else cap


def calculate_score(findings: list[Finding]) -> dict[str, Any]:
    """Calculate the Saboss Security Score from a list of findings."""
    categories: dict[str, dict[str, float]] = {}
    earned = 0.0
    possible = 0

    for finding in findings:
        category = categories.setdefault(finding.category, {"earned": 0.0, "possible": 0})
        if finding.status in UNSCORED_STATUSES:
            continue
        weight = SEVERITY_WEIGHTS[finding.severity]
        points = weight * STATUS_CREDIT[finding.status]
        category["earned"] += points
        category["possible"] += weight
        earned += points
        possible += weight

    applicable = [f for f in findings if f.status != NOT_APPLICABLE]
    completed = [f for f in applicable if f.status != NOT_CHECKED]
    critical_failed = any(f.severity == CRITICAL and f.status == FAIL for f in findings)
    high_risk_failed = critical_failed or any(f.severity == HIGH and f.status == FAIL for f in findings)

    if possible == 0:
        percentage = None
        grade = "N/A"
    else:
        percentage = round(earned / possible * 100)
        grade = _grade_for(percentage)
        if critical_failed:
            grade = _cap(grade, "E")
        elif high_risk_failed:
            grade = _cap(grade, "D")

    coverage = round(len(completed) / len(applicable) * 100) if applicable else 0

    return {
        "earned": _points(earned),
        "possible": possible,
        "percentage": percentage,
        "grade": grade,
        "critical_failed": critical_failed,
        "high_risk_failed": high_risk_failed,
        "checks_completed": len(completed),
        "checks_total": len(applicable),
        "complete": len(completed) == len(applicable),
        "coverage": coverage,
        "counts": {
            status: sum(1 for f in findings if f.status == status)
            for status in ("fail", "warning", "pass", "not_checked", "not_applicable")
        },
        "categories": {
            name: {"earned": _points(values["earned"]), "possible": values["possible"]}
            for name, values in categories.items()
        },
    }
