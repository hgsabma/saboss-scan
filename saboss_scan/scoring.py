from __future__ import annotations

from typing import Any


HEADER_POINTS = 5
MAX_POINTS = {
    "ssl": 25,
    "headers": 30,
    "dns": 20,
    "website_health": 10,
    "email_security": 15,
}


def _score_ssl(ssl_result: dict[str, Any]) -> int:
    score = 0
    if ssl_result.get("https"):
        score += 5
    if ssl_result.get("certificate_valid"):
        score += 15
    days = ssl_result.get("days_until_expiry")
    if isinstance(days, int) and days >= 30:
        score += 5
    return min(score, MAX_POINTS["ssl"])


def _score_headers(headers_result: dict[str, Any]) -> int:
    present_headers = headers_result.get("present", [])
    return min(len(present_headers) * HEADER_POINTS, MAX_POINTS["headers"])


def _score_dns(dns_result: dict[str, Any]) -> int:
    score = 0
    if dns_result.get("a"):
        score += 6
    if dns_result.get("aaaa"):
        score += 4
    if dns_result.get("mx"):
        score += 4
    if dns_result.get("txt"):
        score += 3
    if not dns_result.get("errors"):
        score += 3
    return min(score, MAX_POINTS["dns"])


def _score_website_health(headers_result: dict[str, Any]) -> int:
    score = 0
    status_code = headers_result.get("status_code")
    final_url = headers_result.get("final_url") or ""
    if isinstance(status_code, int) and status_code < 400:
        score += 5
    if final_url.startswith("https://"):
        score += 5
    return min(score, MAX_POINTS["website_health"])


def _score_email_security(dns_result: dict[str, Any]) -> int:
    score = 0
    if dns_result.get("spf"):
        score += 5
    if dns_result.get("dmarc"):
        score += 6
    if dns_result.get("dkim"):
        score += 4
    return min(score, MAX_POINTS["email_security"])


def calculate_score(results: dict[str, Any]) -> dict[str, Any]:
    """Calculate Saboss Security Score from scan results."""
    categories = {
        "ssl": _score_ssl(results.get("ssl", {})),
        "headers": _score_headers(results.get("headers", {})),
        "dns": _score_dns(results.get("dns", {})),
        "website_health": _score_website_health(results.get("headers", {})),
        "email_security": _score_email_security(results.get("dns", {})),
    }
    total = sum(categories.values())
    max_total = sum(MAX_POINTS.values())
    percentage = round((total / max_total) * 100)

    if percentage >= 85:
        grade = "A"
    elif percentage >= 70:
        grade = "B"
    elif percentage >= 55:
        grade = "C"
    elif percentage >= 40:
        grade = "D"
    else:
        grade = "E"

    return {
        "total": total,
        "max_total": max_total,
        "percentage": percentage,
        "grade": grade,
        "categories": categories,
        "max_points": MAX_POINTS,
    }
