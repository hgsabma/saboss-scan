"""Shared test helpers. pytest loads this file automatically."""
import pytest

from saboss_scan.findings import evaluate
from saboss_scan.recommendations import build_recommendations
from saboss_scan.scanner import LIMITATIONS
from saboss_scan.scoring import calculate_score


def build_report(domain="example.com", headers=None, ssl=None):
    """Build a complete report from fake checker results (no network)."""
    results = {
        "tool": "Saboss Scan",
        "version": "test",
        "domain": domain,
        "scanned_at": "2026-10-11T12:00:00+00:00",
        "ssl": ssl or {"https": True, "certificate_valid": True, "days_until_expiry": 90,
                       "error": None, "error_type": None},
        "http_redirect": {"redirects_to_https": True, "location": "https://example.com/", "error": None},
        "headers": {"headers": headers or {}, "error": None},
        "dns": {"a": ["192.0.2.1"], "aaaa": [], "mx": [], "txt": [], "spf": ["v=spf1 -all"],
                "dmarc": ["v=DMARC1; p=none"], "dkim": {}, "errors": {}},
    }
    findings = evaluate(results)
    results["findings"] = [f.to_dict() for f in findings]
    results["score"] = calculate_score(findings)
    results["recommendations"] = build_recommendations(findings)
    results["limitations"] = LIMITATIONS
    return results


@pytest.fixture
def sample_report():
    return build_report()
