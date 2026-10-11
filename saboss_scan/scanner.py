from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import __version__
from .dns_checker import check_dns
from .findings import evaluate
from .headers_checker import check_headers, check_http_redirect
from .recommendations import build_recommendations
from .scoring import calculate_score
from .ssl_checker import check_ssl
from .utils import normalize_domain

LIMITATIONS = [
    "This is a passive, external check of public configuration. It does not test "
    "application code, login pages, servers, or internal networks.",
    "A high score does not mean the website is secure; it means the checked "
    "settings follow common best practices.",
    "Only the homepage over HTTPS is checked; other pages may send different headers.",
    "DKIM is only searched for with common selector names.",
]


def scan_domain(domain_input: str) -> dict[str, Any]:
    """Run the full Saboss Scan against one domain."""
    domain = normalize_domain(domain_input)
    results: dict[str, Any] = {
        "tool": "Saboss Scan",
        "version": __version__,
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ssl": check_ssl(domain),
        "http_redirect": check_http_redirect(domain),
        "headers": check_headers(domain),
        "dns": check_dns(domain),
    }
    findings = evaluate(results)
    results["findings"] = [finding.to_dict() for finding in findings]
    results["score"] = calculate_score(findings)
    results["recommendations"] = build_recommendations(findings)
    results["limitations"] = LIMITATIONS
    return results
