from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .dns_checker import check_dns
from .headers_checker import check_headers
from .recommendations import build_recommendations
from .scoring import calculate_score
from .ssl_checker import check_ssl
from .utils import normalize_domain


def scan_domain(domain_input: str) -> dict[str, Any]:
    """Run the full Saboss Scan against one domain."""
    domain = normalize_domain(domain_input)
    results: dict[str, Any] = {
        "tool": "Saboss Scan",
        "version": "0.1.0",
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ssl": check_ssl(domain),
        "headers": check_headers(domain),
        "dns": check_dns(domain),
    }
    results["score"] = calculate_score(results)
    results["recommendations"] = build_recommendations(results)
    return results
