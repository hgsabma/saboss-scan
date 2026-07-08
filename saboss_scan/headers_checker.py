from __future__ import annotations

from typing import Any

import requests


SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS forces browsers to use HTTPS.",
    "content-security-policy": "CSP reduces the risk of cross-site scripting.",
    "x-frame-options": "X-Frame-Options helps protect against clickjacking.",
    "x-content-type-options": "X-Content-Type-Options reduces MIME-sniffing risk.",
    "referrer-policy": "Referrer-Policy controls what referrer data is leaked.",
    "permissions-policy": "Permissions-Policy limits browser features such as camera or microphone.",
}


def check_headers(domain: str, timeout: int = 4) -> dict[str, Any]:
    """Check common HTTP security headers for a website."""
    url = f"https://{domain}"
    result: dict[str, Any] = {
        "url_checked": url,
        "final_url": None,
        "status_code": None,
        "headers": {},
        "present": [],
        "missing": [],
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "SabossScan/0.1"},
        )
        lowered_headers = {key.lower(): value for key, value in response.headers.items()}

        result["final_url"] = response.url
        result["status_code"] = response.status_code
        result["headers"] = {key: lowered_headers.get(key) for key in SECURITY_HEADERS}
        result["present"] = [key for key in SECURITY_HEADERS if key in lowered_headers]
        result["missing"] = [key for key in SECURITY_HEADERS if key not in lowered_headers]

    except Exception as exc:
        result["error"] = str(exc)

    return result
