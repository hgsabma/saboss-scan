from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from .http_client import FetchError, HttpResponse, fetch
from .utils import InvalidTargetError, normalize_domain

MAX_REDIRECTS = 5

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS forces browsers to use HTTPS.",
    "content-security-policy": "CSP reduces the risk of cross-site scripting.",
    "x-frame-options": "X-Frame-Options helps protect against clickjacking.",
    "x-content-type-options": "X-Content-Type-Options reduces MIME-sniffing risk.",
    "referrer-policy": "Referrer-Policy controls what referrer data is leaked.",
    "permissions-policy": "Permissions-Policy limits browser features such as camera or microphone.",
}


class UnsafeRedirectError(Exception):
    """A redirect pointed somewhere the scanner must not go."""


def _check_redirect_target(url: str) -> None:
    """Allow a redirect only to a valid public domain on the default ports.

    The IP address of the target is checked by fetch() when it connects.
    """
    try:
        normalize_domain(url)
    except InvalidTargetError:
        raise UnsafeRedirectError(f"Stopped at a redirect to a non-public or invalid address: {url}") from None


def _get_following_safe_redirects(url: str, timeout: float) -> HttpResponse:
    """GET a URL, following redirects one by one and checking each target."""
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = fetch(url, timeout)
        except InvalidTargetError:
            raise UnsafeRedirectError(f"Stopped at a redirect to a non-public or invalid address: {url}") from None
        if not response.is_redirect:
            return response
        url = urljoin(url, response.location)
        _check_redirect_target(url)
    raise UnsafeRedirectError(f"Too many redirects (more than {MAX_REDIRECTS}).")


def check_headers(domain: str, timeout: float = 5) -> dict[str, Any]:
    """Check common HTTP security headers for a website."""
    url = f"https://{domain}/"
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
        response = _get_following_safe_redirects(url, timeout)
    except (FetchError, UnsafeRedirectError) as exc:
        result["error"] = str(exc)
        return result

    result["final_url"] = response.url
    result["status_code"] = response.status_code
    result["headers"] = {key: response.headers.get(key) for key in SECURITY_HEADERS}
    result["present"] = [key for key in SECURITY_HEADERS if key in response.headers]
    result["missing"] = [key for key in SECURITY_HEADERS if key not in response.headers]
    return result


def check_http_redirect(domain: str, timeout: float = 5) -> dict[str, Any]:
    """Check whether http:// immediately redirects to https://.

    The redirect is NOT followed; we only read where it points.
    """
    url = f"http://{domain}/"
    result: dict[str, Any] = {
        "url_checked": url,
        "status_code": None,
        "location": None,
        "redirects_to_https": None,
        "error": None,
    }

    try:
        response = fetch(url, timeout)
    except (FetchError, InvalidTargetError) as exc:
        result["error"] = str(exc)
        return result

    result["status_code"] = response.status_code
    if response.is_redirect:
        absolute = urljoin(url, response.location)
        result["location"] = absolute
        result["redirects_to_https"] = absolute.lower().startswith("https://")
    else:
        result["redirects_to_https"] = False
    return result
