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


MAX_COOKIES = 50


def parse_set_cookie(raw: str) -> dict[str, Any]:
    """Read a cookie's name and security attributes.

    The cookie VALUE is deliberately discarded: it may be a session token and
    must never end up in a report or database.
    """
    parts = raw.split(";")
    name = parts[0].split("=", 1)[0].strip()[:100]
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, value = part.strip().partition("=")
        if key:
            attributes[key.lower()] = value.strip()
    return {
        "name": name,
        "secure": "secure" in attributes,
        "httponly": "httponly" in attributes,
        "samesite": attributes.get("samesite", "").lower() or None,
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
    cookies_seen: list[str] = []  # cookies can be set on any hop, not just the last
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = fetch(url, timeout)
        except InvalidTargetError:
            raise UnsafeRedirectError(f"Stopped at a redirect to a non-public or invalid address: {url}") from None
        cookies_seen.extend(response.set_cookies)
        if not response.is_redirect:
            response.set_cookies = cookies_seen
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
        "cookies": [],
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
    result["cookies"] = [parse_set_cookie(raw) for raw in response.set_cookies[:MAX_COOKIES]]
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
