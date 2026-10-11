from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import requests

from . import __version__
from .network_safety import ensure_public_target
from .utils import InvalidTargetError, normalize_domain

USER_AGENT = f"SabossScan/{__version__}"
MAX_REDIRECTS = 5


class UnsafeRedirectError(Exception):
    """A redirect pointed somewhere the scanner must not go."""

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "HSTS forces browsers to use HTTPS.",
    "content-security-policy": "CSP reduces the risk of cross-site scripting.",
    "x-frame-options": "X-Frame-Options helps protect against clickjacking.",
    "x-content-type-options": "X-Content-Type-Options reduces MIME-sniffing risk.",
    "referrer-policy": "Referrer-Policy controls what referrer data is leaked.",
    "permissions-policy": "Permissions-Policy limits browser features such as camera or microphone.",
}


def _describe_request_error(exc: requests.RequestException) -> str:
    """Short, user-friendly description that does not dump internals."""
    if isinstance(exc, requests.Timeout):
        return "The request timed out."
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS/certificate error."
    if isinstance(exc, requests.ConnectionError):
        return "Could not connect."
    return f"Request failed ({type(exc).__name__})."


def _check_redirect_target(url: str) -> None:
    """Allow a redirect only to a public http(s) website on the default ports."""
    try:
        hostname = normalize_domain(url)
        ensure_public_target(hostname)
    except InvalidTargetError:
        raise UnsafeRedirectError(f"Stopped at a redirect to a non-public or invalid address: {url}") from None


def _get_following_safe_redirects(url: str, timeout: int) -> requests.Response:
    """GET a URL, following redirects one by one and checking each target.

    requests can follow redirects automatically, but then it would visit any
    address the website points to, including internal ones. Doing it by hand
    lets us validate every hop.
    """
    for _ in range(MAX_REDIRECTS + 1):
        # stream=True: read the headers only, never download the page body.
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        )
        response.close()
        location = response.headers.get("location")
        if not (response.is_redirect and location):
            return response
        url = urljoin(url, location)
        _check_redirect_target(url)
    raise UnsafeRedirectError(f"Too many redirects (more than {MAX_REDIRECTS}).")


def check_headers(domain: str, timeout: int = 5) -> dict[str, Any]:
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
        response = _get_following_safe_redirects(url, timeout)
        lowered_headers = {key.lower(): value for key, value in response.headers.items()}
        result["final_url"] = response.url
        result["status_code"] = response.status_code

        result["headers"] = {key: lowered_headers.get(key) for key in SECURITY_HEADERS}
        result["present"] = [key for key in SECURITY_HEADERS if key in lowered_headers]
        result["missing"] = [key for key in SECURITY_HEADERS if key not in lowered_headers]

    except requests.RequestException as exc:
        result["error"] = _describe_request_error(exc)
    except UnsafeRedirectError as exc:
        result["error"] = str(exc)

    return result


def check_http_redirect(domain: str, timeout: int = 5) -> dict[str, Any]:
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
        with requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            headers={"User-Agent": USER_AGENT},
        ) as response:
            result["status_code"] = response.status_code
            location = response.headers.get("location")

        if response.is_redirect and location:
            absolute = urljoin(url, location)
            result["location"] = absolute
            result["redirects_to_https"] = absolute.lower().startswith("https://")
        else:
            result["redirects_to_https"] = False

    except requests.RequestException as exc:
        result["error"] = _describe_request_error(exc)

    return result
