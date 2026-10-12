"""A minimal HTTP client that only connects to verified public IP addresses.

Why not just use requests? requests looks up the hostname itself when it
connects. Our safety check (network_safety) also looks it up. Two separate
lookups can give two different answers, so a hostile DNS server could pass
the check with a public IP and then send the real connection to an internal
one ("DNS rebinding").

This client looks the name up ONCE, checks the address, and then connects to
exactly that address. It still sends the right Host header and verifies the
TLS certificate for the hostname, so the website cannot tell the difference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

import certifi
import urllib3

from . import __version__
from .network_safety import resolve_public_ip

USER_AGENT = f"SabossScan/{__version__}"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """A request failed. The message is safe to show to users."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names
    # Set-Cookie headers kept separately: joining them with ", " would break
    # parsing because cookie dates contain commas.
    set_cookies: list[str] = field(default_factory=list)

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in REDIRECT_STATUSES and bool(self.location)


def _make_pool(scheme: str, ip: str, hostname: str, timeout: float) -> urllib3.HTTPConnectionPool:
    pool_timeout = urllib3.Timeout(connect=timeout, read=timeout)
    if scheme == "https":
        return urllib3.HTTPSConnectionPool(
            ip,
            443,
            server_hostname=hostname,  # TLS SNI: which website we want
            assert_hostname=hostname,  # certificate must be valid for the hostname
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            timeout=pool_timeout,
            retries=False,
            maxsize=1,
        )
    return urllib3.HTTPConnectionPool(ip, 80, timeout=pool_timeout, retries=False, maxsize=1)


def fetch(url: str, timeout: float = 5, attempts: int = 2) -> HttpResponse:
    """GET one URL without following redirects and without reading the body.

    A timeout is retried once (attempts=2); other errors are not retried.
    Raises UnsafeTargetError if the host resolves to a non-public address,
    and FetchError for network problems.
    """
    for attempt in range(1, attempts + 1):
        try:
            return _fetch_once(url, timeout)
        except FetchError as exc:
            if not exc.retryable or attempt == attempts:
                raise
    raise AssertionError("unreachable")


def _fetch_once(url: str, timeout: float) -> HttpResponse:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not hostname:
        raise FetchError(f"Unsupported URL: {url}")

    ip = resolve_public_ip(hostname)  # may raise UnsafeTargetError
    if ip is None:
        raise FetchError("The domain name could not be resolved.")

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    pool = _make_pool(parsed.scheme, ip, hostname, timeout)
    try:
        response = pool.urlopen(
            "GET",
            path,
            headers={"Host": hostname, "User-Agent": USER_AGENT, "Accept": "*/*"},
            redirect=False,
            retries=False,
            preload_content=False,  # headers only, never download the page
            assert_same_host=False,
        )
        try:
            # .get() joins repeated headers with ", " like browsers do.
            headers = {name.lower(): response.headers.get(name) for name in response.headers}
            return HttpResponse(
                url=url,
                status_code=response.status,
                headers=headers,
                set_cookies=list(response.headers.getlist("set-cookie")),
            )
        finally:
            response.release_conn()
    except urllib3.exceptions.SSLError:
        raise FetchError("TLS/certificate error.") from None
    # NewConnectionError must come before the timeouts: in urllib3 it is a
    # subclass of ConnectTimeoutError, even for "connection refused".
    except urllib3.exceptions.NewConnectionError:
        raise FetchError("Could not connect.") from None
    except (urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError):
        raise FetchError("The request timed out.", retryable=True) from None
    except urllib3.exceptions.HTTPError as exc:
        raise FetchError(f"Request failed ({type(exc).__name__}).") from None
    finally:
        pool.close()


def post_json(url: str, payload: dict, timeout: float = 5) -> int:
    """POST JSON to a public HTTPS URL (used for webhooks). Returns the status code.

    Uses the same protections as fetch(): the host must resolve to public
    addresses only, and the connection is pinned to the checked address.
    Redirects are not followed.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    if parsed.scheme != "https" or not hostname or parsed.port not in (None, 443) or parsed.username:
        raise FetchError("Webhook URLs must be https:// addresses on the default port.")

    ip = resolve_public_ip(hostname)  # may raise UnsafeTargetError
    if ip is None:
        raise FetchError("The domain name could not be resolved.")

    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    body = json.dumps(payload).encode("utf-8")
    pool = _make_pool("https", ip, hostname, timeout)
    try:
        response = pool.urlopen(
            "POST",
            path,
            body=body,
            headers={
                "Host": hostname,
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            redirect=False,
            retries=False,
            preload_content=False,
            assert_same_host=False,
        )
        try:
            return response.status
        finally:
            response.release_conn()
    except urllib3.exceptions.SSLError:
        raise FetchError("TLS/certificate error.") from None
    except urllib3.exceptions.NewConnectionError:
        raise FetchError("Could not connect.") from None
    except (urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError):
        raise FetchError("The request timed out.") from None
    except urllib3.exceptions.HTTPError as exc:
        raise FetchError(f"Request failed ({type(exc).__name__}).") from None
    finally:
        pool.close()
