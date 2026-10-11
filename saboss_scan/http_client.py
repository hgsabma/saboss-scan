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


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names

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


def fetch(url: str, timeout: float = 5) -> HttpResponse:
    """GET one URL without following redirects and without reading the body.

    Raises UnsafeTargetError if the host resolves to a non-public address,
    and FetchError for network problems.
    """
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
            return HttpResponse(url=url, status_code=response.status, headers=headers)
        finally:
            response.release_conn()
    except urllib3.exceptions.SSLError:
        raise FetchError("TLS/certificate error.") from None
    # NewConnectionError must come before the timeouts: in urllib3 it is a
    # subclass of ConnectTimeoutError, even for "connection refused".
    except urllib3.exceptions.NewConnectionError:
        raise FetchError("Could not connect.") from None
    except (urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError):
        raise FetchError("The request timed out.") from None
    except urllib3.exceptions.HTTPError as exc:
        raise FetchError(f"Request failed ({type(exc).__name__}).") from None
    finally:
        pool.close()
