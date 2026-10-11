import socket

import pytest

from saboss_scan import headers_checker, network_safety, scanner
from saboss_scan.http_client import HttpResponse
from saboss_scan.network_safety import UnsafeTargetError, ensure_public_target, is_public_ip
from saboss_scan.utils import InvalidTargetError


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
     "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1%eth0", "fd00::1",
     "::ffff:127.0.0.1", "::ffff:169.254.169.254"],
)
def test_internal_addresses_are_not_public(address):
    assert is_public_ip(address) is False


@pytest.mark.parametrize("address", ["93.184.215.14", "1.1.1.1", "2606:4700:4700::1111"])
def test_internet_addresses_are_public(address):
    assert is_public_ip(address) is True


def fake_getaddrinfo(addresses):
    def _fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port)) for address in addresses]
    return _fake


def test_domain_pointing_to_localhost_is_blocked(monkeypatch):
    monkeypatch.setattr(network_safety.socket, "getaddrinfo", fake_getaddrinfo(["127.0.0.1"]))
    with pytest.raises(UnsafeTargetError):
        ensure_public_target("evil.example.com")


def test_one_private_address_among_public_ones_is_blocked(monkeypatch):
    monkeypatch.setattr(network_safety.socket, "getaddrinfo", fake_getaddrinfo(["1.1.1.1", "10.0.0.5"]))
    with pytest.raises(UnsafeTargetError):
        ensure_public_target("mixed.example.com")


def test_public_domain_is_allowed(monkeypatch):
    monkeypatch.setattr(network_safety.socket, "getaddrinfo", fake_getaddrinfo(["1.1.1.1"]))
    assert ensure_public_target("good.example.com") == ["1.1.1.1"]


def test_unresolvable_domain_is_allowed_through(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("not found")

    monkeypatch.setattr(network_safety.socket, "getaddrinfo", fail)
    assert ensure_public_target("missing.example.com") == []


def test_unsafe_target_error_is_an_invalid_target_error():
    # main.py catches InvalidTargetError, so this error is shown nicely too.
    assert issubclass(UnsafeTargetError, InvalidTargetError)


def test_scan_stops_before_connecting_when_public_dns_returns_private_ip(monkeypatch):
    connections = []
    monkeypatch.setattr(scanner, "check_dns", lambda domain: {"a": ["169.254.169.254"], "aaaa": []})
    monkeypatch.setattr(scanner, "ensure_public_target", lambda domain: [])
    monkeypatch.setattr(scanner, "check_ssl", lambda domain: connections.append("ssl"))
    monkeypatch.setattr(scanner, "check_headers", lambda domain: connections.append("headers"))
    monkeypatch.setattr(scanner, "check_http_redirect", lambda domain: connections.append("http"))

    with pytest.raises(UnsafeTargetError):
        scanner.scan_domain("metadata.example.com")
    assert connections == []


# --- resolve_public_ip ------------------------------------------------------

def test_resolve_public_ip_prefers_ipv4(monkeypatch):
    monkeypatch.setattr(network_safety, "resolve_addresses", lambda host: ["2606:4700::1", "1.1.1.1"])
    assert network_safety.resolve_public_ip("example.com") == "1.1.1.1"


def test_resolve_public_ip_blocks_private(monkeypatch):
    monkeypatch.setattr(network_safety, "resolve_addresses", lambda host: ["1.1.1.1", "127.0.0.1"])
    with pytest.raises(UnsafeTargetError):
        network_safety.resolve_public_ip("example.com")


def test_resolve_public_ip_returns_none_when_unresolvable(monkeypatch):
    monkeypatch.setattr(network_safety, "resolve_addresses", lambda host: [])
    assert network_safety.resolve_public_ip("example.com") is None


# --- Redirect following ---------------------------------------------------

def page(url, status_code=200, location=None, headers=None):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    if location:
        headers["location"] = location
    return HttpResponse(url=url, status_code=status_code, headers=headers)


def install_fake_web(monkeypatch, pages, private_hosts=()):
    """pages maps a URL to a response; hosts in private_hosts act like internal servers."""
    connected = []

    def fake_fetch(url, timeout):
        host = url.split("/")[2]
        if host in private_hosts:
            # The real fetch() raises this before any connection is made.
            raise UnsafeTargetError(f"{host} is private")
        connected.append(url)
        return pages[url]

    monkeypatch.setattr(headers_checker, "fetch", fake_fetch)
    return connected


def test_safe_redirects_are_followed(monkeypatch):
    connected = install_fake_web(monkeypatch, {
        "https://example.com/": page("https://example.com/", 301, "https://www.example.com/"),
        "https://www.example.com/": page(
            "https://www.example.com/", 200, headers={"X-Content-Type-Options": "nosniff"}
        ),
    })
    result = headers_checker.check_headers("example.com")
    assert result["error"] is None
    assert result["final_url"] == "https://www.example.com/"
    assert "x-content-type-options" in result["present"]
    assert connected == ["https://example.com/", "https://www.example.com/"]


def test_relative_redirect_is_resolved(monkeypatch):
    install_fake_web(monkeypatch, {
        "https://example.com/": page("https://example.com/", 302, "/en/"),
        "https://example.com/en/": page("https://example.com/en/", 200),
    })
    assert headers_checker.check_headers("example.com")["final_url"] == "https://example.com/en/"


def test_redirect_to_internal_host_is_not_followed(monkeypatch):
    connected = install_fake_web(
        monkeypatch,
        {"https://example.com/": page("https://example.com/", 302, "https://internal.example.net/admin")},
        private_hosts={"internal.example.net"},
    )
    result = headers_checker.check_headers("example.com")
    assert "non-public" in result["error"]
    assert connected == ["https://example.com/"]


@pytest.mark.parametrize(
    "location",
    ["http://169.254.169.254/latest/meta-data/", "https://localhost/", "https://example.com:8443/"],
)
def test_redirect_to_ip_localhost_or_custom_port_is_not_followed(monkeypatch, location):
    connected = install_fake_web(
        monkeypatch, {"https://example.com/": page("https://example.com/", 302, location)}
    )
    result = headers_checker.check_headers("example.com")
    assert result["error"] is not None
    assert connected == ["https://example.com/"]


def test_redirect_loop_stops(monkeypatch):
    install_fake_web(monkeypatch, {
        "https://example.com/": page("https://example.com/", 302, "https://example.com/"),
    })
    result = headers_checker.check_headers("example.com")
    assert "Too many redirects" in result["error"]
