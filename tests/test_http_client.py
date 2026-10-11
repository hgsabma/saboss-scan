"""Tests for the pinned HTTP client. No real connections are made."""
import pytest
import urllib3

from saboss_scan import http_client
from saboss_scan.http_client import FetchError, fetch
from saboss_scan.network_safety import UnsafeTargetError


class FakeUrllib3Response:
    def __init__(self, status, headers):
        self.status = status
        self.headers = urllib3.HTTPHeaderDict(headers)

    def release_conn(self):
        pass


class FakePool:
    """Records how fetch() set up the connection instead of connecting."""
    created = []

    def __init__(self, host, port, **kwargs):
        self.host, self.port, self.kwargs = host, port, kwargs
        self.requests = []
        FakePool.created.append(self)

    def urlopen(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        pass


@pytest.fixture
def fake_network(monkeypatch):
    FakePool.created = []
    FakePool.response = FakeUrllib3Response(200, {"Content-Type": "text/html"})
    monkeypatch.setattr(http_client, "resolve_public_ip", lambda host: "192.0.2.10")
    monkeypatch.setattr(http_client.urllib3, "HTTPSConnectionPool", FakePool)
    monkeypatch.setattr(http_client.urllib3, "HTTPConnectionPool", FakePool)
    return FakePool


def test_https_connects_to_checked_ip_with_hostname_for_tls(fake_network):
    fetch("https://example.com/path?x=1")
    pool = fake_network.created[0]
    assert (pool.host, pool.port) == ("192.0.2.10", 443)
    assert pool.kwargs["server_hostname"] == "example.com"
    assert pool.kwargs["assert_hostname"] == "example.com"
    assert pool.kwargs["cert_reqs"] == "CERT_REQUIRED"
    method, path, kwargs = pool.requests[0]
    assert (method, path) == ("GET", "/path?x=1")
    assert kwargs["headers"]["Host"] == "example.com"
    assert kwargs["redirect"] is False
    assert kwargs["preload_content"] is False


def test_http_uses_port_80(fake_network):
    fetch("http://example.com/")
    assert fake_network.created[0].port == 80


def test_response_headers_are_lowercased_and_repeated_headers_joined(fake_network):
    fake_network.response = FakeUrllib3Response(301, [("Location", "https://example.com/"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    response = fetch("http://example.com/")
    assert response.is_redirect
    assert response.location == "https://example.com/"
    assert response.headers["set-cookie"] == "a=1, b=2"


def test_private_address_is_refused_before_connecting(monkeypatch, fake_network):
    def private(host):
        raise UnsafeTargetError("private")

    monkeypatch.setattr(http_client, "resolve_public_ip", private)
    with pytest.raises(UnsafeTargetError):
        fetch("https://example.com/")
    assert fake_network.created == []


def test_unresolvable_name(monkeypatch, fake_network):
    monkeypatch.setattr(http_client, "resolve_public_ip", lambda host: None)
    with pytest.raises(FetchError, match="could not be resolved"):
        fetch("https://example.com/")


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (urllib3.exceptions.SSLError("bad cert"), "TLS/certificate error."),
        (urllib3.exceptions.ConnectTimeoutError(None, "slow"), "The request timed out."),
        (urllib3.exceptions.ReadTimeoutError(None, "/", "slow"), "The request timed out."),
        (urllib3.exceptions.NewConnectionError(None, "refused"), "Could not connect."),
        (urllib3.exceptions.ProtocolError("broken"), "Request failed (ProtocolError)."),
    ],
)
def test_network_errors_become_friendly_messages(fake_network, error, message):
    fake_network.response = error
    with pytest.raises(FetchError) as excinfo:
        fetch("https://example.com/")
    assert str(excinfo.value) == message


def test_unsupported_scheme_is_rejected(fake_network):
    with pytest.raises(FetchError):
        fetch("ftp://example.com/")
