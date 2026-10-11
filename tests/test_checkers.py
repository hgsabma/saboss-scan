"""Tests for the network checkers. No real network traffic is made:
the functions that would talk to the internet are replaced with fakes."""
import socket
import ssl

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from saboss_scan import dns_checker, ssl_checker


# --- DNS -----------------------------------------------------------------

def test_long_txt_records_are_joined():
    record = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.TXT, '"v=spf1 include:a.example " "include:b.example -all"'
    )
    assert dns_checker._record_to_text(record) == "v=spf1 include:a.example include:b.example -all"


def test_missing_dmarc_record_is_not_an_error(monkeypatch):
    def fake_resolve(_resolver, name, record_type):
        if name.startswith("_dmarc."):
            raise dns.resolver.NXDOMAIN()
        return []

    monkeypatch.setattr(dns_checker, "_resolve", fake_resolve)
    result = dns_checker.check_dns("example.com")
    assert result["dmarc"] == []
    assert "dmarc" not in result["errors"]


def test_dns_timeout_is_reported_as_error(monkeypatch):
    def fake_resolve(_resolver, name, record_type):
        raise dns.resolver.LifetimeTimeout(timeout=6.0, errors=[])

    monkeypatch.setattr(dns_checker, "_resolve", fake_resolve)
    result = dns_checker.check_dns("example.com")
    assert result["errors"]["txt"] == "DNS lookup timed out."
    assert result["errors"]["dmarc"] == "DNS lookup timed out."


def test_spf_is_found_among_many_txt_records():
    # Regression: github.com has 24 TXT records with SPF last; an old limit of 20 hid it.
    texts = [f'"verification-token-{i}"' for i in range(30)] + ['"v=spf1 include:_spf.example.com -all"']
    records = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, text) for text in texts]

    class FakeResolverModule:
        class Resolver:
            def __init__(self, configure):
                pass

            def resolve(self, name, record_type, raise_on_no_answer):
                return records

    txt = dns_checker._resolve(FakeResolverModule, "example.com", "TXT")
    assert dns_checker._find_spf(txt) == ["v=spf1 include:_spf.example.com -all"]


def test_spf_is_only_matched_at_the_start_of_a_record():
    records = ["v=spf1 -all", "google-site-verification=abc v=spf1"]
    assert dns_checker._find_spf(records) == ["v=spf1 -all"]


# --- TLS -----------------------------------------------------------------

@pytest.mark.parametrize(
    ("exception", "expected_type"),
    [
        (ConnectionRefusedError(), "refused"),
        (TimeoutError(), "timeout"),
        (socket.gaierror(), "dns"),
        (ssl.SSLError(), "tls"),
        (OSError(), "network"),
    ],
)
def test_ssl_errors_are_classified(monkeypatch, exception, expected_type):
    def fake_connect(*args, **kwargs):
        raise exception

    monkeypatch.setattr(ssl_checker.socket, "create_connection", fake_connect)
    result = ssl_checker.check_ssl("example.com")
    assert result["error_type"] == expected_type
    assert result["certificate_valid"] is False
