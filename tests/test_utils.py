import pytest

from saboss_scan.utils import InvalidTargetError, normalize_domain


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  Example.COM  ", "example.com"),
        ("https://example.com/path?q=1", "example.com"),
        ("http://example.com", "example.com"),
        ("example.com.", "example.com"),
        ("https://example.com:443/", "example.com"),
        # www is a separate host and is kept as typed.
        ("https://www.example.com/path", "www.example.com"),
        ("www.com", "www.com"),
        ("sub.domain.example.co.uk", "sub.domain.example.co.uk"),
    ],
)
def test_valid_domains_are_normalized(raw, expected):
    assert normalize_domain(raw) == expected


def test_unicode_domain_is_converted_to_punycode():
    assert normalize_domain("bücher.de") == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "app.localhost",
        "printer.local",
        "db.internal",
        "router.home.arpa",
        "site.test",
        "example",  # single label, no TLD
        "127.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "10.0.0.5",
        "[::1]",
        "::1",
        "exa mple.com",
        "-bad-.com",
        "bad_.com",
        "a" * 64 + ".com",  # label longer than 63 characters
        ("a" * 60 + ".") * 5 + "com",  # name longer than 253 characters
        "example.123",  # numeric top-level domain
        "ftp://example.com",
        "http://user:password@example.com",
        "example.com:8080",
    ],
)
def test_invalid_or_unsafe_targets_are_rejected(raw):
    with pytest.raises(InvalidTargetError):
        normalize_domain(raw)


def test_invalid_target_error_is_a_value_error():
    # Existing code that catches ValueError keeps working.
    assert issubclass(InvalidTargetError, ValueError)
