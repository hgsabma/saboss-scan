import pytest

from saboss_scan.findings import evaluate
from saboss_scan.recommendations import build_recommendations

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": None,
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def scan_results(ssl=None, redirect=None, headers=None, headers_error=None, dns=None):
    """Build fake checker output; anything not given is a healthy default."""
    return {
        "ssl": ssl if ssl is not None else {
            "https": True, "certificate_valid": True, "days_until_expiry": 90,
            "error": None, "error_type": None,
        },
        "http_redirect": redirect if redirect is not None else {
            "redirects_to_https": True, "location": "https://example.com/", "error": None,
        },
        "headers": {"headers": {**GOOD_HEADERS, **(headers or {})}, "error": headers_error},
        "dns": {
            "a": ["192.0.2.1"], "aaaa": ["2001:db8::1"], "mx": ["10 mail.example.com."],
            "txt": [], "spf": ["v=spf1 include:_spf.example.com -all"],
            "dmarc": ["v=DMARC1; p=reject"], "dkim": {"selector1": ["v=DKIM1; k=rsa"]},
            "errors": {}, **(dns or {}),
        },
    }


def status_of(results, finding_id):
    return next(f for f in evaluate(results) if f.id == finding_id).status


def test_healthy_site_passes_everything():
    findings = evaluate(scan_results())
    assert {f.status for f in findings} == {"pass"}
    assert build_recommendations(findings) == []


# --- TLS ---------------------------------------------------------------

def test_refused_port_443_means_no_https():
    results = scan_results(ssl={"error_type": "refused", "error": "refused"})
    assert status_of(results, "tls.https") == "fail"


def test_timeout_is_not_checked_rather_than_failed():
    results = scan_results(ssl={"error_type": "timeout", "error": "timeout"})
    assert status_of(results, "tls.https") == "not_checked"
    assert status_of(results, "tls.certificate") == "not_checked"


def test_untrusted_certificate_fails():
    results = scan_results(ssl={"https": True, "error_type": "certificate", "error": "self-signed"})
    assert status_of(results, "tls.https") == "pass"
    assert status_of(results, "tls.certificate") == "fail"


@pytest.mark.parametrize(("days", "expected"), [(5, "fail"), (20, "warning"), (60, "pass")])
def test_certificate_expiry(days, expected):
    results = scan_results(ssl={"certificate_valid": True, "days_until_expiry": days, "error_type": None})
    assert status_of(results, "tls.expiry") == expected


def test_http_without_redirect_fails():
    results = scan_results(redirect={"redirects_to_https": False, "location": None, "status_code": 200, "error": None})
    assert status_of(results, "tls.http_redirect") == "fail"


def test_http_redirect_to_other_http_url_is_a_warning():
    results = scan_results(redirect={"redirects_to_https": False, "location": "http://www.example.com/", "error": None})
    assert status_of(results, "tls.http_redirect") == "warning"


# --- Headers -----------------------------------------------------------

def test_headers_not_checked_when_site_could_not_be_fetched():
    findings = evaluate(scan_results(headers_error="The request timed out."))
    header_findings = [f for f in findings if f.category == "http_headers"]
    assert {f.status for f in header_findings} == {"not_checked"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "fail"),
        ("max-age=0", "fail"),
        ("includeSubDomains", "fail"),
        ("max-age=86400", "warning"),
        ('max-age="31536000"', "pass"),
    ],
)
def test_hsts_max_age(value, expected):
    results = scan_results(headers={"strict-transport-security": value})
    assert status_of(results, "headers.hsts") == expected


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ("default-src 'self'", "pass"),
        ("script-src 'self' 'unsafe-inline'", "warning"),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", "pass"),
        ("default-src 'self' 'unsafe-eval'", "warning"),
        # unsafe-inline for styles only does not weaken script protection
        ("default-src 'self'; style-src 'unsafe-inline'", "pass"),
    ],
)
def test_csp_quality(policy, expected):
    results = scan_results(headers={"content-security-policy": policy})
    assert status_of(results, "headers.csp") == expected


def test_clickjacking_accepts_x_frame_options_without_csp():
    results = scan_results(headers={"content-security-policy": None, "x-frame-options": "DENY"})
    assert status_of(results, "headers.clickjacking") == "pass"


def test_clickjacking_fails_without_any_protection():
    results = scan_results(headers={"content-security-policy": "default-src 'self'", "x-frame-options": None})
    assert status_of(results, "headers.clickjacking") == "fail"


def test_weak_referrer_policy_is_a_warning():
    results = scan_results(headers={"referrer-policy": "unsafe-url"})
    assert status_of(results, "headers.referrer_policy") == "warning"


# --- E-mail and DNS --------------------------------------------------------

@pytest.mark.parametrize(
    ("spf", "expected"),
    [
        ([], "fail"),
        (["v=spf1 +all"], "fail"),
        (["v=spf1 all"], "fail"),
        (["v=spf1 ?all"], "warning"),
        (["v=spf1 include:x.com"], "warning"),
        (["v=spf1 ~all"], "pass"),
        (["v=spf1 -all"], "pass"),
        (["v=spf1 redirect=_spf.example.com"], "pass"),
        (["v=spf1 -all", "v=spf1 ~all"], "fail"),  # two SPF records are invalid
    ],
)
def test_spf_rules(spf, expected):
    assert status_of(scan_results(dns={"spf": spf}), "email.spf") == expected


@pytest.mark.parametrize(
    ("dmarc", "expected"),
    [
        ([], "fail"),
        (["v=DMARC1; p=none"], "warning"),
        (["v=DMARC1; p=quarantine"], "pass"),
        (["v=DMARC1;p=reject;rua=mailto:x@example.com"], "pass"),
        (["v=DMARC1; rua=mailto:x@example.com"], "fail"),  # no policy
        (["v=DMARC1; p=reject", "v=DMARC1; p=none"], "fail"),
    ],
)
def test_dmarc_rules(dmarc, expected):
    assert status_of(scan_results(dns={"dmarc": dmarc}), "email.dmarc") == expected


def test_dns_lookup_failure_is_not_checked():
    results = scan_results(dns={"txt": [], "spf": [], "errors": {"txt": "DNS lookup timed out."}})
    assert status_of(results, "email.spf") == "not_checked"


def test_domain_without_addresses_fails():
    results = scan_results(dns={"a": [], "aaaa": []})
    assert status_of(results, "dns.resolves") == "fail"


def test_missing_dkim_is_only_informational():
    findings = evaluate(scan_results(dns={"dkim": {}}))
    dkim = next(f for f in findings if f.id == "email.dkim")
    assert dkim.status == "warning"
    assert dkim.severity == "info"


def test_recommendations_are_sorted_by_severity():
    results = scan_results(
        ssl={"error_type": "refused", "error": "refused"},
        headers={"referrer-policy": None},
    )
    recommendations = build_recommendations(evaluate(results))
    assert recommendations[0].startswith("[HIGH]")
    assert recommendations[-1].startswith("[LOW]")
