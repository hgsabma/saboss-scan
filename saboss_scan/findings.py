"""Turn raw checker results into findings.

A finding answers one question about the target, for example
"Does the site send an HSTS header?". Every finding has:

- severity: how important the check is (critical, high, medium, low, info).
  This is fixed per check, so the score stays comparable between scans.
- status: the outcome of the check.
    pass            the check succeeded
    warning         partly OK, but could be improved
    fail            the problem was found
    not_checked     the scanner could not determine the answer (for example
                    a timeout); it is NOT counted as a failure
    not_applicable  nothing to evaluate (for example no cookies are set)
- evidence: what was actually observed (a fact), e.g. the header value.
- explanation: why this matters (the inferred risk).
- confidence: "confirmed" when the outcome follows directly from what was
  observed, "heuristic" when the scanner can only make an educated guess.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

PASS = "pass"
WARNING = "warning"
FAIL = "fail"
NOT_CHECKED = "not_checked"
NOT_APPLICABLE = "not_applicable"
STATUSES = (PASS, WARNING, FAIL, NOT_CHECKED, NOT_APPLICABLE)

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"
SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)

CONFIRMED = "confirmed"
HEURISTIC = "heuristic"

HSTS_RECOMMENDED_MAX_AGE = 15_552_000  # 180 days, in seconds
CERT_EXPIRY_FAIL_DAYS = 14
CERT_EXPIRY_WARNING_DAYS = 30

EXPLANATIONS = {
    "tls.https": "Without HTTPS, everything sent between visitors and the site can be read or changed by anyone on the network.",
    "tls.certificate": "Browsers show a full-page security warning for untrusted or mismatched certificates, and visitors cannot tell the real site from an impostor.",
    "tls.expiry": "An expired certificate takes the site offline for most visitors until it is renewed.",
    "tls.http_redirect": "Visitors who type the address without https:// stay on an unencrypted connection unless they are redirected.",
    "web.https_status": "Shows whether the homepage loads successfully over HTTPS. Errors can mean the site is down or blocking automated checks.",
    "headers.hsts": "HSTS tells browsers to always use HTTPS for this site, which blocks downgrade attacks on public Wi-Fi.",
    "headers.csp": "A Content-Security-Policy limits which scripts can run, reducing the damage of cross-site scripting (XSS) bugs.",
    "headers.clickjacking": "Without framing protection, another site can load this site invisibly and trick visitors into clicking buttons.",
    "headers.nosniff": "Stops browsers from guessing file types, which can turn an uploaded file into executable script.",
    "headers.referrer_policy": "Controls how much of the page address is shared with other sites, which can leak private URLs or tokens.",
    "headers.permissions_policy": "Lets the site switch off browser features (camera, microphone, location) it does not use.",
    "headers.cookies": "Cookies without Secure, HttpOnly and SameSite can be stolen over HTTP, read by injected scripts, or sent in cross-site attacks.",
    "dns.resolves": "If the domain has no address records, nobody can reach the website.",
    "dns.ipv6": "Some networks are IPv6-only; IPv6 support improves reachability.",
    "email.spf": "SPF lists the servers allowed to send e-mail for the domain, making it harder to forge its address.",
    "email.dmarc": "DMARC tells receiving mail servers to reject or quarantine forged e-mail that claims to come from the domain.",
    "email.dkim": "DKIM adds a cryptographic signature to outgoing e-mail so receivers can verify it was not forged.",
}
HEURISTIC_CHECKS = {"email.dkim"}


@dataclass
class Finding:
    id: str
    category: str
    title: str
    severity: str
    status: str
    detail: str = ""
    recommendation: str = ""
    evidence: str = ""
    explanation: str = ""
    confidence: str = CONFIRMED

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


# ---------------------------------------------------------------- TLS / HTTPS


def _tls_findings(ssl_result: dict[str, Any], redirect_result: dict[str, Any]) -> list[Finding]:
    error_type = ssl_result.get("error_type")
    error = ssl_result.get("error") or ""

    https = Finding("tls.https", "tls", "HTTPS is available", HIGH, NOT_CHECKED)
    if error_type in (None, "certificate"):
        https.status = PASS
        if ssl_result.get("tls_version"):
            https.evidence = f"TLS handshake succeeded ({ssl_result['tls_version']})."
        else:
            https.evidence = "TLS handshake on port 443 succeeded."
    elif error_type in ("refused", "tls"):
        https.status = FAIL
        https.detail = error
        https.evidence = error
        https.recommendation = "Serve the website over HTTPS on port 443 with a modern TLS configuration."
    else:
        https.detail = f"Could not connect to port 443: {error}"

    cert = Finding("tls.certificate", "tls", "TLS certificate is trusted and matches the domain", CRITICAL, NOT_CHECKED)
    if ssl_result.get("certificate_valid"):
        cert.status = PASS
        cert.detail = f"Issuer: {ssl_result.get('issuer')}"
        cert.evidence = f"Subject: {ssl_result.get('subject')}; issuer: {ssl_result.get('issuer')}"
    elif error_type == "certificate":
        cert.status = FAIL
        cert.detail = error
        cert.evidence = error
        cert.recommendation = (
            "Install a certificate from a trusted authority that covers this exact domain "
            "(for example a free Let's Encrypt certificate)."
        )

    expiry = Finding("tls.expiry", "tls", "TLS certificate is not about to expire", MEDIUM, NOT_CHECKED)
    days = ssl_result.get("days_until_expiry")
    if isinstance(days, int):
        expiry.detail = f"Expires in {days} days ({ssl_result.get('expires_at')})."
        expiry.evidence = f"Certificate valid until {ssl_result.get('expires_at')}."
        if days < CERT_EXPIRY_FAIL_DAYS:
            expiry.status = FAIL
            expiry.recommendation = "Renew the TLS certificate now and enable automatic renewal."
        elif days < CERT_EXPIRY_WARNING_DAYS:
            expiry.status = WARNING
            expiry.recommendation = "Renew the TLS certificate soon and enable automatic renewal."
        else:
            expiry.status = PASS

    redirect = Finding("tls.http_redirect", "tls", "Plain HTTP redirects to HTTPS", MEDIUM, NOT_CHECKED)
    redirects_to_https = redirect_result.get("redirects_to_https")
    status_code = redirect_result.get("status_code")
    if redirects_to_https is True:
        redirect.status = PASS
        redirect.evidence = f"http:// answered {status_code} → {redirect_result.get('location')}"
    elif redirect_result.get("error"):
        redirect.detail = f"Could not check http://: {redirect_result['error']}"
    elif redirect_result.get("location"):
        redirect.status = WARNING
        redirect.evidence = f"http:// answered {status_code} → {redirect_result['location']}"
        redirect.detail = f"http:// redirects to {redirect_result['location']} instead of directly to HTTPS."
        redirect.recommendation = "Make http:// redirect straight to the https:// address of the same host."
    elif redirects_to_https is False:
        redirect.status = FAIL
        redirect.evidence = f"http:// answered {status_code} without a redirect."
        redirect.detail = f"http:// answered with status {status_code} and no redirect."
        redirect.recommendation = "Redirect all http:// requests to https:// with a 301 redirect."

    return [https, cert, expiry, redirect]


# ------------------------------------------------------------- HTTP headers


def _csp_directives(policy: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in policy.split(";"):
        tokens = part.strip().split(None, 1)
        if tokens:
            directives[tokens[0].lower()] = tokens[1].lower() if len(tokens) > 1 else ""
    return directives


def _header_evidence(name: str, value: str | None) -> str:
    return f"{name}: {value}" if value else f"{name}: (not sent)"


def _cookie_finding(headers_result: dict[str, Any]) -> Finding:
    finding = Finding("headers.cookies", "http_headers", "Cookie security attributes", MEDIUM, NOT_CHECKED)
    if headers_result.get("error"):
        finding.detail = f"Could not fetch the website: {headers_result['error']}"
        return finding

    cookies = headers_result.get("cookies", [])
    if not cookies:
        finding.status = NOT_APPLICABLE
        finding.detail = "The homepage did not set any cookies."
        finding.evidence = "No Set-Cookie headers were observed."
        return finding

    def describe(cookie: dict[str, Any]) -> str:
        flags = [flag for flag in ("Secure", "HttpOnly") if cookie.get(flag.lower())]
        flags.append(f"SameSite={cookie['samesite']}" if cookie.get("samesite") else "no SameSite")
        return f"{cookie['name']} ({', '.join(flags)})"

    finding.evidence = "; ".join(describe(cookie) for cookie in cookies)
    not_secure = [c["name"] for c in cookies if not c.get("secure")]
    weak = [c["name"] for c in cookies if not c.get("httponly") or not c.get("samesite")]
    samesite_none_insecure = [c["name"] for c in cookies if c.get("samesite") == "none" and not c.get("secure")]

    if not_secure or samesite_none_insecure:
        finding.status = FAIL
        finding.detail = "Cookies without the Secure flag: " + ", ".join(
            sorted(set(not_secure + samesite_none_insecure))
        )
        finding.recommendation = "Add the Secure attribute to every cookie so it is never sent over plain HTTP."
    elif weak:
        finding.status = WARNING
        finding.detail = "Cookies missing HttpOnly or SameSite: " + ", ".join(weak)
        finding.recommendation = (
            "Add HttpOnly to cookies that scripts do not need to read, and set SameSite=Lax or Strict."
        )
    else:
        finding.status = PASS
    return finding


def _header_findings(headers_result: dict[str, Any]) -> list[Finding]:
    status_finding = Finding(
        "web.https_status", "http_headers", "HTTPS homepage responds successfully", LOW, NOT_CHECKED
    )
    hsts = Finding("headers.hsts", "http_headers", "Strict-Transport-Security (HSTS)", MEDIUM, NOT_CHECKED)
    csp = Finding("headers.csp", "http_headers", "Content-Security-Policy (CSP)", MEDIUM, NOT_CHECKED)
    framing = Finding("headers.clickjacking", "http_headers", "Clickjacking protection", MEDIUM, NOT_CHECKED)
    nosniff = Finding("headers.nosniff", "http_headers", "X-Content-Type-Options: nosniff", LOW, NOT_CHECKED)
    referrer = Finding("headers.referrer_policy", "http_headers", "Referrer-Policy", LOW, NOT_CHECKED)
    permissions = Finding("headers.permissions_policy", "http_headers", "Permissions-Policy", INFO, NOT_CHECKED)
    findings = [status_finding, hsts, csp, framing, nosniff, referrer, permissions]

    if headers_result.get("error"):
        for finding in findings:
            finding.detail = f"Could not fetch the website: {headers_result['error']}"
        return findings + [_cookie_finding(headers_result)]

    values: dict[str, str | None] = headers_result.get("headers", {})

    # Homepage status
    code = headers_result.get("status_code")
    status_finding.evidence = f"{headers_result.get('final_url')} answered HTTP {code}."
    if isinstance(code, int) and code < 400:
        status_finding.status = PASS
    elif isinstance(code, int):
        status_finding.status = WARNING
        status_finding.detail = (
            f"The homepage answered HTTP {code}. Header results may not reflect what normal visitors receive."
        )
        status_finding.recommendation = "Check that the homepage loads correctly over HTTPS."

    # HSTS
    hsts_value = values.get("strict-transport-security")
    hsts.evidence = _header_evidence("Strict-Transport-Security", hsts_value)
    match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts_value or "", re.IGNORECASE)
    if not hsts_value:
        hsts.status = FAIL
        hsts.recommendation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
    elif not match or int(match.group(1)) == 0:
        hsts.status = FAIL
        hsts.detail = f"Header present but max-age is missing or 0: {hsts_value}"
        hsts.recommendation = "Set a positive max-age, for example max-age=31536000."
    elif int(match.group(1)) < HSTS_RECOMMENDED_MAX_AGE:
        hsts.status = WARNING
        hsts.detail = f"max-age is {match.group(1)} seconds (less than 180 days)."
        hsts.recommendation = "Increase HSTS max-age to at least 15552000 (180 days)."
    else:
        hsts.status = PASS

    # CSP
    csp_value = values.get("content-security-policy")
    csp.evidence = _header_evidence("Content-Security-Policy", csp_value)
    directives = _csp_directives(csp_value or "")
    if not csp_value:
        csp.status = FAIL
        csp.recommendation = "Add a Content-Security-Policy to reduce the impact of cross-site scripting (XSS)."
    else:
        script_policy = directives.get("script-src", directives.get("default-src", ""))
        allows_inline = "'unsafe-inline'" in script_policy and not re.search(r"'(nonce|sha\d+)-", script_policy)
        if allows_inline or "'unsafe-eval'" in script_policy:
            csp.status = WARNING
            csp.detail = "The policy allows 'unsafe-inline' or 'unsafe-eval' scripts, which weakens XSS protection."
            csp.recommendation = "Remove 'unsafe-inline'/'unsafe-eval' from script-src and use nonces or hashes."
        else:
            csp.status = PASS

    # Clickjacking: CSP frame-ancestors replaces X-Frame-Options.
    xfo = (values.get("x-frame-options") or "").strip().lower()
    if "frame-ancestors" in directives:
        framing.evidence = f"Content-Security-Policy frame-ancestors {directives['frame-ancestors']}"
    else:
        framing.evidence = _header_evidence("X-Frame-Options", values.get("x-frame-options"))
    if "frame-ancestors" in directives or xfo in ("deny", "sameorigin"):
        framing.status = PASS
    elif xfo:
        framing.status = WARNING
        framing.detail = f"Unsupported X-Frame-Options value: {xfo}"
        framing.recommendation = "Use X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors."
    else:
        framing.status = FAIL
        framing.recommendation = "Add CSP 'frame-ancestors' (or X-Frame-Options: DENY) to prevent clickjacking."

    # nosniff
    nosniff.evidence = _header_evidence("X-Content-Type-Options", values.get("x-content-type-options"))
    if (values.get("x-content-type-options") or "").strip().lower() == "nosniff":
        nosniff.status = PASS
    else:
        nosniff.status = FAIL
        nosniff.recommendation = "Add 'X-Content-Type-Options: nosniff'."

    # Referrer-Policy
    referrer.evidence = _header_evidence("Referrer-Policy", values.get("referrer-policy"))
    referrer_value = (values.get("referrer-policy") or "").strip().lower()
    if not referrer_value:
        referrer.status = FAIL
        referrer.recommendation = "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    elif referrer_value in ("unsafe-url", "no-referrer-when-downgrade"):
        referrer.status = WARNING
        referrer.detail = f"'{referrer_value}' can leak full URLs to other websites."
        referrer.recommendation = "Use 'strict-origin-when-cross-origin' or stricter."
    else:
        referrer.status = PASS

    # Permissions-Policy (informational only)
    permissions.evidence = _header_evidence("Permissions-Policy", values.get("permissions-policy"))
    if values.get("permissions-policy"):
        permissions.status = PASS
    else:
        permissions.status = WARNING
        permissions.recommendation = "Consider a Permissions-Policy to disable browser features you do not use."

    return findings + [_cookie_finding(headers_result)]


# ---------------------------------------------------------- DNS and e-mail


def _spf_finding(dns_result: dict[str, Any]) -> Finding:
    finding = Finding("email.spf", "email", "SPF record", MEDIUM, NOT_CHECKED)
    if "txt" in dns_result.get("errors", {}):
        finding.detail = f"TXT lookup failed: {dns_result['errors']['txt']}"
        return finding

    records = dns_result.get("spf", [])
    finding.evidence = " | ".join(records) if records else "No TXT record starting with v=spf1."
    if not records:
        finding.status = FAIL
        finding.recommendation = "Publish an SPF record. If the domain sends no e-mail, use 'v=spf1 -all'."
        return finding
    if len(records) > 1:
        finding.status = FAIL
        finding.detail = f"{len(records)} SPF records found; only one is allowed, so SPF is invalid."
        finding.recommendation = "Merge the SPF records into a single TXT record."
        return finding

    terms = records[0].lower().split()
    finding.detail = records[0]
    if "+all" in terms or "all" in terms:
        finding.status = FAIL
        finding.recommendation = "'+all' lets anyone send mail as your domain. Change it to '-all' or '~all'."
    elif "?all" in terms:
        finding.status = WARNING
        finding.recommendation = "'?all' gives no protection. Change it to '-all' or '~all'."
    elif "-all" in terms or "~all" in terms or any(term.startswith("redirect=") for term in terms):
        finding.status = PASS
    else:
        finding.status = WARNING
        finding.recommendation = "End the SPF record with '-all' or '~all'."
    return finding


def _dmarc_finding(dns_result: dict[str, Any]) -> Finding:
    finding = Finding("email.dmarc", "email", "DMARC policy", MEDIUM, NOT_CHECKED)
    if "dmarc" in dns_result.get("errors", {}):
        finding.detail = f"DMARC lookup failed: {dns_result['errors']['dmarc']}"
        return finding

    records = dns_result.get("dmarc", [])
    finding.evidence = " | ".join(records) if records else "No DMARC record at _dmarc.<domain>."
    if not records:
        finding.status = FAIL
        finding.recommendation = (
            "Publish a DMARC record at _dmarc.<domain>, starting with 'v=DMARC1; p=none' to monitor."
        )
        return finding
    if len(records) > 1:
        finding.status = FAIL
        finding.detail = f"{len(records)} DMARC records found; only one is allowed."
        finding.recommendation = "Keep exactly one DMARC record."
        return finding

    tags = {}
    for part in records[0].split(";"):
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip().lower()
    policy = tags.get("p")
    finding.detail = records[0]
    if policy in ("quarantine", "reject"):
        finding.status = PASS
    elif policy == "none":
        finding.status = WARNING
        finding.recommendation = "DMARC 'p=none' only monitors. Move to 'p=quarantine' and then 'p=reject'."
    else:
        finding.status = FAIL
        finding.recommendation = "The DMARC record has no valid 'p=' policy. Fix the record syntax."
    return finding


def _dns_findings(dns_result: dict[str, Any]) -> list[Finding]:
    errors = dns_result.get("errors", {})
    resolves = Finding("dns.resolves", "dns", "Domain resolves to an address", HIGH, NOT_CHECKED)
    addresses = dns_result.get("a", []) + dns_result.get("aaaa", [])
    if addresses:
        resolves.status = PASS
        resolves.evidence = "Addresses: " + ", ".join(addresses[:10])
    elif "a" in errors or "aaaa" in errors:
        resolves.detail = f"DNS lookup failed: {errors.get('a') or errors.get('aaaa')}"
    else:
        resolves.status = FAIL
        resolves.evidence = "No A or AAAA records were returned."
        resolves.detail = "No A or AAAA records were found. Check the domain name."
        resolves.recommendation = "Make sure the domain is registered and has A/AAAA records."

    ipv6 = Finding("dns.ipv6", "dns", "IPv6 (AAAA) is available", INFO, NOT_CHECKED)
    if dns_result.get("aaaa"):
        ipv6.status = PASS
        ipv6.evidence = "AAAA: " + ", ".join(dns_result["aaaa"][:5])
    elif "aaaa" not in errors:
        ipv6.status = WARNING
        ipv6.evidence = "No AAAA records were returned."
        ipv6.recommendation = "Consider adding AAAA records so IPv6-only users can reach the site."

    dkim = Finding("email.dkim", "email", "DKIM key found (common selectors only)", INFO, NOT_CHECKED)
    if dns_result.get("dkim"):
        dkim.status = PASS
        dkim.detail = "Selectors found: " + ", ".join(dns_result["dkim"])
        dkim.evidence = dkim.detail
    else:
        dkim.status = WARNING
        dkim.evidence = "No DKIM key at the common selectors that were tried."
        dkim.detail = (
            "No DKIM key found with common selector names. DKIM may still be configured "
            "with another selector; this scan cannot list all selectors."
        )
        dkim.recommendation = "If the domain sends e-mail, make sure DKIM signing is enabled."

    return [resolves, ipv6, _spf_finding(dns_result), _dmarc_finding(dns_result), dkim]


def evaluate(results: dict[str, Any]) -> list[Finding]:
    """Build all findings from the raw results of the checkers."""
    findings = (
        _tls_findings(results.get("ssl", {}), results.get("http_redirect", {}))
        + _header_findings(results.get("headers", {}))
        + _dns_findings(results.get("dns", {}))
    )
    for finding in findings:
        finding.explanation = EXPLANATIONS.get(finding.id, "")
        if finding.id in HEURISTIC_CHECKS:
            finding.confidence = HEURISTIC
    return findings
