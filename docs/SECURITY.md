# Security

Saboss Scan is security software and is itself a target. This document describes the threat model,
the controls in place, how they are tested, and the known remaining risks.

## Reporting a vulnerability

Please report security issues privately to the maintainers (for now: open a GitHub security
advisory on the repository, not a public issue). Include steps to reproduce. Do not test against
other people's installations.

## Responsible use

Saboss Scan performs passive checks only: DNS lookups, one TLS handshake, and a few HTTP GET
requests for headers (page bodies are not downloaded). It never sends exploits, brute-forces,
crawls, or bypasses authentication. Users must confirm they are authorized to assess a domain before
adding it (recorded in the audit log), and scheduled monitoring requires DNS ownership verification.

## Threats and controls

| Threat | Control | Tested in |
|---|---|---|
| **SSRF**: using the scanner to reach internal systems | Targets must be valid public domain names (no IPs, `localhost`, `.local`, `.internal`, …). All resolved addresses must be public (`ipaddress.is_global`, IPv4-mapped IPv6 unwrapped). Applies to the target, every redirect hop (max 5) and webhook URLs. | `test_utils.py`, `test_network_safety.py`, `test_platform.py` |
| **DNS rebinding** | The name is resolved once, checked, and the TCP connection goes to exactly that IP (TLS SNI and certificate verification still use the hostname). | `test_http_client.py`, `test_checkers.py` |
| **Hostile scan results** (XSS via header values) | Jinja2 autoescaping; HTML report escapes every value; reportlab text escaped; strict CSP without inline scripts or styles; cookie *values* are never stored. | `test_html_report.py`, `test_platform.py` |
| **Account takeover** | Argon2id hashing; constant-work login for unknown e-mails; login rate limits per IP and per e-mail; generic error messages; sessions rotated at login, invalidated at logout, on password change and reset. | `test_platform.py` |
| **Session theft** | Random 256-bit tokens, only SHA-256 stored; HttpOnly, SameSite=Lax, Secure + `__Host-` prefix in production; absolute and idle expiry. | `test_platform.py` |
| **CSRF** | Double-submit token (SameSite=Strict cookie) on every form, plus Origin check; API uses bearer keys, not cookies. | `test_platform.py` |
| **Broken access control / IDOR** | Every query filtered by organization; other organizations' objects return 404; role checks on every mutating route; last owner cannot be removed. | `test_platform.py` |
| **API key leakage** | Keys shown once, stored as SHA-256, revocable, scoped to one organization and a role. | `test_platform.py` |
| **SQL injection** | SQLAlchemy ORM and bound parameters only; `LIKE` searches use `autoescape`. | – |
| **Open redirect** | `next` parameter limited to same-site paths. | `test_platform.py` |
| **Information leakage** | Generic error pages, no stack traces; unexpected scan errors logged server-side only; logs contain paths but not query strings (reset tokens). | `test_platform.py` |
| **Host header attacks** | `TrustedHostMiddleware` with an explicit allow-list. | `test_platform.py` |
| **Clickjacking / MIME sniffing** | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`. | `test_platform.py` |
| **Vulnerable dependencies** | Pinned versions; `pip-audit` in CI; `bandit` and ruff security rules in CI. | CI |
| **Abuse of scanning capacity** | Per-organization hourly scan limit, one active scan per domain, per-API-key request limit. | `test_platform.py` |

## Known limitations and remaining risks

1. **Rate limits are in memory.** They reset on restart and are per process. Use Redis before running
   several app instances.
2. **Authorization for one-off scans is an attestation**, not proof. Only monitoring requires DNS
   verification. Consider requiring verification for all scans on a public, open-registration service.
3. **No e-mail verification at registration** and no multi-factor authentication yet.
4. **Password reset depends on SMTP.** Without SMTP the link is only printed to the server log in
   development mode (never in production).
5. **Account enumeration at registration:** registering an existing e-mail reports that it exists
   (mitigated by rate limiting).
6. **No external security review or penetration test** has been performed yet.
7. **Webhook URLs are stored in plain text** in the database; protect database access and backups.
8. **Single-process scheduler:** running several instances would schedule duplicate scans.

## Deployment hardening checklist

- Run behind a TLS-terminating reverse proxy; set `SABOSS_ENV=production`, `SABOSS_BASE_URL`,
  `SABOSS_ALLOWED_HOSTS`, keep `SABOSS_COOKIE_SECURE=true`.
- Use PostgreSQL with a strong password, private network, and encrypted, tested backups.
- Restrict outbound traffic of the scanner host to ports 53, 80, 443 (and SMTP if used).
- Do not run the scanner inside a network with sensitive internal services without egress filtering
  as a second line of defence against SSRF.
- Set `SABOSS_REGISTRATION_OPEN=false` if the installation is private.
- Monitor the JSON logs for `user.login_failed` spikes and 5xx errors.
