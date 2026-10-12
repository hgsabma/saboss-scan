# Saboss Scan

[![Tests](https://github.com/hgsabma/saboss-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/hgsabma/saboss-scan/actions/workflows/tests.yml)

**Saboss Scan** is a passive security assessment platform for websites and domains, built by
Saboss Technologies. It checks publicly visible configuration (HTTPS, certificates, security
headers, cookies, DNS and e-mail protection), explains every finding with evidence, and tells you
exactly what to fix.

> Only assess domains you own or have explicit permission to assess. Saboss Scan makes only
> ordinary requests (the same ones a browser or mail server makes) and never attempts exploitation.

It comes in two forms that share one scanning engine:

| | Command line (`main.py`) | Web platform (`saboss_platform`) |
|---|---|---|
| For | Quick checks, scripts | Teams, history, monitoring |
| Accounts & organizations | – | ✓ roles: owner, admin, member, viewer |
| Reports | Terminal, JSON, HTML | Web, JSON, HTML, PDF |
| History, comparison, alerts | – | ✓ |
| API | – | ✓ REST API with API keys |

## What it checks

| Category | Checks |
|---|---|
| HTTPS / TLS | HTTPS available, certificate trusted and matching (critical), expiry, http:// → https:// redirect |
| HTTP security | Homepage status, HSTS (incl. max-age), Content-Security-Policy (incl. unsafe scripts), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy, cookie `Secure` / `HttpOnly` / `SameSite` |
| DNS | Domain resolves, IPv6 available |
| E-mail | SPF (incl. `+all`, multiple records), DMARC policy, DKIM (common selectors, marked as heuristic) |

Every finding includes **evidence** (what was observed), an **explanation** (why it matters),
a **confidence** (confirmed or heuristic) and a **recommendation**. Checks that could not run are
reported as *not checked* and never counted as failures.

### How the score works

| Severity | Points | | Outcome | Credit |
|---|---|---|---|---|
| critical | 20 | | pass | 100% |
| high | 10 | | warning | 50% |
| medium | 5 | | fail | 0% |
| low | 2 | | not checked / not applicable | excluded |
| info | 0 (shown, not scored) | | | |

Score = earned ÷ possible points. Grades: **A** ≥ 85%, **B** ≥ 70%, **C** ≥ 55%, **D** ≥ 40%, else **E**.
A failed critical check caps the grade at E, a failed high check at D. The report shows the
*coverage* (share of applicable checks that completed) as the score's confidence.
**A high score does not mean a website is secure**: it means the checked settings follow common best practices.

## Quick start

Requires Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate it (Windows PowerShell: `.venv\Scripts\Activate.ps1`, macOS/Linux: `source .venv/bin/activate`), then:

```bash
pip install -r requirements.txt
```

### Command line

```bash
python main.py example.com
python main.py example.com --html reports/example.html --json reports/example.json
```

Exit codes: `0` scan completed, `1` report could not be saved, `2` invalid or unsafe target.

### Web platform

```bash
python -m saboss_platform serve
```

Open http://127.0.0.1:8000, create an account, add a domain and run a scan. Data is stored in
`data/saboss.db` (SQLite) by default; the schema is created and migrated automatically.

For a production-like setup with PostgreSQL and Docker see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Security model (summary)

- **SSRF protection:** targets must be public domain names; every resolved address (including each
  redirect hop and webhook target) is checked, and connections are pinned to the checked IP to
  prevent DNS rebinding. Private, loopback, link-local, CGNAT and cloud-metadata addresses are refused.
- **Authorization:** adding a domain requires confirming authorization (recorded in the audit log);
  scheduled monitoring additionally requires DNS TXT ownership verification.
- **Accounts:** Argon2id password hashing, server-side sessions with hashed tokens, CSRF protection,
  rate limits, role-based access, organization isolation, audit log.
- **Web hardening:** strict Content-Security-Policy (no inline scripts or styles), HSTS in
  production, `X-Frame-Options: DENY`, escaped output everywhere, no stack traces shown to users.

Details and remaining risks: [docs/SECURITY.md](docs/SECURITY.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, data model, request flow, how future Saboss products plug in |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model, controls, known limitations, reporting vulnerabilities |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Configuration, Docker, PostgreSQL, backups, hardening checklist |
| [docs/API.md](docs/API.md) | REST API with examples |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Prioritized remaining work |

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest              # 217 offline tests (no real network traffic)
ruff check . && ruff format --check .
bandit -q -r saboss_scan saboss_platform main.py -s B105
pip-audit -r requirements.txt
```

GitHub Actions runs all of these, a migration consistency check and a Docker build on every pull request.

```text
main.py                    command-line interface
saboss_scan/               scanning engine (no web dependencies)
  scanner.py               runs all checks and builds the report
  utils.py                 target validation
  network_safety.py        private-address blocking
  http_client.py           HTTP client pinned to verified IPs
  ssl_checker.py, headers_checker.py, dns_checker.py
  findings.py              rules: raw results → findings
  scoring.py, recommendations.py, html_report.py
saboss_platform/           web platform shared by Saboss products
  app.py                   application factory, security middleware
  auth.py, security.py     sessions, CSRF, API keys, password hashing
  models.py                users, organizations, memberships, audit log
  routes_account.py        register, login, password reset
  routes_settings.py       account, organization, API keys, notifications, audit
  scan/                    the Saboss Scan product module
migrations/                Alembic database migrations
tests/                     automated tests
```

## Status

Version 0.4.0. The scanner, web platform, API, reports and monitoring work end to end and are
covered by automated tests. It has **not** yet been deployed publicly or load-tested, and it has not
had an external security review: see [docs/ROADMAP.md](docs/ROADMAP.md) before going live.
