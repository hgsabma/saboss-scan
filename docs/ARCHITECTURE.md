# Architecture

Saboss Scan is the first product of Saboss Technologies. The code is split so the scanning engine,
the shared platform and the product can evolve independently, without building infrastructure that
is not needed yet.

```text
┌──────────────────────────── saboss_platform (shared) ─────────────────────────────┐
│ app.py      FastAPI factory · security headers · logging · errors · health        │
│ auth.py     sessions · CSRF · API keys · roles        security.py  Argon2, tokens │
│ models.py   User · Organization · Membership · UserSession · ApiKey · AuditLog     │
│ routes_account.py / routes_settings.py   web.py (templates, flash, redirects)     │
│ notifications.py (SMTP, webhooks)  ratelimit.py  audit.py  config.py  db.py       │
│                                                                                    │
│   ┌────────── saboss_platform.scan (product module: Saboss Scan) ──────────┐      │
│   │ models.py  Domain · Scan · Alert       service.py  business logic      │      │
│   │ worker.py  thread pool + scheduler     routes_web.py · routes_api.py   │      │
│   │ pdf.py     PDF reports                                                  │      │
│   └──────────────────────────────┬─────────────────────────────────────────┘      │
└──────────────────────────────────┼────────────────────────────────────────────────┘
                                   │ scan_domain(hostname) → report dict
┌──────────────────────────────────▼──────────── saboss_scan (engine) ──────────────┐
│ utils.normalize_domain → network_safety (public IPs only) → checkers:              │
│   ssl_checker · headers_checker (http_client, pinned IP) · dns_checker            │
│ findings.evaluate → scoring.calculate_score → recommendations · html_report      │
└────────────────────────────────────────────────────────────────────────────────────┘
```

## Layers

**Engine (`saboss_scan`)** – a plain Python library with no web or database dependencies. The
command line (`main.py`) and the platform both call `scan_domain()`. Checkers only collect raw facts;
`findings.py` turns facts into findings; `scoring.py` and `recommendations.py` only read findings.
This keeps the rules testable without a network.

**Platform (`saboss_platform`)** – everything that is not specific to one product: accounts,
organizations and roles, sessions, API keys, audit log, notifications, configuration, the design
system (`static/app.css`) and page layout (`templates/base.html`).

**Product module (`saboss_platform.scan`)** – the Saboss Scan features: domains, scans, monitoring,
alerts, reports and its REST API.

## Request flow (web scan)

1. `POST /domains/{id}/scan` → CSRF check → session lookup → role check (member+).
2. `service.create_scan` checks "already running" and the per-organization hourly limit, then stores
   a `queued` scan and records `scan.created` in the audit log.
3. `ScanWorker.submit` runs `service.run_scan` in a background thread. The browser shows a progress
   page that polls `GET /scans/{id}/status`.
4. `run_scan` calls the engine, stores the JSON report, grade and score, and (for monitored domains)
   compares the result with the previous scan to create and deliver alerts.

## Data model

| Table | Purpose |
|---|---|
| `users` | E-mail, name, Argon2id password hash |
| `organizations` | Tenant; notification settings |
| `memberships` | User ↔ organization with role (owner, admin, member, viewer) |
| `user_sessions` | SHA-256 of session token, current organization, expiry |
| `password_reset_tokens` | SHA-256 of reset token, expiry, used flag |
| `api_keys` | SHA-256 of key, prefix for display, role, revoked flag |
| `audit_log` | Who did what, when, from which IP |
| `domains` | Hostname per organization, authorization attestation, TXT verification, monitoring schedule |
| `scans` | Status, timestamps, grade, score, full report (JSON) |
| `alerts` | Changes detected by monitoring, delivery status |

Every product query filters by `organization_id` of the signed-in user or API key; objects of other
organizations return 404 (not 403) so their existence is not revealed.

## Key decisions and trade-offs

| Decision | Why | When to revisit |
|---|---|---|
| Server-rendered HTML (Jinja2) + one small JS file | Fast, accessible, works without JavaScript, strict CSP possible | When the UI needs rich client-side interaction |
| SQLite default, PostgreSQL in production | Zero setup locally; Postgres for concurrency and backups | – |
| In-process thread pool for scans | One process to deploy; queued scans survive restarts in the DB | Several app servers or > ~1 scan/second: move to Redis + RQ/Celery behind `ScanWorker` |
| In-memory rate limiting | No extra service | Several app servers: move to Redis |
| Report stored as JSON in `scans.report_json` | Reports are versioned documents; easy export | When cross-scan analytics need indexed finding tables |
| Server-side sessions instead of JWT | Instant logout and revocation, no signing secret | – |
| Double-submit CSRF cookie + Origin check | Works before login (login/registration CSRF) | – |

## Adding a future Saboss product

A new product (for example a future Saboss Monitor or Saboss AI Security) should:

1. Create `saboss_platform/<product>/` with `models.py` (tables with an `organization_id`),
   `service.py`, `routes_web.py` and optionally `routes_api.py` under `/api/v1/<product>/`.
2. Import its models in `migrations/env.py` and generate a migration (`alembic revision --autogenerate`).
3. Include its routers in `app.py` and add navigation entries in `templates/base.html`.
4. Reuse `current_user` / `api_client` dependencies, `ctx.require(role)`, `audit.record`,
   `notifications` and the design system instead of re-implementing them.

Shared billing, single sign-on across products and a central Trust Center are deliberately **not**
built yet; they should be added when a second product exists and needs them.
