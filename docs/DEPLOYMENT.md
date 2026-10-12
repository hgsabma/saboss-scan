# Deployment

> Nothing in this repository deploys anything automatically. Public deployment, DNS, TLS
> certificates and paid infrastructure are decisions for the operator.

## Configuration

All settings are environment variables (see `.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `SABOSS_ENV` | `development` | `production` enables secure cookies by default and disables dev conveniences |
| `SABOSS_DATABASE_URL` | `sqlite:///./data/saboss.db` | SQLAlchemy URL, e.g. `postgresql+psycopg://user:pass@host/db` |
| `SABOSS_BASE_URL` | `http://127.0.0.1:8000` | Public URL (links in e-mails/alerts, CSRF origin check) |
| `SABOSS_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Host names the app answers to |
| `SABOSS_COOKIE_SECURE` | `true` in production | Secure + `__Host-` cookies (requires HTTPS) |
| `SABOSS_REGISTRATION_OPEN` | `true` | Allow self-registration |
| `SABOSS_SESSION_MAX_AGE_HOURS` / `SABOSS_SESSION_IDLE_HOURS` | `168` / `48` | Session lifetime |
| `SABOSS_SCAN_WORKERS` | `2` | Parallel scans per process |
| `SABOSS_SCANS_PER_ORG_PER_HOUR` | `30` | Abuse limit |
| `SABOSS_SCHEDULER_ENABLED` / `SABOSS_SCHEDULER_POLL_SECONDS` | `true` / `60` | Monitoring scheduler |
| `SABOSS_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_STARTTLS` | empty | E-mail for password resets and alerts (disabled when empty) |
| `SABOSS_HOST`, `SABOSS_PORT` | `127.0.0.1`, `8000` | Bind address |
| `SABOSS_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies whose `X-Forwarded-*` headers are trusted |
| `SABOSS_LOG_LEVEL` | `INFO` | Log level (logs are JSON lines on stdout) |

## Local development

```bash
pip install -r requirements-dev.txt
python -m saboss_platform serve --reload
```

Migrations run automatically at startup. To run them separately: `python -m saboss_platform migrate`.

## Docker (with PostgreSQL)

```bash
cp .env.example .env        # set POSTGRES_PASSWORD, SABOSS_BASE_URL, SABOSS_ALLOWED_HOSTS
docker compose up --build
```

The compose file binds the app to `127.0.0.1:8000` only. Put a reverse proxy (Caddy, nginx,
Traefik or a cloud load balancer) in front of it for TLS. The image runs as an unprivileged user and
has a health check on `/healthz`.

*Status:* the Dockerfile and compose file are built and health-checked in CI. They were not run on
the development machine (Docker was not installed there), and the PostgreSQL configuration has not
yet been exercised against a real PostgreSQL server: test it before relying on it.

## Health checks

- `GET /healthz` – the process is up (liveness).
- `GET /readyz` – the database answers (readiness); returns 503 otherwise.

## Database migrations

Schema changes are Alembic migrations in `migrations/versions/`.

```bash
alembic revision --autogenerate -m "describe the change"   # after changing models
alembic upgrade head
alembic check                                               # CI: models and migrations agree
```

Run only one application instance while migrating.

## Backups

- **PostgreSQL:** `pg_dump --format=custom` daily, encrypted, stored off-site; test restores
  regularly (`pg_restore` into a scratch database).
- **SQLite:** stop the app or use `sqlite3 data/saboss.db ".backup backup.db"`.
- Backups contain e-mail addresses, password hashes, webhook URLs and scan reports: treat them as
  confidential.

## Scaling notes

The app is designed for one process at this stage. Before running several instances:

1. Move rate limiting to Redis.
2. Move scans to a real job queue (e.g. RQ or Celery) behind `saboss_platform/scan/worker.py`.
3. Run the scheduler in exactly one place.
