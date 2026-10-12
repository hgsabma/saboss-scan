# Saboss Scan API (v1)

Base path: `/api/v1`. The OpenAPI 3 specification is served at `/api/openapi.json`.

## Authentication

Create an API key under **Settings → API keys** (admins only). Keys belong to one organization:

- **Scan** keys (role `member`) can add domains and start scans.
- **Read only** keys (role `viewer`) can list and read.

```http
Authorization: Bearer sbk_...
```

## Limits

- 120 requests per minute per key (`429 rate_limited`).
- Scans per organization per hour: `SABOSS_SCANS_PER_ORG_PER_HOUR` (default 30).
- One active scan per domain (`409 conflict`).

## Errors

```json
{"error": {"code": "not_found", "message": "Scan not found."}}
```

Codes: `unauthorized` (401), `forbidden` (403), `not_found` (404), `conflict` (409),
`validation_error` (422, with a `fields` list), `rate_limited` (429), `internal_error` (500).
Submitted values are never echoed back in error messages.

## Endpoints

### Domains

```bash
# List (page, per_page ≤ 100)
curl -s "$BASE/api/v1/domains?page=1&per_page=25" -H "Authorization: Bearer $KEY"

# Add: "authorized": true confirms you may assess the domain
curl -s -X POST "$BASE/api/v1/domains" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"hostname": "example.com", "authorized": true}'

# Get one
curl -s "$BASE/api/v1/domains/1" -H "Authorization: Bearer $KEY"
```

Domain object: `id`, `hostname`, `verified`, `monitoring`, `monitor_interval_hours`, `created_at`.

### Scans

```bash
# Start (202 Accepted); then poll until status is "completed" or "failed"
curl -s -X POST "$BASE/api/v1/scans" -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" -d '{"domain_id": 1}'

# Status and full report
curl -s "$BASE/api/v1/scans/42" -H "Authorization: Bearer $KEY"

# List (filters: domain_id, status; pagination: page, per_page)
curl -s "$BASE/api/v1/scans?domain_id=1&status=completed" -H "Authorization: Bearer $KEY"

# PDF report
curl -s -o report.pdf "$BASE/api/v1/scans/42/report.pdf" -H "Authorization: Bearer $KEY"
```

Scan object: `id`, `domain_id`, `hostname`, `status` (`queued`, `running`, `completed`, `failed`),
`source`, `created_at`, `started_at`, `finished_at`, `grade`, `score`, `error`, and `report` (only on
`GET /scans/{id}`).

### Report format

`report.findings[]` items: `id`, `category`, `title`, `severity` (`critical`…`info`), `status`
(`pass`, `warning`, `fail`, `not_checked`, `not_applicable`), `evidence`, `explanation`,
`recommendation`, `confidence` (`confirmed`, `heuristic`), `detail`.
`report.score`: `percentage`, `grade`, `coverage`, `counts`, `categories`, `critical_failed`,
`high_risk_failed`. `report.limitations[]` describes what the scan does not cover.

## Example: fail a CI pipeline on a bad grade (Python)

```python
import json, os, time, urllib.request

BASE, KEY, DOMAIN_ID = os.environ["SABOSS_URL"], os.environ["SABOSS_API_KEY"], 1


def call(method, path, body=None):
    request = urllib.request.Request(
        BASE + path,
        method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


scan = call("POST", "/api/v1/scans", {"domain_id": DOMAIN_ID})
while scan["status"] in ("queued", "running"):
    time.sleep(3)
    scan = call("GET", f"/api/v1/scans/{scan['id']}")
print(scan["grade"], scan["score"])
raise SystemExit(0 if scan["grade"] in ("A", "B") else 1)
```
