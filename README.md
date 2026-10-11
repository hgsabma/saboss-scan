# Saboss Scan

[![Tests](https://github.com/hgsabma/saboss-scan/actions/workflows/tests.yml/badge.svg)](https://github.com/hgsabma/saboss-scan/actions/workflows/tests.yml)

Saboss Scan is a passive security check for websites and domains, built by Saboss Technologies.
It looks at publicly visible configuration and explains, in plain language, what to improve.

> Only scan domains you own or have explicit permission to assess.

## What it checks

| Category | Checks |
|---|---|
| HTTPS / TLS | HTTPS available, trusted certificate, certificate expiry, http:// → https:// redirect |
| HTTP security headers | HSTS (incl. max-age), Content-Security-Policy (incl. unsafe scripts), clickjacking protection, `nosniff`, Referrer-Policy, Permissions-Policy |
| DNS | Domain resolves, IPv6 available |
| E-mail security | SPF (incl. `+all`, multiple records), DMARC policy (`none`/`quarantine`/`reject`), DKIM (common selectors only) |

All checks are ordinary requests that any browser or mail server would make. Nothing is attacked or brute-forced.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
```

Activate the virtual environment:

- Windows PowerShell: `.venv\Scripts\Activate.ps1`
- macOS/Linux: `source .venv/bin/activate`

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py example.com
```

Save the full report as JSON:

```bash
python main.py example.com --json report.json
```

Invalid or unsafe targets are rejected with exit code `2`:

- IP addresses, `localhost` and internal names such as `.local`/`.internal`
- URLs with passwords or custom ports
- Domains that resolve to private, loopback or cloud-metadata addresses (for example `localtest.me` → `127.0.0.1`)

Redirects are followed one hop at a time (at most 5), and every hop is checked the same way.

## How the score works

Every check produces a **finding** with a fixed severity and an outcome.

| Severity | Points |   | Outcome | Credit |
|---|---|---|---|---|
| high | 10 |   | pass | 100% |
| medium | 5 |   | warning | 50% |
| low | 2 |   | fail | 0% |
| info | 0 (shown, not scored) |   | not checked | left out of the score |

- **Score** = earned points ÷ possible points.
- **Grades:** A ≥ 85%, B ≥ 70%, C ≥ 55%, D ≥ 40%, otherwise E.
- A failed **high**-severity check (for example no HTTPS or an untrusted certificate) caps the grade at **D**.
- If a check could not run (for example a timeout), it is shown as `N/A` and not counted against the site.
  The report always shows how many checks were completed.

## Scope and limitations

- This is an external check of public configuration. It does not test application code,
  login pages, servers or internal networks.
- **A high score does not mean a website is secure.** It means the checked settings follow common best practices.
- Only the homepage over HTTPS is checked; other pages may send different headers.
- DKIM can only be found when a common selector name is used.

## Development

Install the development tools and run the tests (they make no network requests):

```bash
pip install -r requirements-dev.txt
```

```bash
python -m pytest
```

GitHub Actions runs the same tests on Python 3.10–3.13 for every push to `main` and every pull request.

Project layout:

```text
main.py                     command-line interface
saboss_scan/
  scanner.py                runs all checks and builds the report
  utils.py                  input validation (which targets are allowed)
  network_safety.py         blocks private/internal IP addresses
  ssl_checker.py            TLS handshake and certificate details
  headers_checker.py        HTTP security headers and http→https redirect
  dns_checker.py            DNS, SPF, DMARC and DKIM lookups
  findings.py               turns raw results into findings (the rules)
  scoring.py                Saboss Security Score
  recommendations.py        prioritized advice
tests/                      automated tests
```

## Project status

Version 0.2.0. Early MVP, command-line only, not production-ready.

**Done**
- Input validation that rejects IPs, local/reserved names, credentials and custom ports.
- Findings with severity and pass/warning/fail/not-checked outcomes.
- Transparent, documented scoring; failed checks no longer confused with checks that could not run.
- Fixed: missing DMARC records were treated as DNS errors; long TXT records were split; `www.` was stripped.
- Domains resolving to private addresses are blocked; redirects are validated hop by hop.
- Continuous integration with GitHub Actions; dependencies upgraded (requests 2.32.5, dnspython 2.8.0).

**Known issues / next steps**
- DNS rebinding: the safety check and the actual connection resolve the name separately.
  Connections must be pinned to the checked IP address before a public web version.
- HTML reports, translations and a web interface are planned later.
