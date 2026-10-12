# Roadmap

Prioritized remaining work. "Now" items should be done before inviting real customers.

## Now (before real users)

1. **Deploy a private staging environment** behind HTTPS with PostgreSQL; run the Docker image and
   migrations against real PostgreSQL (not yet exercised).
2. **E-mail delivery** (SMTP provider) so password resets and alerts work; add e-mail verification
   at registration.
3. **Require DNS ownership verification for all scans** on an open-registration installation
   (today one-off scans rely on an authorization attestation).
4. **Multi-factor authentication** (TOTP) for accounts, at least for owners and admins.
5. **External security review / penetration test** of the platform.
6. **Privacy policy, terms of service and data retention** (how long scans, logs and audit entries
   are kept; account deletion and data export).

## Next

- Redis-backed rate limiting and job queue (RQ/Celery) to run several instances.
- E-mail invitations for team members (today members must register first).
- Scan more than the homepage (a few key URLs per domain), TLS protocol/cipher details, DNSSEC,
  CAA records, MTA-STS, `security.txt`.
- Alert digest e-mails and Slack/Teams formatting for webhooks.
- Billing (Stripe) with plan limits once pricing is validated with customers.
- Internationalization of the interface (English first; Swedish next).

## Later

- Single sign-on (SAML/OIDC) for business customers.
- Public status badges and shareable report links with expiry.
- Trust Center pages for Saboss Technologies.
- Shared account across future Saboss products, when a second product exists.

## Known technical debt

- In-process scan worker and rate limiter (fine for one instance).
- The Starlette test client still uses `httpx` (deprecation warning filtered in `pytest.ini`).
- Scan reports are stored as JSON documents; cross-scan analytics would need normalized tables.
