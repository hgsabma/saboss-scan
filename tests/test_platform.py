"""Integration tests for the Saboss web platform (no real network traffic).

Scans use a fake engine, password-reset e-mails are captured, and DNS lookups
for webhooks and domain verification are replaced.
"""

import re
from datetime import timedelta

import pytest
from conftest import build_report
from fastapi.testclient import TestClient
from sqlalchemy import select

from saboss_platform import notifications, routes_account, routes_settings
from saboss_platform.app import create_app
from saboss_platform.config import Settings
from saboss_platform.db import utcnow
from saboss_platform.models import ApiKey, Membership, PasswordResetToken, User, UserSession
from saboss_platform.scan import service
from saboss_platform.scan.models import Alert, Domain, Scan
from saboss_scan.utils import InvalidTargetError

PASSWORD = "correct horse battery staple"


@pytest.fixture
def fake_engine(monkeypatch):
    """Replace the real scanner with a fast, deterministic fake."""
    state = {"headers": {}, "calls": [], "error": None}

    def fake_scan(hostname):
        state["calls"].append(hostname)
        if state["error"]:
            raise state["error"]
        return build_report(domain=hostname, headers=state["headers"])

    monkeypatch.setattr(service, "scan_domain", fake_scan)
    return state


@pytest.fixture
def app(tmp_path, fake_engine):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path.as_posix()}/test.db",
        allowed_hosts=["testserver"],
        scan_executor="inline",
        scheduler_enabled=False,
        base_url="http://testserver",
    )
    return create_app(settings)


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def new_client(app):
    return TestClient(app)


def csrf_from(client, path="/register"):
    page = client.get(path)
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def register(client, email="ada@example.com", name="Ada", organization="Ada Labs", password=PASSWORD):
    token = csrf_from(client, "/register")
    return client.post(
        "/register",
        data={"csrf_token": token, "name": name, "email": email, "password": password, "organization": organization},
        follow_redirects=False,
    )


def post(client, path, data=None, page="/dashboard", **kwargs):
    """POST a form with a valid CSRF token, like a browser would."""
    data = dict(data or {})
    data["csrf_token"] = csrf_from(client, page)
    return client.post(path, data=data, follow_redirects=False, **kwargs)


def add_domain(client, hostname="example.com", scan_now=False):
    data = {"hostname": hostname, "authorized": "1"}
    if scan_now:
        data["scan_now"] = "1"
    return post(client, "/domains", data, page="/domains")


def db(app):
    return app.state.database.session()


# ------------------------------------------------------------ registration


def test_register_creates_owner_and_logs_in(app, client):
    response = register(client)
    assert response.status_code == 303 and response.headers["location"] == "/dashboard"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie

    with db(app) as session:
        user = session.scalar(select(User).where(User.email == "ada@example.com"))
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash
        membership = session.scalar(select(Membership).where(Membership.user_id == user.id))
        assert membership.role == "owner"
    assert client.get("/dashboard").status_code == 200


def test_register_rejects_weak_password_and_duplicates(client):
    assert register(client, password="short").status_code == 400
    assert register(client).status_code == 303
    other = new_client(client.app)
    response = register(other)
    assert response.status_code == 400
    assert "already exists" in response.text


def test_session_token_is_stored_hashed(app, client):
    response = register(client)
    raw_token = re.search(r"saboss_session=([^;]+)", response.headers["set-cookie"]).group(1)
    with db(app) as session:
        stored = session.scalars(select(UserSession.token_hash)).all()
    assert raw_token not in stored and len(stored[0]) == 64


def test_pages_require_login(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"].startswith("/login")


# ------------------------------------------------------------------- CSRF


def test_post_without_csrf_token_is_rejected(client):
    register(client)
    response = client.post("/domains", data={"hostname": "example.com", "authorized": "1"})
    assert response.status_code == 403
    assert "expired" in response.text


def test_post_with_wrong_csrf_token_is_rejected(client):
    register(client)
    response = client.post("/domains", data={"hostname": "example.com", "authorized": "1", "csrf_token": "forged"})
    assert response.status_code == 403


def test_cross_origin_post_is_rejected(client):
    register(client)
    response = post(
        client,
        "/domains",
        {"hostname": "example.com", "authorized": "1"},
        page="/domains",
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403


# ------------------------------------------------------------- login/logout


def test_login_and_logout(app):
    first = new_client(app)
    register(first)
    browser = new_client(app)
    token = csrf_from(browser, "/login")
    wrong = browser.post("/login", data={"csrf_token": token, "email": "ada@example.com", "password": "wrong-password"})
    assert wrong.status_code == 400 and "incorrect" in wrong.text

    unknown = browser.post("/login", data={"csrf_token": token, "email": "nobody@example.com", "password": PASSWORD})
    assert "incorrect" in unknown.text  # same message: no account enumeration

    ok = browser.post(
        "/login", data={"csrf_token": token, "email": "ADA@example.com", "password": PASSWORD}, follow_redirects=False
    )
    assert ok.status_code == 303
    assert browser.get("/dashboard").status_code == 200

    old_cookie = browser.cookies.get("saboss_session")
    assert post(browser, "/logout").status_code == 303
    attacker = new_client(app)
    attacker.cookies.set("saboss_session", old_cookie)
    assert attacker.get("/dashboard", follow_redirects=False).status_code == 303  # session is gone server-side


def test_login_is_rate_limited(app, client):
    register(client)
    browser = new_client(app)
    token = csrf_from(browser, "/login")
    for _ in range(5):
        browser.post("/login", data={"csrf_token": token, "email": "ada@example.com", "password": "nope-nope-nope"})
    blocked = browser.post("/login", data={"csrf_token": token, "email": "ada@example.com", "password": PASSWORD})
    assert blocked.status_code == 429


def test_login_does_not_redirect_to_other_sites(app, client):
    register(client)
    browser = new_client(app)
    token = csrf_from(browser, "/login")
    response = browser.post(
        "/login",
        data={"csrf_token": token, "email": "ada@example.com", "password": PASSWORD, "next": "//evil.example/x"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/dashboard"


def test_expired_session_is_rejected(app, client):
    register(client)
    with db(app) as session:
        for user_session in session.scalars(select(UserSession)):
            user_session.expires_at = utcnow() - timedelta(minutes=1)
        session.commit()
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


# ---------------------------------------------------------- password reset


def test_password_reset_flow(app, client, monkeypatch):
    register(client)
    sent = []
    monkeypatch.setattr(routes_account, "send_email", lambda settings, to, subject, body: sent.append(body) or "sent")
    browser = new_client(app)
    response = post(browser, "/forgot-password", {"email": "ada@example.com"}, page="/forgot-password")
    assert "If an account exists" in response.text
    unknown = post(browser, "/forgot-password", {"email": "nobody@example.com"}, page="/forgot-password")
    assert "If an account exists" in unknown.text and len(sent) == 1

    token = re.search(r"token=([\w-]+)", sent[0]).group(1)
    with db(app) as session:
        assert token not in session.scalars(select(PasswordResetToken.token_hash)).all()

    changed = post(
        browser, "/reset-password", {"token": token, "password": "a brand new passphrase"}, page="/forgot-password"
    )
    assert changed.status_code == 303
    # All sessions ended: the originally logged-in client is signed out.
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    # The token works only once.
    again = post(
        browser, "/reset-password", {"token": token, "password": "another new passphrase"}, page="/forgot-password"
    )
    assert again.status_code == 400


# -------------------------------------------------------- domains and scans


def test_add_domain_requires_authorization_confirmation(app, client):
    register(client)
    response = post(client, "/domains", {"hostname": "example.com"}, page="/domains")
    assert response.status_code == 303
    assert "Confirm that you are authorized" in client.get("/domains").text
    with db(app) as session:
        assert session.scalar(select(Domain)) is None


@pytest.mark.parametrize("target", ["localhost", "127.0.0.1", "169.254.169.254", "intranet.local", "a b.com"])
def test_unsafe_targets_cannot_be_added(app, client, target):
    register(client)
    add_domain(client, target)
    with db(app) as session:
        assert session.scalar(select(Domain)) is None


def test_scan_runs_and_report_is_shown(app, client, fake_engine):
    register(client)
    response = add_domain(client, "example.com", scan_now=True)
    assert response.status_code == 303 and response.headers["location"].startswith("/scans/")
    page = client.get(response.headers["location"])
    assert "Executive summary" in page.text and "Technical findings" in page.text
    assert fake_engine["calls"] == ["example.com"]
    with db(app) as session:
        scan = session.scalar(select(Scan))
        assert scan.status == "completed" and scan.grade and scan.report["domain"] == "example.com"


def test_hostile_values_from_scanned_site_are_escaped(client, fake_engine):
    fake_engine["headers"] = {"x-frame-options": "<script>alert(1)</script>"}
    register(client)
    location = add_domain(client, "example.com", scan_now=True).headers["location"]
    page = client.get(location).text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_failed_scans_show_safe_messages(app, client, fake_engine):
    register(client)
    fake_engine["error"] = InvalidTargetError("'example.com' points to a private or reserved address")
    location = add_domain(client, "example.com", scan_now=True).headers["location"]
    assert "private or reserved" in client.get(location).text

    fake_engine["error"] = RuntimeError("secret internal detail")
    with db(app) as session:
        domain = session.scalar(select(Domain))
    location = post(client, f"/domains/{domain.id}/scan").headers["location"]
    page = client.get(location).text
    assert "internal error" in page and "secret internal detail" not in page


def test_scan_limits(app, client):
    register(client)
    add_domain(client, "example.com")
    with db(app) as session:
        domain = session.scalar(select(Domain))
        session.add(
            Scan(
                organization_id=domain.organization_id, domain_id=domain.id, hostname=domain.hostname, status="running"
            )
        )
        session.commit()
    response = post(client, f"/domains/{domain.id}/scan")
    assert response.headers["location"] == f"/domains/{domain.id}"  # refused: already in progress

    limiter = app.state.limiter
    for _ in range(app.state.settings.scans_per_org_per_hour):
        limiter.hit(f"scan:org:{domain.organization_id}", 10_000, 3600)
    with db(app) as session:
        session.query(Scan).delete()
        session.commit()
    post(client, f"/domains/{domain.id}/scan")
    with db(app) as session:
        assert session.scalar(select(Scan)) is None  # refused: hourly limit


def test_exports(client):
    register(client)
    location = add_domain(client, "example.com", scan_now=True).headers["location"]
    pdf = client.get(f"{location}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert "attachment" in pdf.headers["content-disposition"]
    data = client.get(f"{location}/report.json").json()
    assert data["domain"] == "example.com" and "findings" in data
    html = client.get(f"{location}/report.html")
    assert html.headers["content-security-policy"] == "default-src 'none'; style-src 'unsafe-inline'"


def test_scan_history_filters(client):
    register(client)
    for host in ("alpha.example.com", "beta.example.com"):
        add_domain(client, host, scan_now=True)
    assert "alpha.example.com" in client.get("/scans?q=alpha").text
    assert "beta.example.com" not in client.get("/scans?q=alpha").text
    assert "No scans match" in client.get("/scans?status=failed").text
    assert client.get("/scans?sort=score_asc&page=99").status_code == 200


# ------------------------------------------------- organizations and roles


def test_organizations_are_isolated(app, client):
    register(client)
    location = add_domain(client, "example.com", scan_now=True).headers["location"]
    with db(app) as session:
        domain = session.scalar(select(Domain))
    other = new_client(app)
    register(other, email="eve@example.com", name="Eve", organization="Eve Corp")
    assert other.get(f"/domains/{domain.id}").status_code == 404
    assert other.get(location).status_code == 404
    assert other.get(f"{location}/report.pdf").status_code == 404
    assert post(other, f"/domains/{domain.id}/delete").status_code == 404
    assert "No scans yet" in other.get("/scans").text


def _add_member(app, owner_client, email, role):
    member = new_client(app)
    register(member, email=email, name=email.split("@")[0])
    post(owner_client, "/settings/members", {"email": email, "role": role}, page="/settings/organization")
    with db(app) as session:
        user = session.scalar(select(User).where(User.email == email))
        owner_org = session.scalar(select(Membership).where(Membership.role == "owner")).organization_id
        membership = session.scalar(
            select(Membership).where(Membership.user_id == user.id, Membership.organization_id == owner_org)
        )
        session_row = session.scalar(select(UserSession).where(UserSession.user_id == user.id))
        session_row.organization_id = owner_org
        session.commit()
    return member, membership


def test_roles_are_enforced(app, client):
    register(client)
    add_domain(client, "example.com")
    with db(app) as session:
        domain = session.scalar(select(Domain))

    viewer, _ = _add_member(app, client, "viewer@example.com", "viewer")
    assert add_domain(viewer, "viewer.example.com").status_code == 403
    assert post(viewer, f"/domains/{domain.id}/scan").status_code == 403
    assert viewer.get("/settings/api-keys").status_code == 403
    assert viewer.get(f"/domains/{domain.id}").status_code == 200  # viewers can read

    member, _ = _add_member(app, client, "member@example.com", "member")
    assert post(member, f"/domains/{domain.id}/scan").status_code == 303
    assert post(member, f"/domains/{domain.id}/delete").status_code == 403
    assert post(client, f"/domains/{domain.id}/delete").status_code == 303  # owner can


def test_last_owner_cannot_be_demoted_and_admins_cannot_create_admins(app, client):
    register(client)
    with db(app) as session:
        owner_membership = session.scalar(select(Membership))
    post(client, f"/settings/members/{owner_membership.id}/role", {"role": "member"}, page="/settings/organization")
    with db(app) as session:
        assert session.get(Membership, owner_membership.id).role == "owner"

    admin, admin_membership = _add_member(app, client, "admin@example.com", "admin")
    member_client, member_membership = _add_member(app, client, "member@example.com", "member")
    post(admin, f"/settings/members/{member_membership.id}/role", {"role": "admin"}, page="/settings/organization")
    with db(app) as session:
        assert session.get(Membership, member_membership.id).role == "member"


def test_audit_log_records_actions(client):
    register(client)
    add_domain(client, "example.com")
    page = client.get("/settings/audit").text
    for action in ("user.register", "domain.created"):
        assert action in page


# ---------------------------------------------------------------------- API


def create_api_key(client, role="member"):
    page = post(client, "/settings/api-keys", {"name": "ci", "role": role}, page="/settings/api-keys")
    return re.search(r"<code>(sbk_[\w-]+)</code>", page.text).group(1)


def test_api_requires_a_key(client):
    response = client.get("/api/v1/domains")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    bad = client.get("/api/v1/domains", headers={"Authorization": "Bearer sbk_wrong"})
    assert bad.status_code == 401


def test_api_full_flow(app, client):
    register(client)
    key = create_api_key(client)
    with db(app) as session:
        assert key not in session.scalars(select(ApiKey.key_hash)).all()
    api = new_client(app)
    headers = {"Authorization": f"Bearer {key}"}

    refused = api.post("/api/v1/domains", json={"hostname": "example.com", "authorized": False}, headers=headers)
    assert refused.status_code == 422
    created = api.post("/api/v1/domains", json={"hostname": "Example.COM", "authorized": True}, headers=headers)
    assert created.status_code == 201 and created.json()["hostname"] == "example.com"
    duplicate = api.post("/api/v1/domains", json={"hostname": "example.com", "authorized": True}, headers=headers)
    assert duplicate.status_code == 409 and duplicate.json()["error"]["code"] == "conflict"

    scan = api.post("/api/v1/scans", json={"domain_id": created.json()["id"]}, headers=headers)
    assert scan.status_code == 202
    result = api.get(f"/api/v1/scans/{scan.json()['id']}", headers=headers).json()
    assert result["status"] == "completed" and result["report"]["domain"] == "example.com"

    listing = api.get("/api/v1/scans?per_page=1", headers=headers).json()
    assert listing["pagination"] == {"page": 1, "per_page": 1, "total": 1}
    pdf = api.get(f"/api/v1/scans/{scan.json()['id']}/report.pdf", headers=headers)
    assert pdf.content.startswith(b"%PDF")


def test_api_validation_errors_do_not_echo_input(app, client):
    register(client)
    key = create_api_key(client)
    response = new_client(app).post(
        "/api/v1/scans", json={"domain_id": "<script>"}, headers={"Authorization": f"Bearer {key}"}
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error" and "<script>" not in response.text


def test_read_only_and_revoked_keys(app, client):
    register(client)
    viewer_key = create_api_key(client, role="viewer")
    api = new_client(app)
    headers = {"Authorization": f"Bearer {viewer_key}"}
    assert api.get("/api/v1/domains", headers=headers).status_code == 200
    forbidden = api.post("/api/v1/domains", json={"hostname": "example.com", "authorized": True}, headers=headers)
    assert forbidden.status_code == 403

    with db(app) as session:
        key_id = session.scalar(select(ApiKey.id))
    post(client, f"/settings/api-keys/{key_id}/revoke", page="/settings/api-keys")
    assert api.get("/api/v1/domains", headers=headers).status_code == 401


def test_api_keys_cannot_reach_other_organizations(app, client):
    register(client)
    add_domain(client, "example.com")
    with db(app) as session:
        domain_id = session.scalar(select(Domain.id))
    other = new_client(app)
    register(other, email="eve@example.com", name="Eve")
    key = create_api_key(other)
    headers = {"Authorization": f"Bearer {key}"}
    assert other.get(f"/api/v1/domains/{domain_id}", headers=headers).status_code == 404
    assert other.post("/api/v1/scans", json={"domain_id": domain_id}, headers=headers).status_code == 404


# --------------------------------------------------------------- monitoring


def test_monitoring_requires_verified_ownership(app, client, monkeypatch):
    register(client)
    add_domain(client, "example.com")
    with db(app) as session:
        domain = session.scalar(select(Domain))
    post(client, f"/domains/{domain.id}/monitoring", {"enabled": "1", "interval": "24"})
    with db(app) as session:
        assert session.get(Domain, domain.id).monitor_enabled is False

    monkeypatch.setattr(service, "_safe_resolve", lambda name, rtype: ([], None))
    post(client, f"/domains/{domain.id}/verify")
    with db(app) as session:
        assert session.get(Domain, domain.id).verified_at is None

    expected = f"saboss-verify={domain.verification_token}"
    monkeypatch.setattr(service, "_safe_resolve", lambda name, rtype: ([expected], None))
    post(client, f"/domains/{domain.id}/verify")
    post(client, f"/domains/{domain.id}/monitoring", {"enabled": "1", "interval": "168"})
    with db(app) as session:
        refreshed = session.get(Domain, domain.id)
        assert refreshed.verified_at is not None
        assert refreshed.monitor_enabled is True and refreshed.monitor_interval_hours == 168


def test_scheduled_scan_detects_changes_and_alerts(app, client, fake_engine, monkeypatch):
    register(client)
    fake_engine["headers"] = {"referrer-policy": "strict-origin-when-cross-origin"}
    add_domain(client, "example.com", scan_now=True)  # first scan: baseline with a good referrer policy
    with db(app) as session:
        domain = session.scalar(select(Domain))
        domain.verified_at = utcnow()
        domain.monitor_enabled = True
        domain.next_scan_at = utcnow() - timedelta(minutes=1)
        session.commit()

    deliveries = []
    monkeypatch.setattr(service, "send_webhook", lambda url, payload: deliveries.append(payload) or "webhook ok")
    # Something gets worse on the site: the referrer policy becomes unsafe.
    fake_engine["headers"] = {"referrer-policy": "unsafe-url"}

    scan_ids = app.state.worker.run_scheduler_once()
    assert len(scan_ids) == 1
    with db(app) as session:
        scan = session.get(Scan, scan_ids[0])
        assert scan.source == "schedule" and scan.status == "completed"
        alert = session.scalar(select(Alert))
        domain = session.get(Domain, domain.id)
        assert domain.next_scan_at > utcnow()
    assert alert is not None and "Referrer-Policy" in alert.message
    assert "e-mail not configured" in alert.delivery and deliveries[0]["event"] == "scan.alert"
    assert "Security changes detected" in client.get("/alerts").text

    # Nothing is due right after a scan.
    assert app.state.worker.run_scheduler_once() == []


def test_compare_reports():
    before = build_report(headers={"x-content-type-options": "nosniff"})
    after = build_report(headers={})
    comparison = service.compare_reports(before, after)
    assert [issue["id"] for issue in comparison.new_issues] == ["headers.nosniff"]
    reverse = service.compare_reports(after, before)
    assert [issue["id"] for issue in reverse.resolved] == ["headers.nosniff"]
    assert service.compare_reports(before, before).has_changes is False


def test_interrupted_scans_are_recovered(app):
    with db(app) as session:
        from saboss_platform.models import Organization

        org = Organization(name="x")
        session.add(org)
        session.flush()
        domain = Domain(organization_id=org.id, hostname="example.com", verification_token="t")
        session.add(domain)
        session.flush()
        running = Scan(organization_id=org.id, domain_id=domain.id, hostname="example.com", status="running")
        queued = Scan(organization_id=org.id, domain_id=domain.id, hostname="example.com", status="queued")
        session.add_all([running, queued])
        session.commit()
        assert service.recover_interrupted_scans(session) == [queued.id]
        assert session.get(Scan, running.id).status == "failed"


# --------------------------------------------------------- notifications


def test_webhook_settings_reject_unsafe_urls(app, client, monkeypatch):
    register(client)
    for url in ("http://hooks.example.com/x", "https://127.0.0.1/x", "https://localhost/x"):
        response = post(client, "/settings/notifications", {"webhook_url": url}, page="/settings/notifications")
        assert response.status_code == 303
    with db(app) as session:
        from saboss_platform.models import Organization

        assert session.scalar(select(Organization)).webhook_url is None

    monkeypatch.setattr(routes_settings, "resolve_public_ip", lambda host: "203.0.113.10")
    post(
        client,
        "/settings/notifications",
        {"webhook_url": "https://hooks.example.com/x"},
        page="/settings/notifications",
    )
    with db(app) as session:
        from saboss_platform.models import Organization

        assert session.scalar(select(Organization)).webhook_url == "https://hooks.example.com/x"


def test_email_is_not_sent_when_not_configured():
    assert notifications.send_email(Settings(), ["a@example.com"], "s", "b") == "e-mail not configured"


def test_webhook_requires_configuration():
    assert notifications.send_webhook(None, {}) == "webhook not configured"


# ------------------------------------------------------ headers and health


def test_security_headers_on_pages(client):
    response = client.get("/login")
    headers = response.headers
    assert "script-src 'self'" in headers["content-security-policy"]
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert "x-request-id" in headers


def test_unknown_host_header_is_rejected(app):
    assert TestClient(app, base_url="http://evil.example").get("/healthz").status_code == 400


def test_health_endpoints(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json()["status"] == "ready"


def test_not_found_page_is_html(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404 and "Page not found" in response.text


def test_scan_grade_filter_is_remembered(client):
    register(client)
    add_domain(client, "example.com", scan_now=True)
    page = client.get("/scans?grade=E").text
    assert '<option value="E" selected>' in page
    assert '<option value="A" selected>' not in page
