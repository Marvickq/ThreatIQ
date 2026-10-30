"""Settings sections: persistence, server-side permissions, tenant isolation and failure cases.

Goes through the real HTTP stack with real sessions and CSRF tokens; nothing about authentication is bypassed.
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

PASSWORD = "correct-horse-battery"


@pytest.fixture(scope="module")
def _lifespan():
    with TestClient(app):  # runs migrations / starts workers once for this module
        yield


def _email(tag):
    return f"{tag}-{uuid.uuid4().hex[:8]}@example.com"


def _csrf(c):
    c.headers["X-CSRF-Token"] = c.cookies.get("tiq_csrf")
    return c


def signup(tag="owner", org="Org"):
    c = TestClient(app)
    email = _email(tag)
    r = c.post("/api/v1/auth/register", json={"email": email, "password": PASSWORD, "display_name": tag.title(), "organization_name": f"{org} {uuid.uuid4().hex[:4]}"})
    assert r.status_code == 201, r.text
    c.me, c.email = r.json(), email
    return _csrf(c)


def login(email):
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.me = r.json()
    return _csrf(c)


def member_of(owner, role):
    """A second account added to the owner's organization with `role`, signed in with that organization active."""
    other = signup(role, "Own")
    assert owner.post("/api/v1/organization/members", json={"email": other.email, "role": role}).status_code == 201
    other.post("/api/v1/auth/switch-organization", json={"organization_id": owner.me["organization"]["id"]})
    _csrf(other)
    assert other.get("/api/v1/auth/me").json()["role"] == role
    return other


@pytest.fixture
def owner(_lifespan):
    return signup("owner")


# ------------------------------------------------------------------------------ 1. profile & notifications
def test_profile_changes_persist_and_can_be_cleared(owner):
    r = owner.patch("/api/v1/auth/me", json={"display_name": "New Name", "locale": "de", "timezone": "Asia/Kolkata"})
    assert r.status_code == 200
    u = owner.get("/api/v1/auth/me").json()["user"]
    assert (u["display_name"], u["locale"], u["timezone"]) == ("New Name", "de", "Asia/Kolkata")
    u = owner.patch("/api/v1/auth/me", json={"locale": None, "timezone": None}).json()["user"]
    assert u["locale"] is None and u["timezone"] is None and u["display_name"] == "New Name"


@pytest.mark.parametrize("body", [{"timezone": "Mars/Phobos"}, {"timezone": "../../etc/passwd"}, {"locale": "not a locale!"}, {"display_name": ""}])
def test_profile_validation_rejects_bad_input(owner, body):
    assert owner.patch("/api/v1/auth/me", json=body).status_code == 422


def test_notification_preferences_persist_exactly(owner):
    prefs = {"in_app": False, "on_job_failure": False, "min_severity": "critical", "on_assignment": False}
    assert owner.patch("/api/v1/auth/me", json={"notification_prefs": prefs}).json()["user"]["notification_prefs"] == prefs
    assert owner.get("/api/v1/auth/me").json()["user"]["notification_prefs"] == prefs
    assert owner.patch("/api/v1/auth/me", json={"notification_prefs": {"min_severity": "urgent"}}).status_code == 422


def test_profile_requires_authentication_and_csrf(owner):
    assert TestClient(app).get("/api/v1/auth/me").status_code == 401
    assert TestClient(app).patch("/api/v1/auth/me", json={"display_name": "x"}).status_code == 401
    bad = TestClient(app, cookies=owner.cookies)
    assert bad.patch("/api/v1/auth/me", json={"display_name": "x"}, headers={"X-CSRF-Token": "wrong"}).status_code == 403


# ------------------------------------------------------------------------------ 2. security
def test_security_policy_is_real_and_exposes_no_secrets(owner):
    me = owner.get("/api/v1/auth/me")
    sec = me.json()["security"]
    assert sec["password_min_length"] == 10 and sec["sso_user"] is False
    assert "password_hash" not in me.text


def test_sessions_list_and_revocation(owner):
    second = login(owner.email)
    sessions = owner.get("/api/v1/auth/sessions").json()
    assert len(sessions) >= 2 and sum(s["current"] for s in sessions) == 1
    assert all(set(s) == {"id", "created_at", "last_seen_at", "expires_at", "ip", "user_agent", "current"} for s in sessions)  # no tokens
    other = next(s for s in sessions if not s["current"])
    assert owner.delete(f"/api/v1/auth/sessions/{other['id']}").status_code in (200, 204)
    assert second.get("/api/v1/auth/me").status_code == 401  # revoked server-side, not just hidden


def test_password_change_rules(owner):
    assert owner.post("/api/v1/auth/change-password", json={"current_password": "wrong-wrong-wrong", "new_password": "another-long-password"}).status_code in (400, 401, 403, 422)
    assert owner.post("/api/v1/auth/change-password", json={"current_password": PASSWORD, "new_password": "short"}).status_code == 422
    r = owner.post("/api/v1/auth/change-password", json={"current_password": PASSWORD, "new_password": "another-long-password"})
    assert r.status_code in (200, 204)
    assert TestClient(app).post("/api/v1/auth/login", json={"email": owner.email, "password": PASSWORD}).status_code == 401
    assert TestClient(app).post("/api/v1/auth/login", json={"email": owner.email, "password": "another-long-password"}).status_code == 200


# ------------------------------------------------------------------------------ 3. organization
def test_organization_update_persists_and_hides_internal_fields(owner):
    r = owner.patch("/api/v1/organization", json={"name": "Renamed Org", "retention_days": 90, "default_timezone": "Europe/London"})
    assert r.status_code == 200
    org = owner.get("/api/v1/organization").json()
    assert (org["name"], org["retention_days"], org["default_timezone"]) == ("Renamed Org", 90, "Europe/London")
    assert org["id"] == owner.me["organization"]["id"]
    assert not ({"entra_tenant_id", "password_hash"} & set(org))
    assert owner.patch("/api/v1/organization", json={"default_timezone": "Nope/Zone"}).status_code == 422
    assert owner.patch("/api/v1/organization", json={"retention_days": -1}).status_code == 422


def test_organization_edit_is_admin_only_and_tenant_scoped(owner):
    for role in ("viewer", "analyst"):
        assert member_of(owner, role).patch("/api/v1/organization", json={"name": "Hacked"}).status_code == 403
    stranger = signup("stranger")
    owner.patch("/api/v1/organization", json={"name": "Mine"})
    assert stranger.get("/api/v1/organization").json()["id"] == stranger.me["organization"]["id"]
    assert stranger.get("/api/v1/organization").json()["name"] != "Mine"


# ------------------------------------------------------------------------------ 4. members
def test_member_lifecycle_and_validation(owner):
    newbie = signup("newbie")
    r = owner.post("/api/v1/organization/members", json={"email": newbie.email, "role": "analyst"})
    assert r.status_code == 201 and r.json()["role"] == "analyst"
    assert owner.post("/api/v1/organization/members", json={"email": newbie.email, "role": "viewer"}).status_code == 409  # duplicate
    assert owner.post("/api/v1/organization/members", json={"email": _email("ghost"), "role": "viewer"}).status_code == 404  # no invitations
    assert owner.post("/api/v1/organization/members", json={"email": newbie.email, "role": "superuser"}).status_code == 422
    uid = r.json()["user_id"]
    assert owner.patch(f"/api/v1/organization/members/{uid}", json={"role": "viewer"}).json()["role"] == "viewer"
    assert next(m for m in owner.get("/api/v1/organization/members").json() if m["user_id"] == uid)["role"] == "viewer"
    assert owner.delete(f"/api/v1/organization/members/{uid}").status_code == 204
    assert uid not in {m["user_id"] for m in owner.get("/api/v1/organization/members").json()}


def test_member_management_is_forbidden_below_admin_and_cannot_escalate(owner):
    assert member_of(owner, "analyst").get("/api/v1/organization/members").status_code == 403
    admin = member_of(owner, "admin")
    target = signup("target")
    assert admin.post("/api/v1/organization/members", json={"email": target.email, "role": "owner"}).status_code == 403  # no granting owner
    assert admin.post("/api/v1/organization/members", json={"email": target.email, "role": "viewer"}).status_code == 201
    owner_id = owner.me["user"]["id"]
    assert admin.patch(f"/api/v1/organization/members/{owner_id}", json={"role": "viewer"}).status_code == 403  # no demoting owners
    assert admin.delete(f"/api/v1/organization/members/{owner_id}").status_code == 403


def test_last_owner_is_protected_and_removal_revokes_access(owner):
    me = owner.me["user"]["id"]
    assert owner.patch(f"/api/v1/organization/members/{me}", json={"role": "admin"}).status_code == 409
    assert owner.delete(f"/api/v1/organization/members/{me}").status_code == 409
    viewer = member_of(owner, "viewer")
    owner.delete(f"/api/v1/organization/members/{viewer.me['user']['id']}")
    assert viewer.get("/api/v1/alerts").status_code in (401, 403)  # membership is re-read on every request


# ------------------------------------------------------------------------------ 5. integrations
@pytest.fixture
def public_dns(monkeypatch):
    """Resolve one fake hostname to a public address so the real SSRF validation runs without needing live DNS."""
    import socket

    real = socket.getaddrinfo

    def fake(host, *a, **k):
        if host == "wazuh.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 9200))]
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


def test_integration_status_is_honest_and_secrets_never_returned(owner, public_dns):
    hook = owner.post("/api/v1/integrations", json={"kind": "webhook", "name": "hook", "config": {}, "credentials": {}})
    assert hook.status_code == 201 and hook.json()["status"] == "awaiting_events"
    wz = owner.post("/api/v1/integrations", json={"kind": "wazuh", "name": "wz", "config": {"endpoint": "https://wazuh.example.com:9200"}, "credentials": {"username": "svc", "password": "s3cret-value"}})
    assert wz.status_code == 201
    body = wz.json()
    assert body["status"] == "never_synced" and body["has_credentials"] is True  # saved credentials are not "connected"
    assert "s3cret-value" not in wz.text and "s3cret-value" not in owner.get("/api/v1/integrations").text
    assert "password" not in str(body["config"]).lower()


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1:9200", "http://169.254.169.254/latest", "http://localhost:9200", "file:///etc/passwd"])
def test_integration_endpoints_pass_ssrf_protection(owner, endpoint):
    r = owner.post("/api/v1/integrations", json={"kind": "wazuh", "name": f"bad-{uuid.uuid4().hex[:4]}", "config": {"endpoint": endpoint}, "credentials": {"username": "u", "password": "p"}})
    assert r.status_code in (400, 422), r.text


def test_integration_management_is_admin_only(owner):
    for role in ("viewer", "analyst"):
        assert member_of(owner, role).get("/api/v1/integrations").status_code == 403


# ------------------------------------------------------------------------------ 6. API keys
def test_api_key_lifecycle_masking_scopes_and_audit(owner):
    created = owner.post("/api/v1/api-keys", json={"name": "ci", "scopes": ["alerts:read"], "expires_in_days": 30})
    assert created.status_code == 201
    secret, kid = created.json()["key"], created.json()["id"]
    listing = owner.get("/api/v1/api-keys")
    assert secret not in listing.text and all("key" not in k and "key_hash" not in k for k in listing.json())  # shown exactly once
    assert owner.get("/api/v1/api-keys").json()[0]["prefix"] in secret
    bearer = {"Authorization": f"Bearer {secret}"}
    assert TestClient(app).get("/api/v1/alerts", headers=bearer).status_code == 200
    event = {"source": "s", "external_id": "1", "title": "t", "severity": "low"}
    assert TestClient(app).post("/api/v1/ingest/webhook", headers=bearer, json=event).status_code in (401, 403)  # scope enforced
    assert owner.delete(f"/api/v1/api-keys/{kid}").json()["revoked_at"] is not None
    assert TestClient(app).get("/api/v1/alerts", headers=bearer).status_code == 401
    types = {e["event_type"] for e in owner.get("/api/v1/audit-events?limit=200").json()["items"]}
    assert {"api_key_created", "api_key_revoked"} <= types


def test_api_key_rotation_replaces_key_and_is_audited(owner):
    created = owner.post("/api/v1/api-keys", json={"name": "rot", "scopes": ["alerts:read"], "expires_in_days": 30}).json()
    old_bearer = {"Authorization": f"Bearer {created['key']}"}
    assert TestClient(app).get("/api/v1/alerts", headers=old_bearer).status_code == 200
    r = owner.post(f"/api/v1/api-keys/{created['id']}/rotate")
    assert r.status_code == 201
    new = r.json()
    assert new["id"] != created["id"] and new["key"] != created["key"] and new["name"] == "rot"
    assert new["scopes"] == ["alerts:read"] and new["expires_at"] is not None
    assert TestClient(app).get("/api/v1/alerts", headers=old_bearer).status_code == 401  # old key dead immediately
    assert TestClient(app).get("/api/v1/alerts", headers={"Authorization": f"Bearer {new['key']}"}).status_code == 200
    listing = owner.get("/api/v1/api-keys")
    assert new["key"] not in listing.text and created["key"] not in listing.text
    assert owner.post(f"/api/v1/api-keys/{created['id']}/rotate").status_code == 409  # revoked keys cannot be rotated
    events = owner.get("/api/v1/audit-events?event_type=api_key_rotated").json()["items"]
    assert events and new["key"] not in str(events)


def test_api_key_rotation_permissions_and_isolation(owner):
    kid = owner.post("/api/v1/api-keys", json={"name": "mine", "scopes": ["alerts:read"], "expires_in_days": 5}).json()["id"]
    assert signup("other").post(f"/api/v1/api-keys/{kid}/rotate").status_code == 404
    assert member_of(owner, "analyst").post(f"/api/v1/api-keys/{kid}/rotate").status_code == 403
    assert TestClient(app).post(f"/api/v1/api-keys/{kid}/rotate").status_code in (401, 403)
    assert owner.post("/api/v1/api-keys/does-not-exist/rotate").status_code == 404


def test_api_key_validation_and_permissions(owner):
    assert owner.post("/api/v1/api-keys", json={"name": "x", "scopes": ["admin:everything"], "expires_in_days": 30}).status_code == 422
    assert owner.post("/api/v1/api-keys", json={"name": "x", "scopes": [], "expires_in_days": 30}).status_code == 422
    assert owner.post("/api/v1/api-keys", json={"name": "x", "scopes": ["alerts:read"], "expires_in_days": 99999}).status_code == 422
    for role in ("viewer", "analyst"):
        c = member_of(owner, role)
        assert c.get("/api/v1/api-keys").status_code == 403
        assert c.post("/api/v1/api-keys", json={"name": "x", "scopes": ["alerts:read"], "expires_in_days": 1}).status_code == 403
    other = signup("other")
    kid = owner.post("/api/v1/api-keys", json={"name": "mine", "scopes": ["alerts:read"], "expires_in_days": 5}).json()["id"]
    assert other.delete(f"/api/v1/api-keys/{kid}").status_code == 404  # another tenant cannot revoke it


# ------------------------------------------------------------------------------ 7. audit log
def test_audit_log_is_scoped_filterable_paginated_and_read_only(owner):
    owner.post("/api/v1/api-keys", json={"name": "k", "scopes": ["alerts:read"], "expires_in_days": 5})
    owner.patch("/api/v1/organization", json={"name": "Audit Org"})
    log = owner.get("/api/v1/audit-events?limit=200").json()
    assert {"api_key_created", "organization_updated"} <= set(log["event_types"]) or "api_key_created" in log["event_types"]
    assert all(set(e) >= {"id", "event_type", "actor_type", "actor_name", "created_at", "details"} for e in log["items"])
    assert any(e["actor_name"] == "Owner" for e in log["items"] if e["actor_type"] == "human")
    only = owner.get("/api/v1/audit-events?event_type=api_key_created").json()
    assert only["items"] and all(e["event_type"] == "api_key_created" for e in only["items"])
    page = owner.get("/api/v1/audit-events?limit=1&offset=1").json()
    assert len(page["items"]) <= 1 and page["total"] == log["total"]
    assert owner.get("/api/v1/audit-events?since=2999-01-01T00:00:00Z").json()["total"] == 0
    assert owner.get("/api/v1/audit-events?until=2000-01-01T00:00:00Z").json()["total"] == 0
    assert owner.get("/api/v1/audit-events?since=2000-01-01").json()["total"] == log["total"]
    assert owner.get("/api/v1/audit-events?limit=0").status_code == 422


def test_audit_log_cannot_be_modified_and_is_tenant_isolated(owner):
    first = owner.get("/api/v1/audit-events").json()["items"][0]
    for method in ("post", "put", "patch", "delete"):
        for path in ("/api/v1/audit-events", f"/api/v1/audit-events/{first['id']}"):
            assert getattr(owner, method)(path).status_code in (404, 405)
    stranger = signup("stranger")
    assert first["id"] not in {e["id"] for e in stranger.get("/api/v1/audit-events?limit=200").json()["items"]}
    for role in ("viewer", "analyst"):
        assert member_of(owner, role).get("/api/v1/audit-events").status_code == 403


# ------------------------------------------------------------------------------ 8. system
def test_system_status_is_real_restricted_and_leaks_nothing(owner):
    s = owner.get("/api/v1/system/status")
    assert s.status_code == 200
    body = s.json()
    assert body["database"]["reachable"] is True and body["database"]["up_to_date"] is True
    assert body["database"]["revision"] == body["database"]["head"]
    text = s.text.lower()
    for needle in ("password", "secret", "sqlite:///", "postgresql://", "api_key\":", "sk-", "traceback"):
        assert needle not in text
    for role in ("viewer", "analyst"):
        assert member_of(owner, role).get("/api/v1/system/status").status_code == 403
    assert TestClient(app).get("/api/v1/system/status").status_code == 401
    assert TestClient(app).get("/api/v1/health").json() == {"status": "ok"}
