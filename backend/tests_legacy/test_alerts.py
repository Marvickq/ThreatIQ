from sqlalchemy import text
from sqlmodel import Session

from app.database import engine


def test_health(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_list_alerts_returns_seeded_data(client):
    body = client.get("/api/v1/alerts").json()
    assert body["total"] == 12
    assert len(body["items"]) == 12
    # Newest first.
    dates = [item["created_at"] for item in body["items"]]
    assert dates == sorted(dates, reverse=True)


def test_filter_by_severity(client):
    body = client.get("/api/v1/alerts", params={"severity": "critical"}).json()
    assert body["total"] == 2
    assert {item["severity"] for item in body["items"]} == {"critical"}


def test_filter_by_status(client):
    assert client.get("/api/v1/alerts", params={"status": "new"}).json()["total"] == 12
    assert client.get("/api/v1/alerts", params={"status": "resolved"}).json()["total"] == 0


def test_search_matches_title_and_id(client):
    by_title = client.get("/api/v1/alerts", params={"q": "password spray"}).json()
    assert [item["id"] for item in by_title["items"]] == ["ALT-004"]
    by_id = client.get("/api/v1/alerts", params={"q": "alt-010"}).json()
    assert [item["id"] for item in by_id["items"]] == ["ALT-010"]


def test_filters_combine(client):
    body = client.get(
        "/api/v1/alerts", params={"severity": "high", "q": "login"}
    ).json()
    assert all(item["severity"] == "high" for item in body["items"])


def test_invalid_filter_value_is_rejected(client):
    assert client.get("/api/v1/alerts", params={"severity": "bogus"}).status_code == 422


def test_pagination(client):
    body = client.get("/api/v1/alerts", params={"limit": 5, "offset": 10}).json()
    assert body["total"] == 12
    assert len(body["items"]) == 2


def test_get_alert_detail(client):
    body = client.get("/api/v1/alerts/ALT-002").json()
    assert body["id"] == "ALT-002"
    assert body["is_demo"] is True
    assert body["severity"] == "critical"
    assert "SYNTHETIC" in body["description"]


def test_unknown_alert_returns_404_with_error_body(client):
    response = client.get("/api/v1/alerts/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ALERT_NOT_FOUND"


def test_counts_come_from_data(client):
    body = client.get("/api/v1/alerts/counts").json()
    assert body == {
        "total": 12,
        "unresolved": 12,
        "high_or_critical": 6,
        "awaiting_review": 0,
        "demo": 12,
    }


def test_seed_is_idempotent_and_audited(client):
    from app.services.seed_service import seed_demo_alerts

    with Session(engine) as session:
        assert seed_demo_alerts(session) == 0
        events = session.exec(text("SELECT COUNT(*) FROM audit_events")).one()[0]
    assert events == 12


def test_sqlite_foreign_keys_enforced(client):
    with Session(engine) as session:
        assert session.exec(text("PRAGMA foreign_keys")).one()[0] == 1


def test_history_returns_audit_events_in_order(client):
    body = client.get("/api/v1/alerts/ALT-001/history").json()
    assert body["alert_id"] == "ALT-001"
    assert [e["event_type"] for e in body["events"]] == ["alert_created"]
    assert body["assessments"] == []
    assert body["decisions"] == []


def test_history_unknown_alert_is_404(client):
    response = client.get("/api/v1/alerts/nope/history")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ALERT_NOT_FOUND"
