from sqlmodel import Session

from app.database import engine
from app.models import Assessment, SecurityAlert


def _decide(client, alert_id, **body):
    return client.post(f"/api/v1/alerts/{alert_id}/decisions", json=body)


def test_decision_is_persisted_and_visible_in_history(client):
    response = _decide(client, "ALT-005", decision="false_positive", reviewer_note="  Approved scanner.  ")
    assert response.status_code == 201
    saved = response.json()
    assert saved["decision"] == "false_positive"
    assert saved["reviewer_note"] == "Approved scanner."
    assert saved["assessment_id"] is None

    history = client.get("/api/v1/alerts/ALT-005/history").json()
    assert [d["id"] for d in history["decisions"]] == [saved["id"]]
    types = [e["event_type"] for e in history["events"]]
    assert types == ["alert_created", "decision_recorded", "status_changed"]
    assert history["events"][1]["actor_type"] == "human"
    # The note text is not copied into the audit event.
    assert "Approved scanner" not in str(history["events"][1]["details"])


def test_decision_updates_workflow_status(client):
    assert client.get("/api/v1/alerts/ALT-005").json()["status"] == "resolved"
    _decide(client, "ALT-007", decision="needs_further_review")
    assert client.get("/api/v1/alerts/ALT-007").json()["status"] == "investigating"


def test_repeated_decisions_are_preserved(client):
    _decide(client, "ALT-008", decision="needs_further_review", reviewer_note="Need logs.")
    _decide(client, "ALT-008", decision="true_positive")
    history = client.get("/api/v1/alerts/ALT-008/history").json()
    assert [d["decision"] for d in history["decisions"]] == ["needs_further_review", "true_positive"]
    assert history["decisions"][0]["reviewer_note"] == "Need logs."
    assert client.get("/api/v1/alerts/ALT-008").json()["status"] == "resolved"


def test_no_status_event_when_status_unchanged(client):
    _decide(client, "ALT-009", decision="needs_further_review")
    _decide(client, "ALT-009", decision="needs_further_review")
    types = [e["event_type"] for e in client.get("/api/v1/alerts/ALT-009/history").json()["events"]]
    assert types.count("decision_recorded") == 2
    assert types.count("status_changed") == 1


def test_invalid_decision_rejected(client):
    response = _decide(client, "ALT-010", decision="close_it")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_DECISION"
    assert client.get("/api/v1/alerts/ALT-010/history").json()["decisions"] == []


def test_overlong_note_rejected(client):
    response = _decide(client, "ALT-010", decision="true_positive", reviewer_note="x" * 2001)
    assert response.status_code == 422


def test_unknown_alert_is_404(client):
    response = _decide(client, "nope", decision="true_positive")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ALERT_NOT_FOUND"


def test_assessment_must_belong_to_same_alert(client):
    with Session(engine) as session:
        session.add(
            Assessment(
                id="ASM-TEST-1",
                alert_id="ALT-011",
                model_name="test-fixture",
                suggested_classification="needs_review",
                summary="fixture",
            )
        )
        session.commit()

    wrong = _decide(client, "ALT-012", decision="true_positive", assessment_id="ASM-TEST-1")
    assert wrong.status_code == 422
    assert wrong.json()["error"]["code"] == "INVALID_ASSESSMENT"
    missing = _decide(client, "ALT-012", decision="true_positive", assessment_id="does-not-exist")
    assert missing.status_code == 422

    ok = _decide(client, "ALT-011", decision="needs_further_review", assessment_id="ASM-TEST-1")
    assert ok.status_code == 201
    assert ok.json()["assessment_id"] == "ASM-TEST-1"
    # Nothing was saved for the rejected attempts.
    assert client.get("/api/v1/alerts/ALT-012/history").json()["decisions"] == []
    assert client.get("/api/v1/alerts/ALT-012").json()["status"] == "new"


def test_decision_does_not_modify_assessment(client):
    with Session(engine) as session:
        assessment = session.get(Assessment, "ASM-TEST-1")
        assert assessment.suggested_classification == "needs_review"
