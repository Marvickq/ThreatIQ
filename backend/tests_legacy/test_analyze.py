import json
import os

import pytest

from app.ai.nebius_client import ModelError, ModelResponse
from app.main import app
from app.routers.investigations import get_model_client


class FakeClient:
    """Stands in for NebiusClient. `script` is a list of responses or exceptions, used in order."""

    def __init__(self, script, configured=True):
        self.script = list(script)
        self.configured = configured
        self.calls = []

    @property
    def is_configured(self):
        return self.configured

    def complete_json(self, system, user, schema_name, schema):
        self.calls.append({"system": system, "user": user, "schema_name": schema_name})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok(**overrides):
    body = {
        "summary": "Pattern needs analyst attention.",
        "suggested_classification": "needs_review",
        "supporting_evidence": [
            {"source_type": "alert", "source_id": "ALT-001", "claim": "New country", "evidence": "Login from Lisbon"},
        ],
        "missing_information": ["Confirmation of travel dates"],
        "recommended_steps": ["Check the HR travel calendar"],
    }
    body.update(overrides)
    return ModelResponse(content=json.dumps(body), model="fake-model")


@pytest.fixture
def use_client():
    def _use(fake):
        app.dependency_overrides[get_model_client] = lambda: fake
        return fake

    yield _use
    app.dependency_overrides.pop(get_model_client, None)


def analyze(client, alert_id):
    return client.post(f"/api/v1/alerts/{alert_id}/analyze")


def history(client, alert_id):
    return client.get(f"/api/v1/alerts/{alert_id}/history").json()


def test_successful_analysis_is_validated_persisted_and_audited(client, use_client):
    fake = use_client(FakeClient([ok(
        supporting_evidence=[
            {"source_type": "alert", "source_id": "ALT-001", "claim": "c", "evidence": "e"},
            {"source_type": "historical_incident", "source_id": "INC-001", "claim": "c2", "evidence": "e2"},
        ]
    )]))
    response = analyze(client, "ALT-001")
    assert response.status_code == 201
    body = response.json()
    assert body["suggested_classification"] == "needs_review"
    assert body["model_name"] == "fake-model"
    assert body["confidence"] is None  # no uncalibrated confidence is invented

    h = history(client, "ALT-001")
    assert [e["event_type"] for e in h["events"]] == [
        "alert_created", "assessment_started", "assessment_completed", "status_changed",
    ]
    assert [a["id"] for a in h["assessments"]] == [body["id"]]
    assert client.get("/api/v1/alerts/ALT-001").json()["status"] == "awaiting_review"

    # Alert text goes to the model as delimited data, with instructions kept in the system prompt.
    user = fake.calls[0]["user"]
    assert "<<<EVIDENCE_BEGIN" in user and "EVIDENCE_END>>>" in user
    assert "Lisbon" in user and "INC-001" in user
    assert "untrusted data" in fake.calls[0]["system"]


def test_missing_configuration_returns_503_and_records_nothing(client, use_client):
    fake = use_client(FakeClient([], configured=False))
    response = analyze(client, "ALT-003")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "MODEL_NOT_CONFIGURED"
    assert fake.calls == []
    assert [e["event_type"] for e in history(client, "ALT-003")["events"]] == ["alert_created"]


def test_provider_failure_is_recorded_not_faked(client, use_client):
    fake = use_client(FakeClient([ModelError("MODEL_UNAVAILABLE", "down", 502)]))
    response = analyze(client, "ALT-003")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "MODEL_UNAVAILABLE"
    assert len(fake.calls) == 1  # provider outages are not retried automatically

    h = history(client, "ALT-003")
    assert h["assessments"] == []
    assert [e["event_type"] for e in h["events"]] == ["alert_created", "assessment_started", "assessment_failed"]
    assert h["events"][-1]["details"] == {"error_code": "MODEL_UNAVAILABLE"}
    assert client.get("/api/v1/alerts/ALT-003").json()["status"] == "new"


def test_invalid_output_is_retried_once_then_succeeds(client, use_client):
    valid = ok(supporting_evidence=[
        {"source_type": "alert", "source_id": "ALT-004", "claim": "c", "evidence": "e"},
    ])
    fake = use_client(FakeClient([ModelResponse("not json", "fake-model"), valid]))
    response = analyze(client, "ALT-004")
    assert response.status_code == 201
    assert len(fake.calls) == 2


def test_persistently_invalid_output_returns_error(client, use_client):
    fake = use_client(FakeClient([
        ModelResponse("{}", "fake-model"),
        ModelResponse(json.dumps({"summary": "x", "suggested_classification": "definitely_bad"}), "fake-model"),
    ]))
    response = analyze(client, "ALT-006")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "INVALID_MODEL_OUTPUT"
    assert len(fake.calls) == 2
    h = history(client, "ALT-006")
    assert h["assessments"] == []
    assert h["events"][-1]["event_type"] == "assessment_failed"


def test_unsupported_evidence_reference_is_rejected(client, use_client):
    bad = ok(supporting_evidence=[
        {"source_type": "historical_incident", "source_id": "INC-999", "claim": "c", "evidence": "invented"},
    ])
    use_client(FakeClient([bad, bad]))
    response = analyze(client, "ALT-006")
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "INVALID_MODEL_OUTPUT"
    assert history(client, "ALT-006")["assessments"] == []


def test_reanalysis_adds_a_new_assessment_and_keeps_the_old_one(client, use_client):
    use_client(FakeClient([ok(summary="Second look.", suggested_classification="likely_false_positive")]))
    response = analyze(client, "ALT-001")
    assert response.status_code == 201
    summaries = [a["summary"] for a in history(client, "ALT-001")["assessments"]]
    assert summaries == ["Pattern needs analyst attention.", "Second look."]
    # Status was already awaiting_review, so no extra status event.
    types = [e["event_type"] for e in history(client, "ALT-001")["events"]]
    assert types.count("status_changed") == 1


def test_decision_can_reference_the_reviewed_assessment_and_stays_independent(client, use_client):
    assessments = history(client, "ALT-001")["assessments"]
    reviewed = assessments[0]
    saved = client.post(
        "/api/v1/alerts/ALT-001/decisions",
        json={"decision": "false_positive", "assessment_id": reviewed["id"]},
    )
    assert saved.status_code == 201
    assert saved.json()["assessment_id"] == reviewed["id"]
    # The AI recommendation was needs_review; the human decision differs and is stored separately.
    assert reviewed["suggested_classification"] == "needs_review"

    # A later AI run must not change or reopen the human decision.
    use_client(FakeClient([ok(suggested_classification="likely_true_positive")]))
    assert analyze(client, "ALT-001").status_code == 201
    h = history(client, "ALT-001")
    assert [d["decision"] for d in h["decisions"]] == ["false_positive"]
    assert client.get("/api/v1/alerts/ALT-001").json()["status"] == "resolved"


def test_unknown_alert_is_404(client, use_client):
    use_client(FakeClient([]))
    assert analyze(client, "nope").status_code == 404


@pytest.mark.skipif(os.environ.get("RUN_LIVE_TESTS") != "1", reason="set RUN_LIVE_TESTS=1 to call the real Nebius model")
def test_live_nebius_assessment(client):
    """Real inference call using backend/.env.local. Run manually: RUN_LIVE_TESTS=1 pytest -k live"""
    response = analyze(client, "ALT-002")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["suggested_classification"] in {"likely_true_positive", "likely_false_positive", "needs_review"}
    assert body["summary"]
    assert not body["model_name"].startswith("fake")
