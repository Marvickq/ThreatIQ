"""Automatic triage of HIGH/CRITICAL alerts.

Real HTTP stack, real database, real job table and the real `run_job` / `analyze_alert` code. Only two things
are replaced, and only here: the model client (a fake, so no test ever calls a provider) and job dispatch
(captured, then run explicitly on the test thread, so ordering is deterministic). Alerts carry no CVEs, so the
enrichment step makes no network call either. This does NOT exercise Celery, Redis or a real model.
"""
import json
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app import jobs
from app.ai.nebius_client import ModelError, ModelResponse
from app.config import get_settings
from app.database import engine
from app.main import app
from app.models import (
    Assessment,
    AuditEvent,
    Job,
    Organization,
    ReviewDecision,
    SecurityAlert,
)
from app.services import investigation_service, triage_service
from app.services.seed_service import seed_demo_alerts

PASSWORD = "correct-horse-battery"
MARKER = "SECRET-MARKER-9f3a"  # must never appear in an automatic-triage audit record

GOOD_OUTPUT = json.dumps({
    "summary": "Looks like credential stuffing.", "suggested_classification": "needs_review", "observed_facts": ["Repeated failures."],
    "interpretation": "Possibly automated.", "supporting_evidence": [], "missing_information": ["Source reputation."],
    "recommended_steps": ["Review the sign-in logs."],
})


class FakeClient:
    """Stands in for NebiusClient. Behaviour is set per test through class attributes."""

    configured = True
    error: ModelError | None = None
    delay = 0.0
    calls = 0
    active = 0
    peak = 0
    _lock = threading.Lock()

    def __init__(self, *_a, **_k) -> None:
        pass

    @property
    def is_configured(self) -> bool:
        return type(self).configured

    def params(self) -> dict:
        return {"fake": True}

    def complete_json(self, *_a, **_k) -> ModelResponse:
        cls = type(self)
        with cls._lock:
            cls.calls += 1
            cls.active += 1
            cls.peak = max(cls.peak, cls.active)
        try:
            time.sleep(cls.delay)
            if cls.error is not None:
                raise cls.error
            return ModelResponse(content=GOOD_OUTPUT, model="fake-model")
        finally:
            with cls._lock:
                cls.active -= 1


@pytest.fixture(autouse=True)
def harness(monkeypatch):
    FakeClient.configured, FakeClient.error, FakeClient.delay = True, None, 0.0
    FakeClient.calls = FakeClient.active = FakeClient.peak = 0
    for target in ("app.job_handlers.NebiusClient", "app.services.triage_service.NebiusClient", "app.routers.investigations.NebiusClient"):
        monkeypatch.setattr(target, FakeClient)
    dispatched: list[str] = []
    monkeypatch.setattr(jobs, "_dispatch", lambda job_id, countdown=0: dispatched.append(job_id))
    # The database outlives each test; startup recovery would re-dispatch earlier tests' queued jobs into this one.
    monkeypatch.setattr(jobs, "recover_interrupted_jobs", lambda: None)
    monkeypatch.setattr(investigation_service, "_semaphore", None)
    with TestClient(app):
        yield dispatched
    # Leave no queued work behind: the database is shared, and a later module's startup recovery would
    # otherwise dispatch these jobs to the real executor and the real model client.
    with Session(engine) as s:
        for job in s.exec(select(Job).where(Job.status.in_(["queued", "running"]))).all():
            job.status, job.message = "cancelled", "Cancelled by the test harness"
            s.add(job)
        s.commit()


def run_all(dispatched: list[str]) -> None:
    for job_id in list(dispatched):
        jobs.run_job(job_id)
    dispatched.clear()


def signup(tag="owner"):
    c = TestClient(app)
    r = c.post("/api/v1/auth/register", json={
        "email": f"{tag}-{uuid.uuid4().hex[:8]}@example.com", "password": PASSWORD, "display_name": tag, "organization_name": f"Org {uuid.uuid4().hex[:6]}",
    })
    assert r.status_code == 201, r.text
    c.org_id = r.json()["organization"]["id"]
    c.headers["X-CSRF-Token"] = c.cookies.get("tiq_csrf")
    return c


def api_key(owner) -> dict:
    r = owner.post("/api/v1/api-keys", json={"name": "ingest", "scopes": ["ingest:write", "alerts:read"]})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['key']}"}


def enable(owner, value=True):
    r = owner.patch("/api/v1/organization", json={"auto_triage_enabled": value})
    assert r.status_code == 200 and r.json()["auto_triage_enabled"] is value


def send(owner, headers, severity="critical", external_id=None, title=None, **extra):
    body = {"source": "test-siem", "external_id": external_id or uuid.uuid4().hex, "title": title or f"Alert {uuid.uuid4().hex[:8]}",
            "severity": severity, "description": f"details {MARKER}", "affected_entity": "host-1", **extra}
    return TestClient(app).post("/api/v1/ingest/webhook", json=body, headers=headers)


def jobs_for(org_id, alert_id=None):
    with Session(engine) as s:
        q = select(Job).where(Job.organization_id == org_id, Job.kind == "analyze")
        if alert_id:
            q = q.where(Job.subject_id == alert_id)
        return s.exec(q).all()


def audit(org_id, alert_id, prefix="auto_triage"):
    with Session(engine) as s:
        rows = s.exec(select(AuditEvent).where(AuditEvent.organization_id == org_id, AuditEvent.alert_id == alert_id)).all()
        return [e for e in rows if e.event_type.startswith(prefix)]


@pytest.fixture
def org(harness):
    owner = signup()
    enable(owner)
    return owner, api_key(owner)


# ------------------------------------------------------------------------------ enqueue rules
@pytest.mark.parametrize("severity", ["critical", "high"])
def test_high_and_critical_are_queued_when_enabled(org, severity):
    owner, key = org
    r = send(owner, key, severity)
    assert r.status_code == 201
    [job] = jobs_for(owner.org_id, r.json()["alert_id"])
    assert job.status == "queued" and job.payload == {"auto": True} and job.created_by is None
    assert [e.event_type for e in audit(owner.org_id, r.json()["alert_id"])] == ["auto_triage_enqueued"]
    assert FakeClient.calls == 0  # the ingest request itself never calls the model


@pytest.mark.parametrize("severity", ["medium", "low"])
def test_medium_and_low_are_not_queued(org, severity):
    owner, key = org
    r = send(owner, key, severity)
    assert r.status_code == 201
    assert jobs_for(owner.org_id, r.json()["alert_id"]) == [] and audit(owner.org_id, r.json()["alert_id"]) == []


def test_disabled_by_default_and_when_switched_off(harness):
    owner = signup()
    assert owner.get("/api/v1/organization").json()["auto_triage_enabled"] is False
    key = api_key(owner)
    r = send(owner, key, "critical")
    assert jobs_for(owner.org_id, r.json()["alert_id"]) == []
    enable(owner)
    enable(owner, False)
    assert jobs_for(owner.org_id, send(owner, key, "critical").json()["alert_id"]) == []


def test_only_org_managers_can_change_the_setting(org):
    owner, _ = org
    analyst = signup("analyst")
    email = analyst.get("/api/v1/auth/me").json()["user"]["email"]
    assert owner.post("/api/v1/organization/members", json={"email": email, "role": "analyst"}).status_code == 201
    analyst.post("/api/v1/auth/switch-organization", json={"organization_id": owner.org_id})
    analyst.headers["X-CSRF-Token"] = analyst.cookies.get("tiq_csrf")
    assert analyst.patch("/api/v1/organization", json={"auto_triage_enabled": False}).status_code == 403
    assert owner.get("/api/v1/organization").json()["auto_triage_enabled"] is True


def test_demo_alerts_are_never_triaged(org):
    owner, _ = org
    with Session(engine) as s:
        seed_demo_alerts(s, owner.org_id)
        demo = s.exec(select(SecurityAlert).where(SecurityAlert.organization_id == owner.org_id, SecurityAlert.is_demo.is_(True))).all()
        assert demo and any(a.severity in ("high", "critical") for a in demo)
        for a in demo:
            assert triage_service.maybe_enqueue(s, owner.org_id, a.id) is None
    assert jobs_for(owner.org_id) == []


# ------------------------------------------------------------------------------ duplicates
def test_replays_and_repeat_firings_do_not_create_more_jobs(org):
    owner, key = org
    t0 = datetime.now(UTC) - timedelta(minutes=30)
    t1 = t0 + timedelta(minutes=5)
    first = send(owner, key, "critical", external_id="evt-1", title="Same detection", event_time=t0.isoformat())
    alert_id = first.json()["alert_id"]
    replay = send(owner, key, "critical", external_id="evt-1", title="Same detection", event_time=t0.isoformat())
    update = send(owner, key, "critical", external_id="evt-1", title="Same detection", event_time=t1.isoformat())
    repeat = send(owner, key, "critical", external_id="evt-2", title="Same detection")
    assert (first.status_code, replay.json()["outcome"], update.json()["outcome"]) == (201, "duplicate", "updated")
    assert repeat.json()["alert_id"] == alert_id and repeat.json()["outcome"] == "updated"
    assert len(jobs_for(owner.org_id, alert_id)) == 1
    assert len(audit(owner.org_id, alert_id, "auto_triage_enqueued")) == 1


def test_enqueue_is_idempotent_per_alert(org):
    owner, key = org
    alert_id = send(owner, key, "high").json()["alert_id"]
    with Session(engine) as s:
        again = triage_service.maybe_enqueue(s, owner.org_id, alert_id)
    assert again is not None and len(jobs_for(owner.org_id, alert_id)) == 1


def test_manual_actions_reuse_the_queued_automatic_job(org):
    owner, key = org
    alert_id = send(owner, key, "critical").json()["alert_id"]
    [auto_job] = jobs_for(owner.org_id, alert_id)
    r = owner.post(f"/api/v1/alerts/{alert_id}/analyze")
    assert r.status_code == 202 and r.json()["id"] == auto_job.id
    r = owner.post(f"/api/v1/alerts/{alert_id}/enrich")  # analysis already enriches
    assert r.status_code == 202 and r.json()["id"] == auto_job.id
    forced = owner.post(f"/api/v1/alerts/{alert_id}/enrich?force=true")
    assert forced.status_code == 202 and forced.json()["id"] != auto_job.id  # an explicit force still runs
    assert len(jobs_for(owner.org_id, alert_id)) == 1


# ------------------------------------------------------------------------------ run, audit, review status
def test_automatic_analysis_runs_audits_and_leaves_the_decision_to_a_human(org, harness):
    owner, key = org
    alert_id = send(owner, key, "critical", title=f"Login storm {MARKER}").json()["alert_id"]
    run_all(harness)
    [job] = jobs_for(owner.org_id, alert_id)
    assert job.status == "succeeded" and FakeClient.calls == 1
    events = [e.event_type for e in audit(owner.org_id, alert_id)]
    assert events == ["auto_triage_enqueued", "auto_triage_started", "auto_triage_completed"]
    with Session(engine) as s:
        alert = s.get(SecurityAlert, alert_id)
        assert alert.status == "awaiting_review"  # queued for a human; never resolved
        assert len(s.exec(select(Assessment).where(Assessment.alert_id == alert_id)).all()) == 1
        assert s.exec(select(ReviewDecision).where(ReviewDecision.alert_id == alert_id)).all() == []


def test_audit_records_hold_no_alert_content(org, harness):
    owner, key = org
    alert_id = send(owner, key, "critical", title=f"Title {MARKER}").json()["alert_id"]
    run_all(harness)
    FakeClient.error = ModelError("MODEL_UNAVAILABLE", f"upstream said {MARKER}", 503)
    other = send(owner, key, "high", title=f"Another {MARKER}").json()["alert_id"]
    run_all(harness)
    for aid in (alert_id, other):
        for e in audit(owner.org_id, aid):
            assert MARKER not in json.dumps(e.details), e.event_type


def test_model_failure_is_audited_not_retried_and_does_not_touch_review_status(org, harness):
    owner, key = org
    FakeClient.error = ModelError("MODEL_UNAVAILABLE", "provider down", 503)
    alert_id = send(owner, key, "critical").json()["alert_id"]
    run_all(harness)
    [job] = jobs_for(owner.org_id, alert_id)
    assert job.status == "failed" and job.attempts == 1 and FakeClient.calls == 1
    assert harness == []  # nothing was re-dispatched: no automatic retry of an expensive failure
    events = audit(owner.org_id, alert_id)
    assert [e.event_type for e in events] == ["auto_triage_enqueued", "auto_triage_started", "auto_triage_failed"]
    assert events[-1].details["error_code"] == "MODEL_UNAVAILABLE"
    with Session(engine) as s:
        assert s.get(SecurityAlert, alert_id).status == "new"
        assert s.exec(select(Assessment).where(Assessment.alert_id == alert_id)).all() == []
        assert s.exec(select(ReviewDecision).where(ReviewDecision.alert_id == alert_id)).all() == []
    # An analyst can retry deliberately, and that works.
    FakeClient.error = None
    assert owner.post(f"/api/v1/jobs/{job.id}/retry").status_code == 202
    run_all(harness)  # the retry re-dispatched the job
    with Session(engine) as s:
        assert s.get(Job, job.id).status == "succeeded"


def test_unexpected_crash_during_analysis_is_audited(org, harness, monkeypatch):
    owner, key = org

    def boom(*_a, **_k):
        raise RuntimeError("database exploded " + MARKER)

    monkeypatch.setattr(investigation_service, "analyze_alert", boom)
    alert_id = send(owner, key, "critical").json()["alert_id"]
    run_all(harness)
    events = audit(owner.org_id, alert_id)
    assert events[-1].event_type == "auto_triage_failed" and events[-1].details["error_type"] == "RuntimeError"
    assert MARKER not in json.dumps(events[-1].details)
    with Session(engine) as s:
        assert s.get(SecurityAlert, alert_id).status == "new"


# ------------------------------------------------------------------------------ failure containment
def test_queue_failure_keeps_the_alert_and_can_be_retried_safely(org, monkeypatch):
    owner, key = org
    real_enqueue = jobs.enqueue

    def broken(*_a, **_k):
        raise RuntimeError("broker down " + MARKER)

    monkeypatch.setattr(jobs, "enqueue", broken)
    r = send(owner, key, "critical")
    assert r.status_code == 201  # the ingest still succeeds
    alert_id = r.json()["alert_id"]
    assert owner.get(f"/api/v1/alerts/{alert_id}").status_code == 200  # and the alert is stored
    [event] = audit(owner.org_id, alert_id)
    assert event.event_type == "auto_triage_failed" and event.details == {"stage": "enqueue", "error_type": "RuntimeError"}
    assert jobs_for(owner.org_id, alert_id) == []

    monkeypatch.setattr(jobs, "enqueue", real_enqueue)  # queue recovers; retry by the existing, idempotent paths
    r = owner.post(f"/api/v1/alerts/{alert_id}/analyze")
    again = owner.post(f"/api/v1/alerts/{alert_id}/analyze")
    assert r.status_code == again.status_code == 202 and r.json()["id"] == again.json()["id"]
    assert len(jobs_for(owner.org_id, alert_id)) == 1


def test_model_not_configured_skips_with_a_reason(org):
    owner, key = org
    FakeClient.configured = False
    alert_id = send(owner, key, "critical").json()["alert_id"]
    assert jobs_for(owner.org_id, alert_id) == []
    [event] = audit(owner.org_id, alert_id)
    assert (event.event_type, event.details) == ("auto_triage_skipped", {"reason": "model_not_configured"})


# ------------------------------------------------------------------------------ limits
def test_automatic_cap_and_shared_hourly_limit_are_respected(org, monkeypatch):
    owner, key = org
    monkeypatch.setattr(get_settings(), "auto_triage_max_per_hour", 2)
    ids = [send(owner, key, "critical").json()["alert_id"] for _ in range(4)]
    assert [len(jobs_for(owner.org_id, i)) for i in ids] == [1, 1, 0, 0]
    skipped = audit(owner.org_id, ids[2], "auto_triage_skipped")
    assert skipped[0].details == {"reason": "rate_limited"}
    assert owner.post(f"/api/v1/alerts/{ids[3]}/analyze").status_code == 202  # the automatic cap leaves analysts headroom

    # The shared hourly AI limit also applies: automatic triage cannot exceed what analysts are allowed.
    other = signup()
    enable(other)
    okey = api_key(other)
    monkeypatch.setattr(get_settings(), "auto_triage_max_per_hour", 100)
    monkeypatch.setattr(get_settings(), "rate_limit_ai_per_hour", 1)
    first, second = (send(other, okey, "critical").json()["alert_id"] for _ in range(2))
    assert (len(jobs_for(other.org_id, first)), len(jobs_for(other.org_id, second))) == (1, 0)


def test_manual_analysis_still_works_and_uses_the_same_budget(org, harness, monkeypatch):
    owner, key = org
    enable(owner, False)
    alert_id = send(owner, key, "critical").json()["alert_id"]
    assert jobs_for(owner.org_id, alert_id) == []
    r = owner.post(f"/api/v1/alerts/{alert_id}/analyze")
    assert r.status_code == 202
    run_all(harness)
    assert owner.get(f"/api/v1/alerts/{alert_id}").json()["status"] == "awaiting_review"
    sync = owner.post(f"/api/v1/alerts/{send(owner, key, 'high').json()['alert_id']}/analyze?sync=true")
    assert sync.status_code == 201
    assert audit(owner.org_id, alert_id) == []  # manual runs are not labelled as automatic triage


def test_ai_concurrency_limit_holds_for_parallel_automatic_jobs(org, harness, monkeypatch):
    owner, key = org
    monkeypatch.setattr(get_settings(), "ai_concurrency", 1)
    FakeClient.delay = 0.15
    for _ in range(3):
        send(owner, key, "critical")
    threads = [threading.Thread(target=jobs.run_job, args=(j,)) for j in harness]
    [t.start() for t in threads]
    [t.join(timeout=30) for t in threads]
    assert FakeClient.calls == 3 and FakeClient.peak == 1


# ------------------------------------------------------------------------------ tenant isolation
def test_tenants_are_isolated(harness):
    a, b = signup("a"), signup("b")
    enable(a)  # B stays disabled
    ka, kb = api_key(a), api_key(b)
    shared = {"external_id": "same-id", "title": "Identical detection", "severity": "critical"}
    ra, rb = send(a, ka, **shared), send(b, kb, **shared)
    assert ra.json()["alert_id"] != rb.json()["alert_id"]
    [job_a] = jobs_for(a.org_id)
    assert jobs_for(b.org_id) == [] and job_a.subject_id == ra.json()["alert_id"]
    assert b.get(f"/api/v1/jobs/{job_a.id}").status_code == 404
    assert b.post(f"/api/v1/alerts/{ra.json()['alert_id']}/analyze").status_code == 404
    # The service refuses to act on an alert through the wrong organization.
    with Session(engine) as s:
        assert triage_service.maybe_enqueue(s, b.org_id, ra.json()["alert_id"]) is None
    assert len(jobs_for(a.org_id)) == 1 and jobs_for(b.org_id) == []
    run_all(harness)
    assert audit(b.org_id, rb.json()["alert_id"]) == []


def test_organization_default_in_database(harness):
    owner = signup()
    with Session(engine) as s:
        assert s.get(Organization, owner.org_id).auto_triage_enabled is False
