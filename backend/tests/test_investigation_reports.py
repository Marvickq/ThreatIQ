"""PDF investigation reports, generated from persisted records through the real HTTP stack.

The alert, indicators, evidence, assessment, decision and audit trail are all created by the application's own
services (`ingest_event`, `analyze_alert`, `record_decision`) and stored in the database; the report is built
from those rows. Only the model reply is fixed (no provider is called) and provider lookups are blocked so no
test can reach the network. PDFs are parsed back with pypdf and their text asserted.
"""
import hashlib
import io
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlmodel import Session, select

from app import jobs
from app.ai.nebius_client import ModelResponse
from app.auth.principal import Principal
from app.config import get_settings
from app.database import engine
from app.intel import providers
from app.main import app
from app.models import (
    AlertIndicator,
    Assessment,
    AuditEvent,
    EvidenceItem,
    Integration,
    InvestigationReport,
    ReviewDecision,
    SecurityAlert,
)
from app.schemas import DecisionRequest
from app.schemas_saas import IndicatorIn, IngestEvent
from app.services import (
    evidence_service,
    ingest_service,
    investigation_service,
    report_pdf,
    review_service,
)

PASSWORD = "correct-horse-battery"
CVE = "CVE-2021-26855"
EVENT_TIME = datetime(2026, 10, 29, 8, 15, 0, tzinfo=UTC)


def _no_network(*_a, **_k):
    raise AssertionError("a provider lookup was attempted during a report test")


@pytest.fixture(scope="module", autouse=True)
def _app():
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(jobs, "recover_interrupted_jobs", lambda: None)
        for name in ("lookup_kev", "lookup_nvd", "lookup_virustotal", "refresh_kev"):
            mp.setattr(providers, name, _no_network)
        mp.setattr(get_settings(), "virustotal_api_key", "")  # this machine's .env may hold a real key; tests must not depend on it
        with TestClient(app):
            yield


# ------------------------------------------------------------------------------ building real records
class OrgClient(TestClient):
    org_id: str
    user_id: str
    name: str
    email: str


def signup(tag="owner") -> OrgClient:
    c = OrgClient(app)
    c.email = f"{tag}-{uuid.uuid4().hex[:8]}@example.com"
    c.name = f"Org {uuid.uuid4().hex[:6]}"
    r = c.post("/api/v1/auth/register", json={"email": c.email, "password": PASSWORD, "display_name": f"{tag.title()} Person", "organization_name": c.name})
    assert r.status_code == 201, r.text
    c.org_id, c.user_id = r.json()["organization"]["id"], r.json()["user"]["id"]
    c.headers["X-CSRF-Token"] = c.cookies.get("tiq_csrf")
    return c


def member(owner: OrgClient, role: str) -> OrgClient:
    other = signup(role)
    assert owner.post("/api/v1/organization/members", json={"email": other.email, "role": role}).status_code == 201
    other.post("/api/v1/auth/switch-organization", json={"organization_id": owner.org_id})
    other.headers["X-CSRF-Token"] = other.cookies.get("tiq_csrf")
    other.org_id = owner.org_id
    return other


def new_alert(org_id, *, title="Suspicious PowerShell on web-01", description="Encoded command observed.", severity="high",
              entity="web-01", indicators=(), integration_id=None, event_time=EVENT_TIME) -> str:
    event = IngestEvent(source="test-siem", external_id=uuid.uuid4().hex, title=title, description=description, severity=severity,
                        affected_entity=entity, event_time=event_time, indicators=[IndicatorIn(type=t, value=v) for t, v in indicators])
    with Session(engine) as s:
        return ingest_service.ingest_event(s, org_id, event, integration_id=integration_id).alert_id


def add_evidence(alert_id, source_type, source_id, content, *, status="found", url=None):
    with Session(engine) as s:
        alert = s.get(SecurityAlert, alert_id)
        evidence_service._upsert(s, alert, source_type, source_id, f"{source_type}: {source_id}", content, status=status, url=url,
                                 ttl=timedelta(hours=24))
        s.commit()


def add_kev(alert_id, cve=CVE):
    # Same content shape the CISA KEV provider stores.
    add_evidence(alert_id, "cisa_kev", cve, {
        "cve": cve, "vendor": "Microsoft", "product": "Exchange Server", "name": "Microsoft Exchange Server SSRF Vulnerability",
        "date_added": "2021-11-03", "description": "SSRF allows an attacker to send arbitrary HTTP requests.",
        "required_action": "Apply updates per vendor instructions.", "due_date": "2021-11-17", "known_ransomware_use": "Known",
        "catalog_version": "2026.10.01"}, url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog")


def add_nvd(alert_id, cve=CVE):
    add_evidence(alert_id, "nvd", cve, {
        "id": cve, "status": "Analyzed", "published": "2021-03-03T00:15:00", "description": "Exchange Server SSRF.",
        "cvss": {"version": "3.1", "score": 9.1, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"}}, url=f"https://nvd.nist.gov/vuln/detail/{cve}")


def add_history(alert_id, case_id="ALT-0042"):
    add_evidence(alert_id, "historical_alert", case_id, {
        "description": "Earlier PowerShell alert on the same host.", "recorded_outcome": "true_positive", "details": "closed",
        "matched_on": ["web-01"], "retrieved_by": ["exact"], "reliability": "analyst_decided"})


class Reply:
    """A fixed model reply; the real analyze_alert validates it against the stored evidence like any other."""

    is_configured = True

    def __init__(self, **fields) -> None:
        self.output = {"summary": "Encoded PowerShell consistent with the Exchange exploit chain.", "suggested_classification": "likely_true_positive",
                       "observed_facts": ["An encoded PowerShell command ran on web-01."], "interpretation": "Possibly post-exploitation activity.",
                       "supporting_evidence": [], "missing_information": ["Parent process of the command."],
                       "recommended_steps": ["Review process creation logs for web-01."], **fields}

    def params(self):
        return {"temperature": 0.2}

    def complete_json(self, *_a, **_k):
        return ModelResponse(content=json.dumps(self.output), model="test-model-1")


def analyze(org_id, alert_id, user_id=None, **fields):
    with Session(engine) as s:
        return investigation_service.analyze_alert(s, org_id, alert_id, Reply(**fields), user_id).id


def decide(owner: OrgClient, alert_id, decision, note, assessment_id):
    principal = Principal(kind="session", organization_id=owner.org_id, user_id=owner.user_id, role="analyst")
    with Session(engine) as s:
        review_service.record_decision(s, principal, alert_id, DecisionRequest(decision=decision, reviewer_note=note, assessment_id=assessment_id))


def full_case(owner: OrgClient, *, decision="true_positive", ai="likely_true_positive", note="Confirmed in the EDR console; host isolated by the SOC.") -> dict:
    """An alert with indicators, KEV + NVD + historical evidence, an AI assessment citing them, and an analyst decision."""
    alert_id = new_alert(owner.org_id, description=f"Encoded PowerShell on web-01 after exploitation of {CVE} from 203.0.113.9.",
                         indicators=[("cve", CVE), ("ip", "203.0.113.9"), ("domain", "evil.example.com"), ("sha256", "a" * 64)])
    add_kev(alert_id)
    add_nvd(alert_id)
    add_history(alert_id)
    cites = [{"source_type": "cisa_kev", "source_id": CVE, "claim": "The CVE is actively exploited.", "evidence": "Listed in CISA KEV, ransomware use Known."},
             {"source_type": "alert", "source_id": alert_id, "claim": "A command ran on web-01.", "evidence": "Encoded PowerShell on web-01"}]
    assessment_id = analyze(owner.org_id, alert_id, suggested_classification=ai, supporting_evidence=cites)
    if decision:
        decide(owner, alert_id, decision, note, assessment_id)
    return {"alert_id": alert_id, "assessment_id": assessment_id}


# ------------------------------------------------------------------------------ using the API
def generate(c, alert_id, **body):
    return c.post(f"/api/v1/alerts/{alert_id}/reports", json=body)


def fetch(c, alert_id, report_id):
    return c.get(f"/api/v1/alerts/{alert_id}/reports/{report_id}/download")


def make_report(c, alert_id, **body) -> tuple[dict, str, list[str]]:
    r = generate(c, alert_id, **body)
    assert r.status_code == 201, r.text
    meta = r.json()
    d = fetch(c, alert_id, meta["id"])
    assert d.status_code == 200
    text, pages = pdf_text(d.content)
    return meta, text, pages


def pdf_text(content: bytes) -> tuple[str, list[str]]:
    assert content.startswith(b"%PDF-") and content.rstrip().endswith(b"%%EOF")
    pages = [" ".join((p.extract_text() or "").split()) for p in PdfReader(io.BytesIO(content)).pages]
    return " ".join(pages), pages


def squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


@pytest.fixture
def owner() -> OrgClient:
    return signup("owner")


# ------------------------------------------------------------------------------ content
def test_complete_report_contains_every_section_from_stored_records(owner):
    case = full_case(owner)
    t0 = datetime.now(UTC).replace(microsecond=0)
    meta, text, pages = make_report(owner, case["alert_id"], classification="Restricted")
    t1 = datetime.now(UTC) + timedelta(seconds=1)

    # cover
    assert "ThreatIQ" in pages[0] and "Incident Investigation Report" in pages[0]
    assert owner.name in pages[0] and meta["report_number"] in pages[0] and "RESTRICTED" in pages[0] and case["alert_id"] in pages[0]
    generated = re.search(r"Generated (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", pages[0])
    assert generated and t0 <= datetime.strptime(generated.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC) <= t1
    assert generated.group(1) == meta["created_at"][:19].replace("T", " ")  # history and cover agree
    assert re.fullmatch(r"TIQ-\d{8}-[0-9A-F]{6}", meta["report_number"])

    # all eight parts, in order
    headings = ["1. Executive summary", "2. Alert details", "3. Evidence and threat intelligence", "4. AI investigation", "5. Analyst review",
                "6. Investigation timeline", "7. Limitations and disclaimer"]
    positions = [text.index(h) for h in headings]
    assert positions == sorted(positions)

    # executive summary + alert details
    assert "Suspicious PowerShell on web-01" in text and "High" in text and "test-siem" in text
    assert "Likely true positive (AI-generated, assessment v1" in text
    assert "True positive (by Owner Person" in text
    assert "Resolved" in text  # status follows the human decision
    assert "2026-10-29 08:15:00 UTC" in text  # first seen = the event time sent, not the generation time
    assert "Encoded PowerShell on web-01 after exploitation" in text

    # evidence: indicators, KEV, NVD, historical, provenance. No VirusTotal result exists, and none is invented.
    for needle in ("203.0.113.9", "evil.example.com", CVE, "a" * 64):
        assert needle in squash(text)
    assert "Microsoft Exchange Server SSRF Vulnerability" in text and "Known ransomware use: Known" in text and "Due date: 2021-11-17" in text
    assert "CVSS 3.1: 9.1 (CRITICAL)" in text
    assert "ALT-0042" in text and "analyst_decided" in text
    assert "cisa_kev:" in text and "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in squash(text)
    assert "VirusTotal is not configured for this deployment" in text and "Analysis stats" not in text
    assert "earliest provider result stored; no enrichment event in the audit log" in text  # analysis enriches without its own audit event
    received = re.search(r"Received by ThreatIQ (\d{4}-\d\d-\d\d)", text)
    assert received and received.group(1) == datetime.now(UTC).strftime("%Y-%m-%d")  # real receipt time, not the 2026-10-29 event time

    # AI investigation
    for needle in ("Encoded PowerShell consistent with the Exchange exploit chain.", "An encoded PowerShell command ran on web-01.",
                   "Possibly post-exploitation activity.", "Parent process of the command.", "Review process creation logs for web-01.",
                   "test-model-1", "Matches stored evidence", "Listed in CISA KEV, ransomware use Known."):
        assert needle in text
    assert "Not found in stored evidence" not in text and "not been independently verified" in text

    # analyst review
    assert "Confirmed in the EDR console; host isolated by the SOC." in text and "Consistent with the AI suggestion" in text
    assert "Final classification True positive" in text

    # timeline, with the real recorded events
    for needle in ("Alert received from test-siem", "AI analysis started", "AI assessment generated: Likely true positive (v1)",
                   "Analyst decision recorded: True positive", "Status changed: Awaiting analyst review to Resolved"):
        assert needle in text

    # disclaimer
    for needle in ("does not state that any attack was detected, blocked or prevented by ThreatIQ", "No record' from a threat-intelligence provider",
                   "snapshot generated at"):
        assert needle in text
    assert len(pages) >= 5 and all(f"Page {i} of {len(pages)}" in p for i, p in enumerate(pages, 1) if i > 1)
    assert "Page 1 of" not in pages[0]  # the cover is clean


def test_report_with_no_enrichment_assessment_or_decision_invents_nothing(owner):
    alert_id = new_alert(owner.org_id, description="Something odd happened.", entity=None)  # no indicators, no evidence, no AI, no analyst
    meta, text, _ = make_report(owner, alert_id)
    for needle in ("No indicators are stored for this alert.", "No CVE identifiers were extracted from this alert, so no lookup applied.",
                   "VirusTotal is not configured for this deployment", "No related historical cases are stored",
                   "No evidence records are stored for this alert", "No AI assessment has been generated for this alert",
                   "No analyst decision has been recorded", "Not yet investigated", "No analyst review is recorded for this alert",
                   "Not recorded"):
        assert needle in text, needle
    for forbidden in ("Matches stored evidence", "Known ransomware use", "CVSS", "Consistent with", "Differs from", "Reviewed by an analyst"):
        assert forbidden not in text, forbidden
    assert meta["assessment_id"] is None and meta["decision_id"] is None and meta["evidence_count"] == 0


def test_ai_output_without_analyst_review_is_marked_unverified(owner):
    alert_id = new_alert(owner.org_id)
    analyze(owner.org_id, alert_id)
    _, text, _ = make_report(owner, alert_id)
    assert "Awaiting analyst review" in text and "has NOT been reviewed by an analyst" in text
    assert "No analyst decision has been recorded" in text and "Final classification" not in text
    assert "Encoded PowerShell consistent with the Exchange exploit chain." in text  # shown, but labelled AI-generated
    assert "AI-generated content" in text


def test_rejected_ai_recommendation_is_reported_as_such(owner):
    case = full_case(owner, decision="false_positive", ai="likely_true_positive", note="Authorised admin script; ticket CHG-4411.")
    meta, text, _ = make_report(owner, case["alert_id"])
    assert "Differs from the AI suggestion (v1: Likely true positive); the AI recommendation was not adopted" in text
    assert "False positive (by Owner Person" in text and "Authorised admin script; ticket CHG-4411." in text
    assert "Consistent with the AI suggestion" not in text
    assert meta["decision_id"] is not None


def test_multiple_decisions_are_all_listed_and_the_latest_is_final(owner):
    case = full_case(owner, decision="needs_further_review", note="Waiting on EDR data.")
    decide(owner, case["alert_id"], "true_positive", "EDR confirmed.", case["assessment_id"])
    _, text, _ = make_report(owner, case["alert_id"])
    assert "All recorded decisions (newest first)" in text and "Waiting on EDR data." in text and "EDR confirmed." in text
    assert "Final classification True positive" in text


def test_citation_that_is_not_in_stored_evidence_is_flagged(owner):
    case = full_case(owner)
    with Session(engine) as s:  # the cited evidence row disappears after the assessment was made
        row = s.exec(select(EvidenceItem).where(EvidenceItem.alert_id == case["alert_id"], EvidenceItem.source_type == "cisa_kev")).one()
        s.delete(row)
        s.commit()
    _, text, _ = make_report(owner, case["alert_id"])
    assert "Not found in stored evidence" in text and "Matches stored evidence" in text  # one of each; nothing is papered over


def test_provider_failure_and_no_record_are_distinguished_from_findings(owner):
    alert_id = new_alert(owner.org_id, indicators=[("cve", CVE), ("cve", "CVE-2020-0001")])
    add_evidence(alert_id, "cisa_kev", "CVE-2020-0001", {"catalog_version": "x"}, status="not_found")
    add_evidence(alert_id, "nvd", CVE, {"error": "NVD returned HTTP 503 apiKey=SECRETKEY123"}, status="error")
    _, text, _ = make_report(owner, alert_id)
    assert "No record at this provider" in text and "does not show the activity is benign" in text
    assert "Lookup failed" in text and "provider failure, not a finding" in text
    assert "SECRETKEY123" not in text  # provider error text is redacted
    assert "NIST NVD lookup for CVE-2021-26855 failed, so that evidence is unavailable." in text


def test_virustotal_results_appear_only_when_they_exist(owner, monkeypatch):
    monkeypatch.setattr(get_settings(), "virustotal_api_key", "configured-for-this-test")
    alert_id = new_alert(owner.org_id, indicators=[("ip", "203.0.113.9")])
    add_evidence(alert_id, "virustotal", "203.0.113.9", {"indicator_type": "ip", "last_analysis_stats": {"malicious": 7, "harmless": 60}, "reputation": -12},
                 url="https://www.virustotal.com/gui/ip-address/203.0.113.9")
    _, text, _ = make_report(owner, alert_id)
    assert "Analysis stats: malicious: 7, harmless: 60" in text and "Reputation: -12" in text
    assert "VirusTotal is not configured" not in text and "configured-for-this-test" not in text
    assert "No VirusTotal results" not in text


def test_secrets_and_internal_configuration_never_appear(owner):
    with Session(engine) as s:
        integ = Integration(organization_id=owner.org_id, kind="wazuh", name="Prod Wazuh", config={"endpoint": "https://wazuh.internal.example:9200/secret-path"},
                            secret_encrypted="ENCRYPTED-SECRET-VALUE-XYZ")
        s.add(integ)
        s.commit()
        integ_id = integ.id
    alert_id = new_alert(owner.org_id, integration_id=integ_id)
    _, text, _ = make_report(owner, alert_id)
    assert "Prod Wazuh" in text and "wazuh" in text
    for secret in ("ENCRYPTED-SECRET-VALUE-XYZ", "wazuh.internal.example", "secret-path", "password_hash", "csrf"):
        assert secret not in squash(text)


def test_missing_fields_render_as_not_recorded(owner):
    alert_id = new_alert(owner.org_id)
    with Session(engine) as s:
        a = s.get(SecurityAlert, alert_id)
        a.external_id, a.affected_entity, a.description, a.first_seen_at, a.last_seen_at = None, None, "", None, None
        s.add(a)
        s.commit()
    _, text, _ = make_report(owner, alert_id)
    assert "External ID (source) Not recorded" in text and "Affected host / entity Not recorded" in text and "Assigned to Not recorded" in text
    assert "(empty)" in text


# ------------------------------------------------------------------------------ robustness
def test_long_and_hostile_content_does_not_break_the_report(owner):
    token = "H" * 3000 + "END-TOKEN"
    description = f"Line one <b>not bold</b> & <script>alert(1)</script> </para> {token}\n" + ("filler sentence. " * 800) + "END-OF-DESCRIPTION"
    assert len(description) < 20_000
    alert_id = new_alert(owner.org_id, title="T" * 280, description=description, indicators=[("cve", CVE)])
    add_kev(alert_id)
    cites = [{"source_type": "cisa_kev", "source_id": CVE, "claim": f"Claim {n} " + "c" * 200, "evidence": f"Quote {n} " + "q" * 400} for n in range(1, 31)]
    cites[0]["evidence"] = "Z" * 6000 + "END-QUOTE"  # a cell far taller than a page
    long_note = "N" * 1900 + "END-NOTE"
    assessment_id = analyze(owner.org_id, alert_id, supporting_evidence=cites, observed_facts=[f"Fact {n} " + "f" * 300 for n in range(20)],
                            recommended_steps=[f"Step {n}" for n in range(20)])
    decide(owner, alert_id, "true_positive", long_note, assessment_id)

    meta, text, pages = make_report(owner, alert_id)
    s = squash(text)
    assert "END-TOKEN" in s and "END-OF-DESCRIPTION" in s and "END-QUOTE" in s and "END-NOTE" in s  # nothing truncated or lost
    assert "<b>not bold</b>" in text and "<script>alert(1)</script>" in text  # markup is shown literally, never interpreted
    assert all(f"Claim {n} " in text for n in range(1, 31)) and text.count("Matches ") == 30  # all 30 rows, each checked (one row splits across pages)
    assert len(pages) >= 8 and meta["size_bytes"] > 5_000
    assert not any(p.startswith("Page ") and len(p) < 20 for p in pages[1:])  # no page is only a footer


def test_non_latin_text_is_replaced_and_the_report_says_so(owner):
    alert_id = new_alert(owner.org_id, title="Login from \u65e5\u672c\u8a9e host", description="caf\u00e9 \u2014 r\u00e9sum\u00e9 \u0434\u0430")
    _, text, _ = make_report(owner, alert_id)
    assert "caf\u00e9" in text and "r\u00e9sum\u00e9" in text  # Latin accents are drawn properly
    assert "could not be drawn with this report's font" in text


def test_layout_has_no_overflow_or_empty_pages(owner):
    case = full_case(owner)
    r = generate(owner, case["alert_id"])
    content = fetch(owner, case["alert_id"], r.json()["id"]).content
    reader = PdfReader(io.BytesIO(content))
    for number, page in enumerate(reader.pages, start=1):
        width, height = float(page.mediabox.width), float(page.mediabox.height)
        assert (round(width), round(height)) == (595, 842)  # A4
        xs = []

        def visit(text, cm, tm, _font, _size, out=xs):
            if text.strip():
                out.append(cm[4] + tm[4])

        page.extract_text(visitor_text=visit)
        assert xs, f"page {number} is empty"
        assert all(0 <= x <= width for x in xs), f"text drawn outside page {number}"


# ------------------------------------------------------------------------------ persistence and history
def test_history_download_and_snapshot_behaviour(owner):
    case = full_case(owner, decision=None)
    first = generate(owner, case["alert_id"]).json()
    decide(owner, case["alert_id"], "true_positive", "Confirmed later.", case["assessment_id"])
    second = generate(owner, case["alert_id"], classification="Internal").json()

    history = owner.get(f"/api/v1/alerts/{case['alert_id']}/reports").json()
    assert [h["id"] for h in history] == [second["id"], first["id"]]  # newest first
    assert first["report_number"] != second["report_number"] and all(h["generated_by_name"] == "Owner Person" for h in history)
    assert all(h["status"] == "generated" and h["size_bytes"] > 1000 for h in history) and "pdf" not in history[0]

    d1, d2 = fetch(owner, case["alert_id"], first["id"]), fetch(owner, case["alert_id"], second["id"])
    assert hashlib.sha256(d1.content).hexdigest() == first["sha256"] and len(d1.content) == first["size_bytes"]
    t1, t2 = pdf_text(d1.content)[0], pdf_text(d2.content)[0]
    assert "No analyst decision has been recorded" in t1 and "Confirmed later." not in t1  # a stored report is a snapshot
    assert "Confirmed later." in t2 and "INTERNAL" in t2
    assert f"Investigation report generated ({first['report_number']})" in t2  # the earlier generation is in the later timeline

    assert d1.headers["content-type"] == "application/pdf" and d1.headers["cache-control"] == "no-store"
    assert d1.headers["content-disposition"] == f'attachment; filename="{first["report_number"]}.pdf"'


def test_generation_preserves_the_original_records_and_is_audited(owner):
    case = full_case(owner)

    def snapshot():
        with Session(engine) as s:
            alert = s.get(SecurityAlert, case["alert_id"])
            return (alert.status, alert.updated_at, alert.description, alert.severity,
                    len(s.exec(select(Assessment).where(Assessment.alert_id == alert.id)).all()),
                    len(s.exec(select(ReviewDecision).where(ReviewDecision.alert_id == alert.id)).all()),
                    len(s.exec(select(AlertIndicator).where(AlertIndicator.alert_id == alert.id)).all()))

    before = snapshot()
    meta = generate(owner, case["alert_id"]).json()
    fetch(owner, case["alert_id"], meta["id"])
    assert snapshot() == before
    with Session(engine) as s:
        events = {e.event_type: e for e in s.exec(select(AuditEvent).where(AuditEvent.alert_id == case["alert_id"], AuditEvent.event_type.like("report_%"))).all()}
    assert set(events) == {"report_generated", "report_downloaded"}
    assert events["report_generated"].actor_id == owner.user_id and events["report_generated"].details["report_number"] == meta["report_number"]
    assert "Suspicious PowerShell" not in json.dumps([e.details for e in events.values()])  # no alert content in audit


def test_classification_is_validated(owner):
    alert_id = new_alert(owner.org_id)
    assert generate(owner, alert_id, classification="Top Secret").status_code == 422
    assert generate(owner, alert_id, classification="Confidential").status_code == 201
    assert owner.post(f"/api/v1/alerts/{alert_id}/reports").status_code == 201  # body is optional; defaults to Confidential


# ------------------------------------------------------------------------------ failure
def test_pdf_generation_failure_is_recorded_and_changes_nothing(owner, monkeypatch):
    alert_id = new_alert(owner.org_id)
    with Session(engine) as s:
        before = (s.get(SecurityAlert, alert_id).status, s.get(SecurityAlert, alert_id).updated_at)

    def boom(_data):
        raise RuntimeError("renderer exploded: secret-token-123")

    monkeypatch.setattr(report_pdf, "render", boom)
    r = generate(owner, alert_id)
    assert r.status_code == 500 and r.json()["error"]["code"] == "REPORT_GENERATION_FAILED"
    assert "secret-token-123" not in r.text and "exploded" not in r.text

    history = owner.get(f"/api/v1/alerts/{alert_id}/reports").json()
    assert len(history) == 1 and history[0]["status"] == "failed" and history[0]["error_code"] == "RuntimeError"
    assert history[0]["size_bytes"] is None and history[0]["sha256"] is None
    assert fetch(owner, alert_id, history[0]["id"]).status_code == 404  # a failed attempt has no file
    with Session(engine) as s:
        assert (s.get(SecurityAlert, alert_id).status, s.get(SecurityAlert, alert_id).updated_at) == before
        failure = s.exec(select(AuditEvent).where(AuditEvent.alert_id == alert_id, AuditEvent.event_type == "report_failed")).one()
        assert failure.details == {"report_number": history[0]["report_number"], "error_type": "RuntimeError"}
        assert s.get(InvestigationReport, history[0]["id"]).pdf is None

    monkeypatch.undo()  # a later attempt works
    assert generate(owner, alert_id).status_code == 201


def test_a_renderer_that_returns_garbage_is_a_failure_not_a_report(owner, monkeypatch):
    alert_id = new_alert(owner.org_id)
    monkeypatch.setattr(report_pdf, "render", lambda _d: b"not a pdf")
    assert generate(owner, alert_id).status_code == 500
    assert [h["status"] for h in owner.get(f"/api/v1/alerts/{alert_id}/reports").json()] == ["failed"]


# ------------------------------------------------------------------------------ access control
def test_invalid_alert_and_report_ids(owner):
    missing = str(uuid.uuid4())
    for r in (generate(owner, missing), owner.get(f"/api/v1/alerts/{missing}/reports"), fetch(owner, missing, missing)):
        assert r.status_code == 404 and r.json()["error"]["code"] == "ALERT_NOT_FOUND"
    alert_id = new_alert(owner.org_id)
    r = fetch(owner, alert_id, str(uuid.uuid4()))
    assert r.status_code == 404 and r.json()["error"]["code"] == "REPORT_NOT_FOUND"


def test_other_organizations_cannot_generate_list_or_download(owner):
    case = full_case(owner)
    meta = generate(owner, case["alert_id"]).json()
    other = signup("intruder")
    own_alert = new_alert(other.org_id)
    own_report = generate(other, own_alert).json()

    assert generate(other, case["alert_id"]).status_code == 404
    assert other.get(f"/api/v1/alerts/{case['alert_id']}/reports").status_code == 404
    assert fetch(other, case["alert_id"], meta["id"]).status_code == 404  # right ids, wrong organization
    assert fetch(other, own_alert, meta["id"]).status_code == 404  # A's report id through B's own alert
    assert fetch(owner, case["alert_id"], own_report["id"]).status_code == 404  # and the reverse
    assert fetch(owner, own_alert, own_report["id"]).status_code == 404

    key = other.post("/api/v1/api-keys", json={"name": "k", "scopes": ["alerts:read", "alerts:write"]}).json()["key"]
    bearer = {"Authorization": f"Bearer {key}"}
    assert TestClient(app).post(f"/api/v1/alerts/{case['alert_id']}/reports", json={}, headers=bearer).status_code == 404
    assert TestClient(app).get(f"/api/v1/alerts/{case['alert_id']}/reports/{meta['id']}/download", headers=bearer).status_code == 404

    assert fetch(owner, case["alert_id"], meta["id"]).status_code == 200  # the owner is unaffected
    with Session(engine) as s:
        assert s.exec(select(AuditEvent).where(AuditEvent.alert_id == case["alert_id"], AuditEvent.actor_id == other.user_id)).all() == []
    other_text = pdf_text(fetch(other, own_alert, own_report["id"]).content)[0]
    assert owner.name not in other_text and CVE not in other_text  # B's report holds none of A's data


def test_roles_and_authentication(owner):
    alert_id = new_alert(owner.org_id)
    existing = generate(owner, alert_id).json()
    viewer, analyst = member(owner, "viewer"), member(owner, "analyst")

    assert generate(viewer, alert_id).status_code == 403  # creating a report is an analyst action
    assert viewer.get(f"/api/v1/alerts/{alert_id}/reports").status_code == 200  # but read-only users can see and download them
    assert fetch(viewer, alert_id, existing["id"]).status_code == 200
    made = generate(analyst, alert_id)
    assert made.status_code == 201 and made.json()["generated_by_name"] == "Analyst Person"

    anon = TestClient(app)
    assert anon.get(f"/api/v1/alerts/{alert_id}/reports").status_code == 401
    assert anon.post(f"/api/v1/alerts/{alert_id}/reports", json={}).status_code == 401
    assert anon.get(f"/api/v1/alerts/{alert_id}/reports/{existing['id']}/download").status_code == 401
    forged = TestClient(app, cookies=owner.cookies)
    assert forged.post(f"/api/v1/alerts/{alert_id}/reports", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403

    read_key = owner.post("/api/v1/api-keys", json={"name": "ro", "scopes": ["alerts:read"]}).json()["key"]
    bearer = {"Authorization": f"Bearer {read_key}"}
    assert TestClient(app).post(f"/api/v1/alerts/{alert_id}/reports", json={}, headers=bearer).status_code == 403
    assert TestClient(app).get(f"/api/v1/alerts/{alert_id}/reports", headers=bearer).status_code == 200
