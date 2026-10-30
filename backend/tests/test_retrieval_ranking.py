"""Ranking regressions for hybrid retrieval, using the real seed data and the real retrieval and citation code.

Service-level on purpose: no HTTP, so authentication is not involved or bypassed.
"""
import json
import uuid

import pytest

from app.ai.response_parser import InvalidModelOutput, parse_assessment
from app.config import get_settings
from app.models import Organization, SecurityAlert
from app.services import evidence_service, indicators, retrieval_service
from app.services.seed_service import load_demo_incidents


def _retrieve(db, alert_id):
    alert = db.get(SecurityAlert, alert_id)
    return retrieval_service.retrieve(db, alert).items


def _incident_ids(items):
    return [i.id for i in items if i.kind == "demo_incident"]


def _new_org(db):
    org = Organization(name=f"Org {uuid.uuid4().hex[:6]}", slug=uuid.uuid4().hex[:12])
    db.add(org)
    db.commit()
    return org


def _new_alert(db, org, title, description, is_demo=False):
    alert = SecurityAlert(
        id=str(uuid.uuid4()), organization_id=org.id, title=title, description=description,
        severity="high", source="test", is_demo=is_demo,
    )
    db.add(alert)
    db.flush()
    indicators.store(db, alert)
    db.commit()
    return alert


# ------------------------------------------------------------------------------ the reported regression
def test_alt002_ranks_inc002_above_inc001(db, demo_org):
    """ALT-002 matches INC-002 on 5 keywords and INC-001 on 2; the stronger match must come first."""
    order = _incident_ids(_retrieve(db, "ALT-002"))
    assert "INC-001" in order and "INC-002" in order
    assert order.index("INC-002") < order.index("INC-001")


@pytest.mark.parametrize(
    "alert_id, incident_id",
    [("ALT-001", "INC-001"), ("ALT-002", "INC-002"), ("ALT-003", "INC-004"),
     ("ALT-004", "INC-006"), ("ALT-005", "INC-003"), ("ALT-007", "INC-005")],
)
def test_best_keyword_match_is_the_first_demo_incident(db, demo_org, alert_id, incident_id):
    assert _incident_ids(_retrieve(db, alert_id))[0] == incident_id


def test_no_match_returns_no_invented_incidents(db, demo_org):
    assert _incident_ids(_retrieve(db, "ALT-010")) == []


def test_demo_incidents_are_ordered_by_matched_keyword_count(db, demo_org):
    for alert_id in ("ALT-001", "ALT-002", "ALT-004", "ALT-007"):
        counts = [len(i.matched_terms) for i in _retrieve(db, alert_id) if i.kind == "demo_incident"]
        assert counts == sorted(counts, reverse=True), alert_id


def test_results_are_score_sorted_deterministic_and_capped(db, demo_org):
    strong = retrieval_service.STRONG_TYPES
    for alert_id in ("ALT-001", "ALT-002", "ALT-004", "ALT-007"):
        first = _retrieve(db, alert_id)
        assert [i.id for i in first] == [i.id for i in _retrieve(db, alert_id)]
        exact = [i for i in first if any(t.split(":")[0] in strong for t in i.matched_terms)]
        rest = [i for i in first if i not in exact]
        assert [i.score for i in rest] == sorted((i.score for i in rest), reverse=True), alert_id
        assert len(first) <= get_settings().rag_top_k


# ------------------------------------------------------------------------------ exact priority
def test_exact_indicator_match_outranks_demo_incidents(db):
    org = _new_org(db)
    cve = "CVE-2031-4242"
    earlier = _new_alert(db, org, "Earlier unrelated title", f"Observed {cve} activity", is_demo=True)
    incident = load_demo_incidents()[0]  # INC-001: every keyword is present in the new alert
    query = _new_alert(db, org, "Case with " + " ".join(incident["keywords"]), f"Also mentions {cve}", is_demo=True)
    items = _retrieve(db, query.id)
    assert items[0].id == earlier.id and "exact" in items[0].methods
    assert incident["id"] in _incident_ids(items)


# ------------------------------------------------------------------------------ isolation
def test_real_alerts_never_receive_demo_incidents(db):
    org = _new_org(db)
    keywords = " ".join(load_demo_incidents()[1]["keywords"])
    real = _new_alert(db, org, "Real alert " + keywords, keywords, is_demo=False)
    assert _incident_ids(_retrieve(db, real.id)) == []


def test_demo_and_real_alerts_and_other_orgs_do_not_cross(db):
    a, b = _new_org(db), _new_org(db)
    cve = "CVE-2032-1111"
    query = _new_alert(db, a, "Demo query alert", f"See {cve}", is_demo=True)
    real_same_org = _new_alert(db, a, "Real alert", f"See {cve}", is_demo=False)
    demo_other_org = _new_alert(db, b, "Demo alert elsewhere", f"See {cve}", is_demo=True)
    ids = {i.id for i in _retrieve(db, query.id)}
    assert real_same_org.id not in ids and demo_other_org.id not in ids


# ------------------------------------------------------------------------------ provenance
def test_items_carry_provenance(db, demo_org):
    items = _retrieve(db, "ALT-001")
    demo = [i for i in items if i.kind == "demo_incident"]
    alerts = [i for i in items if i.kind == "historical_alert"]
    assert demo and all(i.reliability == "synthetic" and i.methods == ["keyword"] and i.matched_terms for i in demo)
    assert alerts and all(i.occurred_at and i.methods and i.reliability in ("analyst_decided", "undecided") for i in alerts)


# ------------------------------------------------------------------------------ citation validation
def _output(source_type, source_id):
    return json.dumps({
        "summary": "s", "suggested_classification": "needs_review", "observed_facts": [], "interpretation": "",
        "supporting_evidence": [{"source_type": source_type, "source_id": source_id, "claim": "c", "evidence": "e"}],
        "missing_information": [], "recommended_steps": [],
    })


def test_only_retrieved_cases_can_be_cited(db, demo_org):
    alert = db.get(SecurityAlert, "ALT-002")
    package, valid_refs, _items = evidence_service.build_evidence_package(db, alert)
    retrieved = [c["id"] for c in package["historical_cases"] if c["source_type"] == "demo_incident"]
    assert retrieved.index("INC-002") < retrieved.index("INC-001")
    assert ("demo_incident", "INC-002") in valid_refs
    parse_assessment(_output("demo_incident", "INC-002"), valid_refs)  # accepted
    with pytest.raises(InvalidModelOutput):
        parse_assessment(_output("demo_incident", "INC-999"), valid_refs)  # invented
    not_retrieved = next(i["id"] for i in load_demo_incidents() if i["id"] not in retrieved)
    with pytest.raises(InvalidModelOutput):
        parse_assessment(_output("demo_incident", not_retrieved), valid_refs)  # real incident, but not in this package
