import pytest


def _related(client, alert_id):
    response = client.get(f"/api/v1/alerts/{alert_id}/related-incidents")
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize(
    "alert_id, incident_id",
    [
        ("ALT-001", "INC-001"),  # travel login
        ("ALT-002", "INC-002"),  # failed logins then success on service account
        ("ALT-003", "INC-004"),  # contractor upload
        ("ALT-004", "INC-006"),  # password spray
        ("ALT-005", "INC-003"),  # port sweep from scanner
        ("ALT-007", "INC-005"),  # impossible travel / VPN
    ],
)
def test_expected_incident_is_top_match(client, alert_id, incident_id):
    body = _related(client, alert_id)
    assert body["enabled"] is True
    assert body["items"][0]["id"] == incident_id
    assert body["items"][0]["matched_terms"]


def test_no_match_returns_empty_list_not_invented_cases(client):
    assert _related(client, "ALT-010")["items"] == []


def test_results_are_capped_and_have_source_ids(client):
    for alert_id in ("ALT-001", "ALT-002", "ALT-004"):
        items = _related(client, alert_id)["items"]
        assert len(items) <= 3
        assert all(item["id"].startswith("INC-") for item in items)


def test_unknown_alert_is_404(client):
    assert client.get("/api/v1/alerts/nope/related-incidents").status_code == 404
