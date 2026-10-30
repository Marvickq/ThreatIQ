from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "awaiting_review", "resolved"]
SortField = Literal["created_at", "last_seen_at", "severity", "status", "title", "source"]


class AlertSummary(BaseModel):
    id: str
    title: str
    severity: Severity
    source: str
    affected_entity: str | None
    status: AlertStatus
    is_demo: bool
    occurrence_count: int
    assigned_to: str | None
    created_at: datetime
    last_seen_at: datetime | None


class AlertDetail(AlertSummary):
    description: str
    updated_at: datetime
    first_seen_at: datetime | None
    external_id: str | None
    assigned_to_name: str | None = None


class AlertList(BaseModel):
    items: list[AlertSummary]
    total: int
    limit: int
    offset: int


class AuditEventOut(BaseModel):
    id: str
    event_type: str
    actor_type: str
    actor_id: str | None
    details: dict
    created_at: datetime


class AssessmentOut(BaseModel):
    id: str
    model_name: str
    suggested_classification: str
    summary: str
    observed_facts: list = []
    interpretation: str | None = None
    evidence: list
    missing_information: list
    recommended_steps: list
    confidence: float | None
    version: int
    prompt_version: str | None
    model_params: dict
    evidence_ids: list
    created_at: datetime


class ReviewDecisionOut(BaseModel):
    id: str
    assessment_id: str | None
    decision: str
    reviewer_note: str | None
    reviewer_id: str | None
    reviewer_name: str | None = None
    created_at: datetime


class HistoryResponse(BaseModel):
    alert_id: str
    events: list[AuditEventOut]
    assessments: list[AssessmentOut]
    decisions: list[ReviewDecisionOut]


class DecisionRequest(BaseModel):
    assessment_id: str | None = None
    # Validated in the service so an unsupported value returns INVALID_DECISION.
    decision: str
    reviewer_note: str | None = Field(default=None, max_length=2000)


class RelatedIncident(BaseModel):
    id: str
    kind: Literal["historical_alert", "demo_incident"]
    description: str
    outcome: str
    details: str
    matched_terms: list[str]
    score: float
    # Provenance and reliability of this retrieved case (defaults keep older callers valid).
    methods: list[str] = []  # exact | keyword | semantic
    occurred_at: datetime | None = None
    reliability: Literal["analyst_decided", "undecided", "synthetic"] = "undecided"
    decided_at: datetime | None = None
    analyst_note: str | None = None


class RelatedIncidents(BaseModel):
    """Context only; a similar past case is never proof of the same cause."""

    enabled: bool
    items: list[RelatedIncident]
