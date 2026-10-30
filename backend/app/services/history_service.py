from sqlmodel import Session, select

from app.models import Assessment, AuditEvent, ReviewDecision, User
from app.schemas import AssessmentOut, AuditEventOut, HistoryResponse, ReviewDecisionOut
from app.services.alert_service import get_alert


def get_history(session: Session, organization_id: str, alert_id: str) -> HistoryResponse:
    """Everything recorded for an alert in this organization, oldest first."""
    get_alert(session, organization_id, alert_id)

    events = session.exec(
        select(AuditEvent)
        .where(AuditEvent.organization_id == organization_id, AuditEvent.alert_id == alert_id)
        .order_by(AuditEvent.created_at, AuditEvent.id)
    ).all()
    assessments = session.exec(
        select(Assessment)
        .where(Assessment.organization_id == organization_id, Assessment.alert_id == alert_id)
        .order_by(Assessment.created_at, Assessment.id)
    ).all()
    decisions = session.exec(
        select(ReviewDecision)
        .where(ReviewDecision.organization_id == organization_id, ReviewDecision.alert_id == alert_id)
        .order_by(ReviewDecision.created_at, ReviewDecision.id)
    ).all()

    names = {
        u.id: u.display_name
        for u in session.exec(select(User).where(User.id.in_({d.reviewer_id for d in decisions if d.reviewer_id}))).all()
    } if any(d.reviewer_id for d in decisions) else {}

    return HistoryResponse(
        alert_id=alert_id,
        events=[AuditEventOut.model_validate(e, from_attributes=True) for e in events],
        assessments=[AssessmentOut.model_validate(a, from_attributes=True) for a in assessments],
        decisions=[
            ReviewDecisionOut(
                id=d.id, assessment_id=d.assessment_id, decision=d.decision, reviewer_note=d.reviewer_note,
                reviewer_id=d.reviewer_id, reviewer_name=names.get(d.reviewer_id), created_at=d.created_at,
            )
            for d in decisions
        ],
    )
