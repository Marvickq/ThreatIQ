from sqlmodel import Session

from app.auth.principal import Principal
from app.errors import AppError
from app.events import bus
from app.models import DECISIONS, Assessment, ReviewDecision, utcnow
from app.schemas import DecisionRequest
from app.services.alert_service import get_alert
from app.services.audit_service import record_event

# Workflow status that follows each human decision. The decision itself is stored
# separately; status only describes where the alert is in the workflow.
STATUS_AFTER_DECISION = {
    "true_positive": "resolved",
    "false_positive": "resolved",
    "needs_further_review": "investigating",
}


def record_decision(session: Session, principal: Principal, alert_id: str, request: DecisionRequest) -> ReviewDecision:
    """Persist a human decision, update workflow status and audit it in one transaction."""
    if principal.kind != "session":
        # Decisions must come from an identified person, never from an API key.
        raise AppError("FORBIDDEN", "Review decisions must be made by a signed-in analyst.", 403)
    alert = get_alert(session, principal.organization_id, alert_id)

    if request.decision not in DECISIONS:
        raise AppError("INVALID_DECISION", f"Decision must be one of: {', '.join(DECISIONS)}.", 422)

    if request.assessment_id is not None:
        assessment = session.get(Assessment, request.assessment_id)
        if assessment is None or assessment.alert_id != alert_id or assessment.organization_id != principal.organization_id:
            raise AppError("INVALID_ASSESSMENT", "The referenced assessment does not exist for this alert.", 422)

    note = (request.reviewer_note or "").strip() or None
    decision = ReviewDecision(
        organization_id=principal.organization_id,
        alert_id=alert_id,
        assessment_id=request.assessment_id,
        decision=request.decision,
        reviewer_note=note,
        reviewer_id=principal.user_id,
    )
    previous_status = alert.status
    new_status = STATUS_AFTER_DECISION[request.decision]

    try:
        session.add(decision)
        session.flush()
        record_event(
            session, principal.organization_id, alert_id, "decision_recorded", "human", principal.user_id,
            {"decision_id": decision.id, "decision": decision.decision, "assessment_id": decision.assessment_id, "has_note": note is not None},
        )
        if new_status != previous_status:
            alert.status = new_status
            alert.updated_at = utcnow()
            session.add(alert)
            record_event(session, principal.organization_id, alert_id, "status_changed", "system", None, {"from": previous_status, "to": new_status})
        session.commit()
    except Exception:
        session.rollback()
        raise AppError("PERSISTENCE_ERROR", "The decision could not be saved.", 500)

    session.refresh(decision)
    bus.publish(principal.organization_id, "alert.updated", {"id": alert_id, "reason": "decision_recorded"})
    return decision
