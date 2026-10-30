from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.auth.deps import require
from app.auth.principal import Principal
from app.config import get_settings
from app.database import get_session
from app.schemas import (
    AlertDetail,
    AlertList,
    AlertStatus,
    AlertSummary,
    DecisionRequest,
    HistoryResponse,
    RelatedIncidents,
    ReviewDecisionOut,
    Severity,
    SortField,
)
from app.errors import AppError
from app.schemas_saas import AssignRequest, BulkStatusRequest, BulkStatusResult, DataScope, ReviewState
from app.services import alert_service, history_service, retrieval_service, review_service

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=AlertList)
def list_alerts(
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    q: str | None = Query(default=None, max_length=100),
    source: str | None = Query(default=None, max_length=64),
    assigned_to: str | None = Query(default=None, max_length=64, description="A user ID, 'unassigned' or 'me'"),
    review_state: ReviewState | None = Query(default=None, description="Derived from the latest persisted review decision"),
    data_scope: DataScope = Query(default="all", description="real = ingested alerts only, demo = synthetic only, all = both"),
    unresolved: bool = Query(default=False, description="Exclude resolved alerts"),
    sort: SortField = "created_at",
    order: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require("alerts:read")),
    session: Session = Depends(get_session),
) -> AlertList:
    if assigned_to == "me":
        if principal.user_id is None:
            raise AppError("INVALID_FILTER", "assigned_to=me needs a signed-in user, not an API key.", 422)
        assigned_to = principal.user_id
    items, total = alert_service.list_alerts(
        session, principal.organization_id, severity, status, q, source, assigned_to, sort, order, limit, offset,
        review_state=review_state, data_scope=data_scope, unresolved=unresolved,
    )
    return AlertList(items=[AlertSummary.model_validate(a, from_attributes=True) for a in items], total=total, limit=limit, offset=offset)


@router.post("/alerts/bulk-status", response_model=BulkStatusResult)
def bulk_status(
    body: BulkStatusRequest, principal: Principal = Depends(require("alerts:write")), session: Session = Depends(get_session)
) -> BulkStatusResult:
    updated, unchanged, missing = alert_service.bulk_update_status(session, principal, body.alert_ids, body.status)
    return BulkStatusResult(updated=updated, unchanged=unchanged, not_found=missing)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> AlertDetail:
    return alert_service.alert_detail(session, alert_service.get_alert(session, principal.organization_id, alert_id))


@router.put("/alerts/{alert_id}/assignee", response_model=AlertDetail)
def assign(
    alert_id: str, body: AssignRequest, principal: Principal = Depends(require("alerts:write")), session: Session = Depends(get_session)
) -> AlertDetail:
    return alert_service.alert_detail(session, alert_service.assign_alert(session, principal, alert_id, body.user_id))


@router.get("/alerts/{alert_id}/related-incidents", response_model=RelatedIncidents)
def related_incidents(
    alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)
) -> RelatedIncidents:
    alert = alert_service.get_alert(session, principal.organization_id, alert_id)
    if not get_settings().enable_historical_retrieval:
        return RelatedIncidents(enabled=False, items=[])
    return RelatedIncidents(enabled=True, items=retrieval_service.find_related_incidents(session, alert))


@router.get("/alerts/{alert_id}/history", response_model=HistoryResponse)
def history(alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> HistoryResponse:
    return history_service.get_history(session, principal.organization_id, alert_id)


@router.post("/alerts/{alert_id}/decisions", response_model=ReviewDecisionOut, status_code=201)
def create_decision(
    alert_id: str, body: DecisionRequest, principal: Principal = Depends(require("alerts:write")), session: Session = Depends(get_session)
) -> ReviewDecisionOut:
    decision = review_service.record_decision(session, principal, alert_id, body)
    out = ReviewDecisionOut.model_validate(decision, from_attributes=True)
    from app.models import User

    user = session.get(User, decision.reviewer_id) if decision.reviewer_id else None
    out.reviewer_name = user.display_name if user else None
    return out
