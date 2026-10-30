from fastapi import APIRouter, Depends, Query
from sqlmodel import Session

from app.auth.deps import require
from app.auth.principal import Principal
from app.database import get_session
from app.errors import AppError
from app.schemas import AlertStatus, Severity
from app.schemas_saas import (
    DailyAlertCounts,
    DashboardSummary,
    DataScope,
    InvestigationQueues,
    ReviewState,
    SeverityDistribution,
)
from app.services import dashboard_service
from app.services.dashboard_service import DashboardQuery

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def dashboard_query(
    data_scope: DataScope = Query(default="real", description="real = ingested alerts only, demo = synthetic only, all = both (mixed)"),
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    assigned_to: str | None = Query(default=None, max_length=64, description="A user ID, 'unassigned' or 'me'"),
    review_state: ReviewState | None = Query(default=None, description="Derived from the latest persisted review decision"),
    principal: Principal = Depends(require("alerts:read")),
) -> DashboardQuery:
    if assigned_to == "me" and principal.user_id is None:
        raise AppError("INVALID_FILTER", "assigned_to=me needs a signed-in user, not an API key.", 422)
    return dashboard_service.for_principal(
        principal, data_scope=data_scope, severity=severity, status=status, assigned_to=assigned_to, review_state=review_state
    )


@router.get("/summary", response_model=DashboardSummary)
def summary(q: DashboardQuery = Depends(dashboard_query), session: Session = Depends(get_session)) -> DashboardSummary:
    return dashboard_service.summary(session, q)


@router.get("/severity", response_model=SeverityDistribution)
def severity(q: DashboardQuery = Depends(dashboard_query), session: Session = Depends(get_session)) -> SeverityDistribution:
    return dashboard_service.severity_distribution(session, q)


@router.get("/daily", response_model=DailyAlertCounts)
def daily(q: DashboardQuery = Depends(dashboard_query), session: Session = Depends(get_session)) -> DailyAlertCounts:
    """Alerts created per UTC calendar day over the last 14 days, zero days included."""
    return dashboard_service.daily_counts(session, q)


@router.get("/queues", response_model=InvestigationQueues)
def queues(q: DashboardQuery = Depends(dashboard_query), session: Session = Depends(get_session)) -> InvestigationQueues:
    return dashboard_service.queues(session, q)
