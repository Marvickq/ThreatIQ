from sqlalchemy import case, exists, func, or_
from sqlmodel import Session, select

from app.auth.principal import Principal
from app.errors import AppError
from app.events import bus
from app.models import Membership, ReviewDecision, SecurityAlert, User, utcnow
from app.schemas import AlertDetail
from app.services.audit_service import record_event

SEVERITY_RANK = case(
    (SecurityAlert.severity == "critical", 4),
    (SecurityAlert.severity == "high", 3),
    (SecurityAlert.severity == "medium", 2),
    else_=1,
)
SORT_COLUMNS = {
    "created_at": SecurityAlert.created_at,
    "last_seen_at": func.coalesce(SecurityAlert.last_seen_at, SecurityAlert.created_at),
    "severity": SEVERITY_RANK,
    "status": SecurityAlert.status,
    "title": SecurityAlert.title,
    "source": SecurityAlert.source,
}


def _escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


REVIEW_STATES = ("unreviewed", "reviewed", "true_positive", "false_positive", "needs_further_review")
DATA_SCOPES = ("real", "demo", "all")


def alert_conditions(
    organization_id: str,
    severity: str | None = None,
    status: str | None = None,
    assigned_to: str | None = None,
    review_state: str | None = None,
    data_scope: str = "real",
    unresolved: bool = False,
) -> list:
    """The one definition of "which alerts", shared by the alert list and every dashboard query.

    Always scoped to one organization. `data_scope` keeps synthetic demo alerts and real ingested
    alerts apart: "real" and "demo" are exclusive and only an explicit "all" mixes them.
    `review_state` comes from persisted review decisions (the latest one), not from workflow status.
    """
    conditions = [SecurityAlert.organization_id == organization_id]
    if data_scope == "real":
        conditions.append(SecurityAlert.is_demo.is_(False))
    elif data_scope == "demo":
        conditions.append(SecurityAlert.is_demo.is_(True))
    if severity:
        conditions.append(SecurityAlert.severity == severity)
    if status:
        conditions.append(SecurityAlert.status == status)
    if unresolved:
        conditions.append(SecurityAlert.status != "resolved")
    if assigned_to == "unassigned":
        conditions.append(SecurityAlert.assigned_to.is_(None))
    elif assigned_to:
        conditions.append(SecurityAlert.assigned_to == assigned_to)
    if review_state:
        decided = exists().where(ReviewDecision.alert_id == SecurityAlert.id)
        if review_state == "unreviewed":
            conditions.append(~decided)
        elif review_state == "reviewed":
            conditions.append(decided)
        else:
            latest = (
                select(ReviewDecision.decision)
                .where(ReviewDecision.alert_id == SecurityAlert.id)
                .order_by(ReviewDecision.created_at.desc(), ReviewDecision.id.desc())
                .limit(1)
                .scalar_subquery()
            )
            conditions.append(latest == review_state)
    return conditions


def list_alerts(
    session: Session,
    organization_id: str,
    severity: str | None = None,
    status: str | None = None,
    q: str | None = None,
    source: str | None = None,
    assigned_to: str | None = None,
    sort: str = "created_at",
    order: str = "desc",
    limit: int = 25,
    offset: int = 0,
    review_state: str | None = None,
    data_scope: str = "all",
    unresolved: bool = False,
) -> tuple[list[SecurityAlert], int]:
    # Every query is scoped to the caller's organization; there is no unscoped variant.
    conditions = alert_conditions(organization_id, severity, status, assigned_to, review_state, data_scope, unresolved)
    if source:
        conditions.append(SecurityAlert.source == source)
    if q and q.strip():
        pattern = f"%{_escape_like(q.strip())}%"
        conditions.append(
            or_(
                SecurityAlert.title.ilike(pattern, escape="\\"),
                SecurityAlert.id.ilike(pattern, escape="\\"),
                SecurityAlert.affected_entity.ilike(pattern, escape="\\"),
                SecurityAlert.description.ilike(pattern, escape="\\"),
            )
        )

    total = session.exec(select(func.count()).select_from(SecurityAlert).where(*conditions)).one()
    column = SORT_COLUMNS.get(sort, SecurityAlert.created_at)
    ordering = column.asc() if order == "asc" else column.desc()
    items = session.exec(
        select(SecurityAlert).where(*conditions).order_by(ordering, SecurityAlert.id).limit(limit).offset(offset)
    ).all()
    return list(items), total


def get_alert(session: Session, organization_id: str, alert_id: str) -> SecurityAlert:
    alert = session.get(SecurityAlert, alert_id)
    # Another organization's alert is reported exactly like a missing one.
    if alert is None or alert.organization_id != organization_id:
        raise AppError("ALERT_NOT_FOUND", "The requested alert does not exist.", 404)
    return alert


def alert_detail(session: Session, alert: SecurityAlert) -> AlertDetail:
    detail = AlertDetail.model_validate(alert, from_attributes=True)
    if alert.assigned_to:
        user = session.get(User, alert.assigned_to)
        detail.assigned_to_name = user.display_name if user else None
    return detail


def bulk_update_status(session: Session, principal: Principal, alert_ids: list[str], status: str) -> tuple[int, int, list[str]]:
    """Analyst-driven workflow changes. Every change is audited with the acting user."""
    alerts = {
        a.id: a
        for a in session.exec(
            select(SecurityAlert).where(SecurityAlert.organization_id == principal.organization_id, SecurityAlert.id.in_(alert_ids))
        ).all()
    }
    updated = unchanged = 0
    changed: list[str] = []
    for alert_id in alert_ids:
        alert = alerts.get(alert_id)
        if alert is None:
            continue
        if alert.status == status:
            unchanged += 1
            continue
        record_event(
            session, alert.organization_id, alert.id, "status_changed", principal.actor_type, principal.actor_id,
            {"from": alert.status, "to": status, "via": "manual"},
        )
        alert.status = status
        alert.updated_at = utcnow()
        session.add(alert)
        changed.append(alert.id)
        updated += 1
    session.commit()
    for alert_id in changed:  # lets other open dashboards refresh
        bus.publish(principal.organization_id, "alert.updated", {"id": alert_id, "reason": "status_changed"})
    return updated, unchanged, [i for i in alert_ids if i not in alerts]


def assign_alert(session: Session, principal: Principal, alert_id: str, user_id: str | None) -> SecurityAlert:
    alert = get_alert(session, principal.organization_id, alert_id)
    if user_id is not None:
        member = session.exec(
            select(Membership).where(Membership.organization_id == principal.organization_id, Membership.user_id == user_id)
        ).first()
        if member is None:
            raise AppError("INVALID_ASSIGNEE", "The assignee must be a member of this organization.", 422)
    previous = alert.assigned_to
    alert.assigned_to = user_id
    alert.updated_at = utcnow()
    session.add(alert)
    record_event(session, alert.organization_id, alert.id, "alert_assigned", principal.actor_type, principal.actor_id,
                 {"from": previous, "to": user_id})
    session.commit()
    bus.publish(alert.organization_id, "alert.updated", {"id": alert.id, "reason": "assignment_changed"})
    return alert
