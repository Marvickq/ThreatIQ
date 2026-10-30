"""Dashboard queries. Everything here is computed from persisted alerts, review decisions and audit events.

All functions take the same `DashboardQuery`, so the metrics, charts and queues on one screen can never
disagree about which alerts they describe. Dates are UTC calendar days throughout.
"""
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import func
from sqlmodel import Session, select

from app.auth.principal import Principal
from app.models import AuditEvent, SecurityAlert, utcnow
from app.schemas_saas import (
    ActivityItem,
    AlertRow,
    DailyAlertCounts,
    DailyCount,
    DashboardFilters,
    DashboardSummary,
    DataSourceCounts,
    InvestigationQueues,
    QueueItem,
    SeverityCount,
    SeverityDistribution,
)
from app.services.alert_service import alert_conditions

SEVERITY_ORDER = ("critical", "high", "medium", "low")
DAILY_WINDOW_DAYS = 14


@dataclass(frozen=True)
class DashboardQuery:
    organization_id: str
    user_id: str | None  # the signed-in user, used to resolve assigned_to="me"; None for API keys
    data_scope: str = "real"
    severity: str | None = None
    status: str | None = None
    assigned_to: str | None = None  # user id, "unassigned" or "me"
    review_state: str | None = None

    @property
    def assignee(self) -> str | None:
        return self.user_id if self.assigned_to == "me" else self.assigned_to

    def conditions(self, **overrides) -> list:
        args = dict(
            severity=self.severity, status=self.status, assigned_to=self.assignee,
            review_state=self.review_state, data_scope=self.data_scope,
        )
        args.update(overrides)
        return alert_conditions(self.organization_id, **args)

    def echo(self) -> DashboardFilters:
        return DashboardFilters(
            data_scope=self.data_scope, severity=self.severity, status=self.status,
            assigned_to=self.assigned_to, review_state=self.review_state,
        )


def _count(session: Session, conditions: list) -> int:
    return session.exec(select(func.count()).select_from(SecurityAlert).where(*conditions)).one()


def summary(session: Session, q: DashboardQuery) -> DashboardSummary:
    where = q.conditions()
    unresolved = _count(session, [*where, SecurityAlert.status != "resolved"])
    high_or_critical = _count(session, [*where, SecurityAlert.severity.in_(("critical", "high"))])
    awaiting = _count(session, [*where, SecurityAlert.status == "awaiting_review"])
    unreviewed = _count(session, q.conditions(review_state="unreviewed")) if q.review_state in (None, "unreviewed") else 0

    recent = session.exec(select(SecurityAlert).where(*where).order_by(SecurityAlert.created_at.desc()).limit(8)).all()
    activity = session.exec(
        select(AuditEvent)
        .join(SecurityAlert, SecurityAlert.id == AuditEvent.alert_id)
        .where(AuditEvent.organization_id == q.organization_id, *where)
        .order_by(AuditEvent.created_at.desc())
        .limit(10)
    ).all()

    return DashboardSummary(
        generated_at=utcnow(),
        filters=q.echo(),
        sources=_source_counts(session, q.organization_id),
        total=_count(session, where),
        unresolved=unresolved,
        high_or_critical=high_or_critical,
        awaiting_review=awaiting,
        unreviewed=unreviewed,
        recent_alerts=[
            AlertRow(id=a.id, title=a.title, severity=a.severity, status=a.status, source=a.source, created_at=a.created_at, is_demo=a.is_demo)
            for a in recent
        ],
        activity=[
            ActivityItem(id=e.id, event_type=e.event_type, actor_type=e.actor_type, alert_id=e.alert_id, created_at=e.created_at)
            for e in activity
        ],
    )


def _source_counts(session: Session, organization_id: str) -> DataSourceCounts:
    rows = dict(
        session.exec(
            select(SecurityAlert.is_demo, func.count()).where(SecurityAlert.organization_id == organization_id).group_by(SecurityAlert.is_demo)
        ).all()
    )
    return DataSourceCounts(real=rows.get(False, 0), demo=rows.get(True, 0))


def severity_distribution(session: Session, q: DashboardQuery) -> SeverityDistribution:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for severity, n in session.exec(
        select(SecurityAlert.severity, func.count()).where(*q.conditions()).group_by(SecurityAlert.severity)
    ).all():
        if severity in counts:
            counts[severity] = n
    return SeverityDistribution(
        generated_at=utcnow(), filters=q.echo(), total=sum(counts.values()),
        items=[SeverityCount(severity=s, count=counts[s]) for s in SEVERITY_ORDER],
    )


def _utc_day(dialect: str):
    # SQLite stores UTC (naive) text, so date() is already the UTC day. PostgreSQL stores timestamptz,
    # and date() would otherwise use the database session's time zone.
    column = SecurityAlert.created_at
    return func.date(func.timezone("UTC", column)) if dialect == "postgresql" else func.date(column)


def daily_counts(session: Session, q: DashboardQuery, days: int = DAILY_WINDOW_DAYS) -> DailyAlertCounts:
    today = utcnow().astimezone(timezone.utc).date()
    first = today - timedelta(days=days - 1)
    start = datetime.combine(first, time.min, tzinfo=timezone.utc)  # whole UTC days, including the first
    day = _utc_day(session.get_bind().dialect.name)
    found = {
        str(d)[:10]: n
        for d, n in session.exec(select(day, func.count()).where(*q.conditions(), SecurityAlert.created_at >= start).group_by(day)).all()
    }
    items = [DailyCount(date=(d := (first + timedelta(days=i)).isoformat()), count=found.get(d, 0)) for i in range(days)]
    return DailyAlertCounts(generated_at=utcnow(), filters=q.echo(), days=days, total=sum(i.count for i in items), items=items)


# key, label, extra alert-list parameters. "unresolved" means status is not "resolved".
_QUEUES: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("critical_open", "Critical, still open", {"severity": "critical", "unresolved": "true"}),
    ("awaiting_review", "Awaiting analyst review", {"status": "awaiting_review"}),
    ("new_unassigned", "New and unassigned", {"status": "new", "assigned_to": "unassigned"}),
    ("assigned_to_me", "Assigned to me", {"assigned_to": "me", "unresolved": "true"}),
)


def queues(session: Session, q: DashboardQuery) -> InvestigationQueues:
    items: list[QueueItem] = []
    for key, label, params in _QUEUES:
        if key == "assigned_to_me" and q.user_id is None:
            continue  # API keys have no "me"
        filters = {"severity": q.severity, "status": q.status, "assigned_to": q.assigned_to, "review_state": q.review_state}
        conflict = any(filters.get(k) not in (None, v) for k, v in params.items() if k != "unresolved")
        conflict = conflict or (params.get("unresolved") == "true" and q.status == "resolved")
        if conflict:  # e.g. the "Resolved" status filter can never contain a still-open alert
            items.append(QueueItem(key=key, label=label, count=0, query=None))
            continue
        merged = {**{k: v for k, v in filters.items() if v}, **params, "data_scope": q.data_scope}
        where = alert_conditions(
            q.organization_id,
            severity=merged.get("severity"), status=merged.get("status"), assigned_to=q.user_id if merged.get("assigned_to") == "me" else merged.get("assigned_to"),
            review_state=merged.get("review_state"), data_scope=q.data_scope, unresolved=merged.get("unresolved") == "true",
        )
        items.append(QueueItem(key=key, label=label, count=_count(session, where), query=merged))
    return InvestigationQueues(generated_at=utcnow(), filters=q.echo(), items=items)


def for_principal(principal: Principal, **filters) -> DashboardQuery:
    return DashboardQuery(organization_id=principal.organization_id, user_id=principal.user_id, **filters)
