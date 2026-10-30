"""Investigation report generation: gathers persisted records, renders a PDF, stores it with its history.

Everything comes from existing tables (alert, indicators, evidence, assessments, decisions, audit events).
Nothing is created apart from the report row itself and an audit event. Every query is scoped to the
caller's organization, and the alert is checked first, so one organization can never produce or fetch
another organization's report.
"""
import hashlib
import logging
import uuid

from sqlalchemy.orm import defer
from sqlmodel import Session, func, select

from app.auth.principal import Principal
from app.errors import AppError
from app.models import (
    AlertIndicator,
    Assessment,
    AuditEvent,
    EvidenceItem,
    Integration,
    InvestigationReport,
    Organization,
    ReviewDecision,
    SourceEvent,
    User,
    utcnow,
)
from app.schemas_saas import ReportOut
from app.services import evidence_service, report_pdf
from app.services.alert_service import get_alert
from app.services.audit_service import record_event

logger = logging.getLogger(__name__)


def _report_number() -> str:
    return f"TIQ-{utcnow():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def collect(session: Session, organization_id: str, alert_id: str, report_number: str, classification: str,
            generated_by: str | None) -> report_pdf.ReportData:
    """Load the persisted investigation record for one alert. Read-only."""
    alert = get_alert(session, organization_id, alert_id)  # 404 for a missing alert or another organization's
    org = session.get(Organization, organization_id)
    scope = (lambda model: model.organization_id == organization_id)

    assessments = session.exec(select(Assessment).where(scope(Assessment), Assessment.alert_id == alert.id)
                               .order_by(Assessment.created_at, Assessment.id)).all()
    decisions = session.exec(select(ReviewDecision).where(scope(ReviewDecision), ReviewDecision.alert_id == alert.id)
                             .order_by(ReviewDecision.created_at, ReviewDecision.id)).all()
    events = session.exec(select(AuditEvent).where(scope(AuditEvent), AuditEvent.alert_id == alert.id)
                          .order_by(AuditEvent.created_at, AuditEvent.id)).all()
    evidence = session.exec(select(EvidenceItem).where(scope(EvidenceItem), EvidenceItem.alert_id == alert.id)
                            .order_by(EvidenceItem.source_type, EvidenceItem.source_id)).all()
    # Read directly: the shared helper would compute and save indicators, and a report must not write alert data.
    indicators = session.exec(select(AlertIndicator).where(scope(AlertIndicator), AlertIndicator.alert_id == alert.id)
                              .order_by(AlertIndicator.type, AlertIndicator.value)).all()
    received = session.exec(select(func.min(SourceEvent.received_at)).where(scope(SourceEvent), SourceEvent.alert_id == alert.id)).one()
    integration = session.get(Integration, alert.integration_id) if alert.integration_id else None
    if integration is not None and integration.organization_id != organization_id:
        integration = None

    user_ids = {d.reviewer_id for d in decisions} | {generated_by, alert.assigned_to}
    user_ids |= {e.actor_id for e in events if e.actor_type == "human"}
    user_ids.discard(None)
    names = {u.id: u.display_name for u in session.exec(select(User).where(User.id.in_(user_ids))).all()} if user_ids else {}

    return report_pdf.ReportData(
        organization_name=org.name, report_number=report_number, generated_at=utcnow(), classification=classification,
        generated_by_name=names.get(generated_by), alert=alert, integration=integration, assigned_to_name=names.get(alert.assigned_to),
        indicators=list(indicators), evidence=list(evidence), providers=evidence_service.providers_status(session, org),
        assessments=list(assessments), decisions=list(decisions), events=list(events), user_names=names, received_at=received,
    )


def _to_out(report: InvestigationReport, names: dict[str, str]) -> ReportOut:
    out = ReportOut.model_validate(report, from_attributes=True)
    out.generated_by_name = names.get(report.generated_by or "")
    return out


def generate(session: Session, principal: Principal, alert_id: str, classification: str) -> ReportOut:
    """Render and store a report. A failed attempt is recorded (error code only) and raises REPORT_GENERATION_FAILED."""
    number = _report_number()
    data = collect(session, principal.organization_id, alert_id, number, classification, principal.user_id)
    row = InvestigationReport(
        organization_id=principal.organization_id, alert_id=data.alert.id, report_number=number, classification=classification,
        generated_by=principal.user_id, assessment_id=data.assessments[-1].id if data.assessments else None,
        decision_id=data.decisions[-1].id if data.decisions else None, evidence_count=len(data.evidence),
        created_at=data.generated_at,  # the history and the cover page show the same moment
    )
    try:
        pdf = report_pdf.render(data)
        if not pdf.startswith(b"%PDF"):
            raise RuntimeError("renderer did not produce a PDF")
    except Exception as exc:
        logger.exception("Report generation failed", extra={"alert_id": data.alert.id})
        session.rollback()
        row.status, row.error_code = "failed", type(exc).__name__[:64]
        session.add(row)
        record_event(session, principal.organization_id, data.alert.id, "report_failed", principal.actor_type, principal.actor_id,
                     {"report_number": number, "error_type": type(exc).__name__})
        session.commit()
        raise AppError("REPORT_GENERATION_FAILED", "The report could not be generated. The failure has been recorded; nothing was changed on the alert.", 500)

    row.pdf, row.size_bytes, row.sha256 = pdf, len(pdf), hashlib.sha256(pdf).hexdigest()
    session.add(row)
    record_event(session, principal.organization_id, data.alert.id, "report_generated", principal.actor_type, principal.actor_id,
                 {"report_id": row.id, "report_number": number, "size_bytes": len(pdf), "classification": classification})
    session.commit()
    session.refresh(row)
    return _to_out(row, data.user_names)


def list_reports(session: Session, organization_id: str, alert_id: str) -> list[ReportOut]:
    alert = get_alert(session, organization_id, alert_id)
    rows = session.exec(
        select(InvestigationReport).options(defer(InvestigationReport.pdf))  # never load file bytes for a listing
        .where(InvestigationReport.organization_id == organization_id, InvestigationReport.alert_id == alert.id)
        .order_by(InvestigationReport.created_at.desc(), InvestigationReport.id)
    ).all()
    ids = {r.generated_by for r in rows if r.generated_by}
    names = {u.id: u.display_name for u in session.exec(select(User).where(User.id.in_(ids))).all()} if ids else {}
    return [_to_out(r, names) for r in rows]


def get_file(session: Session, principal: Principal, alert_id: str, report_id: str) -> InvestigationReport:
    """The stored report, only if it belongs to this organization AND this alert. Otherwise indistinguishable from missing."""
    alert = get_alert(session, principal.organization_id, alert_id)
    report = session.get(InvestigationReport, report_id)
    if (report is None or report.organization_id != principal.organization_id or report.alert_id != alert.id
            or report.status != "generated" or not report.pdf):
        raise AppError("REPORT_NOT_FOUND", "The requested report does not exist.", 404)
    record_event(session, principal.organization_id, alert.id, "report_downloaded", principal.actor_type, principal.actor_id,
                 {"report_id": report.id, "report_number": report.report_number})
    session.commit()
    return report
