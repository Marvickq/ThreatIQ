import re

from fastapi import APIRouter, Depends, Response
from sqlmodel import Session

from app import ratelimit
from app.auth.deps import require
from app.auth.principal import Principal
from app.database import get_session
from app.schemas_saas import GenerateReportRequest, ReportOut
from app.services import report_service

router = APIRouter(tags=["reports"])

REPORTS_PER_MINUTE = 20  # per organization; rendering is CPU work


@router.post("/alerts/{alert_id}/reports", response_model=ReportOut, status_code=201, summary="Generate a PDF investigation report")
def generate_report(
    alert_id: str,
    body: GenerateReportRequest | None = None,
    principal: Principal = Depends(require("alerts:write")),
    session: Session = Depends(get_session),
) -> ReportOut:
    """Builds the report from the alert's stored records and keeps it. Analyst role or an `alerts:write` API key."""
    ratelimit.enforce(f"report:{principal.organization_id}", REPORTS_PER_MINUTE)
    return report_service.generate(session, principal, alert_id, (body or GenerateReportRequest()).classification)


@router.get("/alerts/{alert_id}/reports", response_model=list[ReportOut], summary="Report generation history for an alert")
def list_reports(alert_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session)) -> list[ReportOut]:
    return report_service.list_reports(session, principal.organization_id, alert_id)


@router.get("/alerts/{alert_id}/reports/{report_id}/download", summary="Download a generated report (PDF)")
def download_report(
    alert_id: str, report_id: str, principal: Principal = Depends(require("alerts:read")), session: Session = Depends(get_session),
) -> Response:
    report = report_service.get_file(session, principal, alert_id, report_id)
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", report.report_number) + ".pdf"
    return Response(
        content=report.pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
