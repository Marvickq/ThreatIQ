"""Renders an Incident Investigation Report as a PDF from persisted ThreatIQ records.

Pure presentation: it receives already-loaded records (`ReportData`) and returns PDF bytes. It reads
nothing itself, invents nothing, and states plainly when a record is missing. Rendering uses ReportLab
with the Bitstream Vera fonts that ship inside the ReportLab package, so output is identical on any host
and needs no system fonts.

Layout rules that keep the document from breaking: long text lives in splittable paragraphs, never in
a fixed-height cell; tables repeat their header row and may split inside a row; very long unbroken
tokens (hashes, URLs) are split by the paragraph engine instead of overflowing.
"""
import io
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
)

from app.models import (
    Assessment,
    AuditEvent,
    EvidenceItem,
    Integration,
    InvestigationReport,
    ReviewDecision,
    SecurityAlert,
)
from app.observability import redact

# ------------------------------------------------------------------------------------------ data
NOT_RECORDED = "Not recorded"


@dataclass
class ReportData:
    organization_name: str
    report_number: str
    generated_at: datetime
    classification: str
    generated_by_name: str | None
    alert: SecurityAlert
    integration: Integration | None
    assigned_to_name: str | None
    indicators: list  # AlertIndicator rows
    evidence: list[EvidenceItem]
    providers: list[dict]  # evidence_service.providers_status(): configuration/availability, no secrets
    assessments: list[Assessment]  # oldest first
    decisions: list[ReviewDecision]  # oldest first
    events: list[AuditEvent]  # oldest first
    user_names: dict[str, str] = field(default_factory=dict)
    prior_reports: list[InvestigationReport] = field(default_factory=list)
    received_at: datetime | None = None  # earliest stored source event: when ThreatIQ actually received the alert


# ------------------------------------------------------------------------------------------ design
NAVY = colors.HexColor("#0B1F3A")
INK = colors.HexColor("#1D2939")
MUTED = colors.HexColor("#667085")
ACCENT = colors.HexColor("#0E9AA7")
RULE = colors.HexColor("#D0D5DD")
ZEBRA = colors.HexColor("#F5F7FA")
LABEL_BG = colors.HexColor("#EAF0F6")
SEVERITY = {
    "critical": colors.HexColor("#B42318"), "high": colors.HexColor("#C4320A"),
    "medium": colors.HexColor("#B54708"), "low": colors.HexColor("#027A48"),
}
CALLOUT = {
    "info": (colors.HexColor("#E6F4F6"), ACCENT), "warn": (colors.HexColor("#FEF6E7"), colors.HexColor("#B54708")),
    "alert": (colors.HexColor("#FEECEB"), colors.HexColor("#B42318")), "ok": (colors.HexColor("#E8F6EE"), colors.HexColor("#027A48")),
}

PAGE_W, PAGE_H = A4
MARGIN_X, MARGIN_TOP, MARGIN_BOTTOM = 20 * mm, 24 * mm, 20 * mm
FRAME_W = PAGE_W - 2 * MARGIN_X

_FONTS_REGISTERED = False


def _register_fonts() -> None:
    global _FONTS_REGISTERED
    if _FONTS_REGISTERED:
        return
    folder = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
    for name, file in (("Vera", "Vera.ttf"), ("Vera-Bold", "VeraBd.ttf"), ("Vera-Italic", "VeraIt.ttf"), ("Vera-BoldItalic", "VeraBI.ttf")):
        pdfmetrics.registerFont(TTFont(name, os.path.join(folder, file)))
    pdfmetrics.registerFontFamily("Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic", boldItalic="Vera-BoldItalic")
    _FONTS_REGISTERED = True


def _styles() -> dict[str, ParagraphStyle]:
    def s(name, **kw):
        base = {"fontName": "Vera", "fontSize": 9, "leading": 13, "textColor": INK, "alignment": TA_LEFT, "splitLongWords": 1}
        base.update(kw)
        return ParagraphStyle(name, **base)

    return {
        "body": s("body", spaceAfter=4),
        "small": s("small", fontSize=7.5, leading=10.5, textColor=MUTED, spaceAfter=3),
        "cell": s("cell", fontSize=8.5, leading=11.5),
        "cellb": s("cellb", fontName="Vera-Bold", fontSize=8.5, leading=11.5),
        "mono": s("mono", fontName="Courier", fontSize=8, leading=10.5),
        "th": s("th", fontName="Vera-Bold", fontSize=8, leading=10.5, textColor=colors.white),
        "label": s("label", fontName="Vera-Bold", fontSize=8.5, leading=11.5, textColor=NAVY),
        "muted": s("muted", fontName="Vera-Italic", fontSize=8.5, leading=11.5, textColor=MUTED),
        "h1": s("h1", fontName="Vera-Bold", fontSize=14, leading=18, textColor=NAVY),
        "h2": s("h2", fontName="Vera-Bold", fontSize=10.5, leading=14, textColor=NAVY, spaceBefore=8, spaceAfter=3, keepWithNext=1),
        "quote": s("quote", fontSize=8.5, leading=12, backColor=ZEBRA, borderColor=RULE, borderWidth=0.5, borderPadding=6, leftIndent=6, rightIndent=6, spaceBefore=10, spaceAfter=10),
        "bullet": s("bullet", leftIndent=12, bulletIndent=2, spaceAfter=2),
        "title": s("title", fontName="Vera-Bold", fontSize=26, leading=31, textColor=NAVY),
        "subtitle": s("subtitle", fontSize=13, leading=18, textColor=INK),
    }


# ------------------------------------------------------------------------------------------ text safety
class _Text:
    """Makes arbitrary stored text safe for the PDF without changing its meaning.

    Escapes ReportLab markup, normalises control characters, and replaces any character the embedded
    font cannot draw with '?'. The number of replacements is counted so the report can say so.
    """

    def __init__(self) -> None:
        _register_fonts()
        self._glyphs = pdfmetrics.getFont("Vera").face.charToGlyph
        self.replaced = 0

    def clean(self, value, ascii_only: bool = False) -> str:
        text = "" if value is None else str(value)
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\t", "    ")
        out = []
        for ch in text:
            code = ord(ch)
            if ch == "\n" or (32 <= code < 127):
                out.append(ch)
            elif code < 32 or 127 <= code < 160 or code in (0x200B, 0x200E, 0x200F, 0xFEFF):
                continue  # control / invisible characters carry no readable content
            elif ascii_only or code not in self._glyphs:
                out.append("?")
                self.replaced += 1
            else:
                out.append(ch)
        return "".join(out)

    def markup(self, value, ascii_only: bool = False) -> str:
        return escape(self.clean(value, ascii_only)).replace("\n", "<br/>")


def fmt_dt(value) -> str:
    if value is None:
        return NOT_RECORDED
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
STATUS_LABEL = {"new": "New", "investigating": "Investigating", "awaiting_review": "Awaiting analyst review", "resolved": "Resolved"}
AI_CLASS_LABEL = {"likely_true_positive": "Likely true positive", "likely_false_positive": "Likely false positive", "needs_review": "Needs review"}
DECISION_LABEL = {"true_positive": "True positive", "false_positive": "False positive", "needs_further_review": "Needs further review"}
# What an analyst decision corresponds to in the AI's vocabulary, used only to compare the two.
DECISION_AS_AI = {"true_positive": "likely_true_positive", "false_positive": "likely_false_positive", "needs_further_review": "needs_review"}
SOURCE_LABEL = {
    "alert": "Original alert", "historical_alert": "Historical alert", "demo_incident": "Demo incident (synthetic)",
    "cisa_kev": "CISA KEV", "nvd": "NIST NVD", "virustotal": "VirusTotal",
}
INDICATOR_GROUPS = (
    ("IP addresses", ("ip",)), ("Domains", ("domain",)), ("URLs", ("url",)), ("File hashes", ("md5", "sha1", "sha256")),
    ("CVE identifiers", ("cve",)), ("Accounts", ("account",)), ("Hosts", ("host",)),
)
TIMELINE_LABEL = {
    "alert_created": "Alert received", "alert_occurrence_recorded": "Further occurrence recorded", "severity_changed": "Severity changed",
    "enrichment_completed": "Enrichment performed", "retrieval_completed": "Historical case retrieval completed",
    "assessment_started": "AI analysis started", "assessment_completed": "AI assessment generated", "assessment_failed": "AI analysis failed",
    "status_changed": "Status changed", "alert_assigned": "Alert assignment changed", "decision_recorded": "Analyst decision recorded",
    "auto_triage_enqueued": "Automatic triage queued", "auto_triage_started": "Automatic triage started",
    "auto_triage_completed": "Automatic triage completed", "auto_triage_failed": "Automatic triage failed",
    "auto_triage_skipped": "Automatic triage skipped", "report_generated": "Investigation report generated",
    "report_downloaded": "Investigation report downloaded",
}


# ------------------------------------------------------------------------------------------ canvas
class _NumberedCanvas(canvas.Canvas):
    """Draws header, footer and 'Page X of Y' once the total page count is known. The cover is left clean."""

    def __init__(self, *args, meta: dict, **kwargs):
        super().__init__(*args, **kwargs)
        self._meta = meta
        self._saved: list[dict] = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self._chrome(total)
            super().showPage()
        super().save()

    def _chrome(self, total: int) -> None:
        m = self._meta
        self.saveState()
        self.setStrokeColor(RULE)
        self.setLineWidth(0.6)
        self.line(MARGIN_X, PAGE_H - 15 * mm, PAGE_W - MARGIN_X, PAGE_H - 15 * mm)
        self.setFillColor(NAVY)
        self.setFont("Vera-Bold", 8.5)
        self.drawString(MARGIN_X, PAGE_H - 12 * mm, "ThreatIQ")
        self.setFillColor(MUTED)
        self.setFont("Vera", 8)
        self.drawString(MARGIN_X + pdfmetrics.stringWidth("ThreatIQ", "Vera-Bold", 8.5) + 8, PAGE_H - 12 * mm, "Incident Investigation Report")
        self.setFillColor(SEVERITY["critical"])
        self.setFont("Vera-Bold", 7.5)
        self.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 12 * mm, m["classification"].upper())
        self.setStrokeColor(RULE)
        self.line(MARGIN_X, 14 * mm, PAGE_W - MARGIN_X, 14 * mm)
        self.setFillColor(MUTED)
        self.setFont("Vera", 7.5)
        self.drawString(MARGIN_X, 9.5 * mm, f"{m['report_number']}  |  {m['organization']}")
        self.drawRightString(PAGE_W - MARGIN_X, 9.5 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _draw_cover(c: canvas.Canvas, doc) -> None:
    c.saveState()
    c.setFillColor(NAVY)
    c.rect(0, PAGE_H - 92 * mm, PAGE_W, 92 * mm, stroke=0, fill=1)
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - 94 * mm, PAGE_W, 2 * mm, stroke=0, fill=1)
    # Shield mark, drawn as vector so no image asset is needed.
    x, y, w, h = MARGIN_X, PAGE_H - 52 * mm, 17 * mm, 20 * mm
    p = c.beginPath()
    p.moveTo(x + w / 2, y + h)
    p.lineTo(x + w, y + h * 0.82)
    p.lineTo(x + w, y + h * 0.45)
    p.curveTo(x + w, y + h * 0.18, x + w * 0.7, y + h * 0.06, x + w / 2, y)
    p.curveTo(x + w * 0.3, y + h * 0.06, x, y + h * 0.18, x, y + h * 0.45)
    p.lineTo(x, y + h * 0.82)
    p.close()
    c.setFillColor(ACCENT)
    c.drawPath(p, stroke=0, fill=1)
    c.setFillColor(NAVY)
    c.setFont("Vera-Bold", 17)
    c.drawCentredString(x + w / 2, y + h * 0.36, "IQ")
    c.setFillColor(colors.white)
    c.setFont("Vera-Bold", 28)
    c.drawString(x + w + 6 * mm, PAGE_H - 44 * mm, "ThreatIQ")
    c.setFont("Vera", 10.5)
    c.setFillColor(colors.HexColor("#B8C7DA"))
    c.drawString(x + w + 6 * mm, PAGE_H - 52 * mm, "Alert investigation platform")
    c.restoreState()


# ------------------------------------------------------------------------------------------ builder
class _Builder:
    def __init__(self, data: ReportData) -> None:
        _register_fonts()
        self.d = data
        self.t = _Text()
        self.st = _styles()
        self.story: list = []
        self.alert = data.alert
        self.latest_assessment = data.assessments[-1] if data.assessments else None
        self.latest_decision = data.decisions[-1] if data.decisions else None
        self.evidence_refs = {(e.source_type, e.source_id) for e in data.evidence}
        self.sections = 0

    # ---- primitives
    def P(self, value, style="cell", ascii_only=False) -> Paragraph:
        return Paragraph(self.t.markup(value, ascii_only), self.st[style])

    def rich(self, markup: str, style="cell") -> Paragraph:
        """Paragraph from markup the builder wrote itself (never from stored text)."""
        return Paragraph(markup, self.st[style])

    def val(self, value, style="cell"):
        if value is None or str(value).strip() == "":
            return self.P(NOT_RECORDED, "muted")
        return self.P(value, style)

    def h1(self, title: str) -> None:
        self.sections += 1
        head = Table([[self.P(f"{self.sections}.  {title}", "h1")]], colWidths=[FRAME_W])
        head.setStyle([("LINEBELOW", (0, 0), (-1, -1), 1.4, ACCENT), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                       ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 0)])
        head.keepWithNext = True
        gap = Spacer(1, 3 * mm)
        gap.keepWithNext = True  # a heading must stay with what follows it
        self.story += [Spacer(1, 4 * mm), head, gap]

    def h2(self, title: str) -> None:
        self.story.append(self.P(title, "h2"))

    def text(self, value, style="body") -> None:
        self.story.append(self.P(value, style))

    def callout(self, message: str, kind="info", title: str | None = None) -> None:
        bg, edge = CALLOUT[kind]
        inner = [self.P(title, "cellb")] if title else []
        inner.append(self.P(message, "cell"))
        box = Table([[inner]], colWidths=[FRAME_W])
        box.setStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3, edge),
                      ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                      ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)])
        self.story += [box, Spacer(1, 3 * mm)]

    def kv(self, rows: list[tuple[str, object]], label_w: float = 0.27) -> None:
        data = [[self.P(k, "label"), v if not isinstance(v, str) and v is not None else self.val(v)] for k, v in rows]
        tbl = Table(data, colWidths=[FRAME_W * label_w, FRAME_W * (1 - label_w)], splitInRow=1)
        tbl.setStyle([("BACKGROUND", (0, 0), (0, -1), LABEL_BG), ("GRID", (0, 0), (-1, -1), 0.4, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                      ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                      ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])
        self.story += [tbl, Spacer(1, 3 * mm)]

    def grid(self, header: list[str], rows: list[list], widths: list[float]) -> None:
        total = sum(widths)
        cols = [FRAME_W * w / total for w in widths]
        data = [[self.P(h, "th") for h in header]] + rows
        tbl = Table(data, colWidths=cols, repeatRows=1, splitInRow=1)
        style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                 ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]
        style += [("BACKGROUND", (0, i), (-1, i), ZEBRA) for i in range(2, len(data), 2)]
        tbl.setStyle(style)
        self.story += [tbl, Spacer(1, 3 * mm)]

    def bullets(self, items: list, empty: str) -> None:
        items = [i for i in (items or []) if str(i).strip()]
        if not items:
            self.text(empty, "muted")
            return
        for item in items:
            self.story.append(Paragraph(self.t.markup(item), self.st["bullet"], bulletText="•"))
        self.story.append(Spacer(1, 2 * mm))

    def person(self, user_id: str | None) -> str:
        return self.d.user_names.get(user_id or "", "") or NOT_RECORDED

    def actor(self, e: AuditEvent) -> str:
        if e.actor_type == "human":
            return self.person(e.actor_id) if e.actor_id else "Analyst"
        if e.actor_type == "ai":
            return f"AI model ({e.actor_id})" if e.actor_id else "AI model"
        return "ThreatIQ system"

    def severity_chip(self, severity: str) -> Table:
        chip = Table([[Paragraph(f"<font color='white'><b>{escape(SEVERITY_LABEL.get(severity, severity.title()))}</b></font>", self.st["cell"])]],
                     colWidths=[24 * mm])
        chip.setStyle([("BACKGROUND", (0, 0), (-1, -1), SEVERITY.get(severity, MUTED)), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                       ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)])
        chip.hAlign = "LEFT"
        return chip

    # ---- sections
    def cover(self) -> None:
        d, a = self.d, self.alert
        self.story += [Spacer(1, 102 * mm), self.P("Incident Investigation Report", "title"), Spacer(1, 4 * mm)]
        self.story += [self.P(a.title, "subtitle"), Spacer(1, 12 * mm)]
        self.kv([
            ("Organization", d.organization_name), ("Report ID", d.report_number), ("Alert ID", a.id),
            ("Generated", fmt_dt(d.generated_at)), ("Prepared by", d.generated_by_name),
            ("Classification", d.classification.upper()),
        ], label_w=0.3)
        self.story += [Spacer(1, 8 * mm)]
        self.callout(
            "This report contains security-relevant information about an organization's systems and alerts. Distribute only to people "
            "authorised to receive it, in line with the classification above. It is a point-in-time snapshot of records held in ThreatIQ.",
            "warn", title=f"{d.classification.upper()}",
        )
        self.story += [NextPageTemplate("body"), PageBreak()]

    def executive_summary(self) -> None:
        a, d = self.alert, self.d
        self.h1("Executive summary")
        source = a.source + (f" (integration: {d.integration.name}, {d.integration.kind})" if d.integration else "")
        ai = self.latest_assessment
        ai_text = (f"{AI_CLASS_LABEL.get(ai.suggested_classification, ai.suggested_classification)}  (AI-generated, assessment v{ai.version}, {fmt_dt(ai.created_at)})"
                   if ai else "No AI assessment has been generated for this alert.")
        dec = self.latest_decision
        dec_text = (f"{DECISION_LABEL.get(dec.decision, dec.decision)}  (by {self.person(dec.reviewer_id)}, {fmt_dt(dec.created_at)})"
                    if dec else "No analyst decision has been recorded.")
        self.kv([
            ("Alert title", a.title), ("Severity", self.severity_chip(a.severity)), ("Source", source),
            ("Investigation status", STATUS_LABEL.get(a.status, a.status)),
            ("AI-suggested classification", ai_text), ("Analyst final decision", dec_text),
        ])
        if dec:
            self.callout(f"An analyst has reviewed this alert. The recorded decision is '{DECISION_LABEL.get(dec.decision, dec.decision)}'. "
                         "The analyst decision, not the AI suggestion, is the investigation outcome.", "ok", title="Reviewed by an analyst")
        elif ai:
            self.callout("The AI assessment in this report has NOT been reviewed by an analyst. Treat it as an unverified suggestion.",
                         "warn", title="Awaiting analyst review")
        else:
            self.callout("No AI assessment and no analyst decision exist for this alert. This report documents the alert and any "
                         "stored enrichment only.", "info", title="Not yet investigated")

    def alert_details(self) -> None:
        a, d = self.alert, self.d
        self.h1("Alert details")
        self.kv([
            ("Alert ID", a.id), ("External ID (source)", a.external_id), ("Source", a.source),
            ("Source integration", f"{d.integration.name} ({d.integration.kind})" if d.integration else None),
            ("Affected host / entity", a.affected_entity),
            ("First seen", fmt_dt(a.first_seen_at or a.created_at)), ("Last seen", fmt_dt(a.last_seen_at or a.created_at)),
            ("Received by ThreatIQ", fmt_dt(d.received_at) if d.received_at else None), ("Occurrences", str(a.occurrence_count)),
            ("Assigned to", d.assigned_to_name), ("Indicators extracted", f"{len(d.indicators)} (listed in section 3)"),
        ])
        self.h2("Original alert description")
        self.text("Shown exactly as received from the source. This is source data, not AI output.", "small")
        self.story.append(self.P(a.description or "(empty)", "quote"))

    def evidence(self) -> None:
        d = self.d
        self.h1("Evidence and threat intelligence")
        # 3.1 indicators
        self.h2("3.1  Extracted indicators")
        if not d.indicators:
            self.text("No indicators are stored for this alert.", "muted")
        else:
            rows = []
            for label, kinds in INDICATOR_GROUPS:
                values = sorted({i.value for i in d.indicators if i.type in kinds})
                if values:
                    rows.append([self.P(label, "cellb"), self.P("\n".join(values), "mono", ascii_only=True)])
            self.grid(["Type", "Values"], rows, [24, 76])
        cves = sorted({i.value for i in d.indicators if i.type == "cve"})
        prov = {p["provider"]: p for p in d.providers}
        # 3.2 provider results
        self.h2("3.2  Threat-intelligence lookups")
        for key in ("cisa_kev", "nvd", "virustotal"):
            self.provider_block(key, prov.get(key), cves)
        # 3.3 historical
        self.h2("3.3  Related historical cases")
        hist = [e for e in d.evidence if e.source_type in ("historical_alert", "demo_incident")]
        if not hist:
            self.text("No related historical cases are stored for this alert. Retrieval may not have run, or no earlier case matched.", "muted")
        else:
            rows = []
            for e in hist:
                c = e.content or {}
                desc = str(c.get("description", ""))
                if len(desc) > 500:
                    desc = desc[:500] + " ... [truncated in this report]"
                rows.append([
                    self.P(f"{SOURCE_LABEL.get(e.source_type, e.source_type)}\n{e.source_id}", "cell"),
                    self.P(desc or NOT_RECORDED), self.P(c.get("recorded_outcome") or NOT_RECORDED),
                    self.P(", ".join(c.get("retrieved_by") or []) or NOT_RECORDED),
                    self.P(c.get("reliability") or NOT_RECORDED),
                ])
            self.grid(["Case", "Description", "Recorded outcome", "Matched by", "Reliability"], rows, [18, 33, 16, 11, 22])
            self.text("Historical cases are context, not proof of the same cause.", "small")
        # 3.4 register
        self.h2("3.4  Evidence register and retrieval provenance")
        if not d.evidence:
            self.text("No evidence records are stored for this alert (no enrichment or analysis has been run).", "muted")
        else:
            rows = []
            for e in d.evidence:
                rows.append([
                    self.P(f"{e.source_type}:{e.source_id}", "mono", ascii_only=True),
                    self.P({"found": "Found", "not_found": "No record", "error": "Provider error"}.get(e.provider_status, e.provider_status)),
                    self.P(fmt_dt(e.retrieved_at)), self.P((e.content_hash or "")[:10], "mono", ascii_only=True),
                    self.val(e.url, "mono"),
                ])
            self.grid(["Reference", "Result", "Retrieved", "Content hash", "Source URL"], rows, [30, 10, 18, 14, 28])
            self.text("Content hash: first 10 characters of the SHA-256 of the stored evidence content, so a record can be matched to what was analysed.", "small")

    def provider_block(self, key: str, status: dict | None, cves: list[str]) -> None:
        name = SOURCE_LABEL[key]
        items = [e for e in self.d.evidence if e.source_type == key]
        state = (status or {}).get("detail", "Provider state is unknown.")
        self.story.append(self.rich(f"<b>{escape(name)}</b>", "body"))
        if not items:
            if key in ("cisa_kev", "nvd") and not cves:
                msg = "No CVE identifiers were extracted from this alert, so no lookup applied."
            elif key == "virustotal" and status and not status.get("configured"):
                msg = "VirusTotal is not configured for this deployment. No VirusTotal results are available."
            elif status and not status.get("available"):
                msg = "This provider was not available to this organization, so it was not queried."
            else:
                msg = "No lookup result is stored for this provider."
            self.text(f"{msg}  Provider state: {state}", "muted")
            return
        rows = []
        for e in items:
            rows.append([self.P(e.source_id, "mono", ascii_only=True), self.P(self.result_text(e)), self.P(fmt_dt(e.retrieved_at))])
        self.grid(["Subject", "Result", "Retrieved"], rows, [20, 62, 18])

    def result_text(self, e: EvidenceItem) -> str:
        c = e.content or {}
        if c.get("_stored_externally"):
            return "The full result is held in ThreatIQ's artifact store and is not embedded in this report."
        if e.provider_status == "error":
            return "Lookup failed: " + redact(str(c.get("error", "unknown error")))[:300] + "\nThis is a provider failure, not a finding about the indicator."
        if e.provider_status == "not_found":
            return "No record at this provider.\nThe absence of a record does not show the activity is benign."
        if e.source_type == "cisa_kev":
            return "\n".join(x for x in (
                f"In the CISA Known Exploited Vulnerabilities catalog: {c.get('name') or c.get('cve') or ''}",
                f"Vendor / product: {c.get('vendor') or NOT_RECORDED} / {c.get('product') or NOT_RECORDED}",
                f"Date added: {c.get('date_added') or NOT_RECORDED}",
                f"Due date: {c.get('due_date') or NOT_RECORDED}",
                f"Known ransomware use: {c.get('known_ransomware_use') or NOT_RECORDED}",
                f"Required action: {c.get('required_action') or NOT_RECORDED}",
            ) if x)
        if e.source_type == "nvd":
            cvss = c.get("cvss") or {}
            score = f"CVSS {cvss.get('version')}: {cvss.get('score')} ({cvss.get('severity')})" if cvss else "CVSS: " + NOT_RECORDED
            return "\n".join((f"NVD status: {c.get('status') or NOT_RECORDED}", f"Published: {c.get('published') or NOT_RECORDED}", score,
                              f"Description: {c.get('description') or NOT_RECORDED}"))
        if e.source_type == "virustotal":
            stats = c.get("last_analysis_stats") or {}
            parts = ", ".join(f"{k}: {v}" for k, v in stats.items()) or NOT_RECORDED
            return f"Analysis stats: {parts}\nReputation: {c.get('reputation') if c.get('reputation') is not None else NOT_RECORDED}"
        return "Found."

    def ai_investigation(self) -> None:
        self.h1("AI investigation")
        ai = self.latest_assessment
        if not ai:
            self.callout("No AI assessment has been generated for this alert, so there is no AI analysis to report.", "info", title="No AI assessment")
            return
        self.callout("Everything in this section was generated by an AI model from the stored evidence. It is advice for an analyst and has "
                     "not been independently verified unless an analyst review is shown in section 5.", "warn", title="AI-generated content")
        self.kv([
            ("Suggested classification", AI_CLASS_LABEL.get(ai.suggested_classification, ai.suggested_classification)),
            ("Model", ai.model_name), ("Prompt version", ai.prompt_version),
            ("Assessment version", f"{ai.version} of {len(self.d.assessments)}"), ("Generated", fmt_dt(ai.created_at)),
            ("Evidence items supplied", str(len(ai.evidence_ids or []))),
        ])
        self.h2("Summary")
        self.text(ai.summary)
        self.h2("Observed facts")
        self.text("Statements the model reports as taken directly from the supplied evidence.", "small")
        self.bullets(ai.observed_facts, "No observed facts were recorded.")
        self.h2("Interpretation")
        self.text("The model's reasoning about what the facts may mean. This is inference, not established fact.", "small")
        if ai.interpretation:
            self.text(ai.interpretation)
        else:
            self.text("No interpretation was recorded.", "muted")
        self.h2("Missing information")
        self.bullets(ai.missing_information, "The model listed no missing information.")
        self.h2("Recommended next steps")
        self.text("Guidance for the analyst. ThreatIQ does not carry out any of these steps.", "small")
        self.bullets(ai.recommended_steps, "No next steps were recorded.")
        self.h2("Evidence citations")
        cites = ai.evidence or []
        if not cites:
            self.text("The model cited no evidence for this assessment.", "muted")
        else:
            self.text("Each citation was checked against the evidence package when the assessment was created, and is checked again against the "
                      "stored evidence when this report is generated.", "small")
            rows = []
            for n, c in enumerate(cites, start=1):
                ref = (c.get("source_type"), c.get("source_id"))
                ok = ref in self.evidence_refs
                rows.append([
                    self.P(str(n)), self.P(f"{ref[0]}:{ref[1]}", "mono", ascii_only=True), self.P(c.get("claim")), self.P(c.get("evidence")),
                    self.rich("<font color='#027A48'><b>Matches stored evidence</b></font>" if ok
                              else "<font color='#B42318'><b>Not found in stored evidence</b></font>"),
                ])
            self.grid(["#", "Source", "Claim", "Quoted evidence", "Check"], rows, [4, 20, 28, 32, 16])
        if len(self.d.assessments) > 1:
            self.h2("Assessment history")
            rows = [[self.P(f"v{a.version}"), self.P(fmt_dt(a.created_at)), self.P(AI_CLASS_LABEL.get(a.suggested_classification, a.suggested_classification)),
                     self.P(a.model_name)] for a in reversed(self.d.assessments)]
            self.grid(["Version", "Generated", "Suggested classification", "Model"], rows, [12, 30, 36, 22])
            self.text("Only the latest assessment is detailed above. Earlier versions are preserved in ThreatIQ.", "small")

    def analyst_review(self) -> None:
        self.h1("Analyst review")
        decs = self.d.decisions
        if not decs:
            self.callout("No analyst decision has been recorded for this alert. There is no final classification, reviewer note or review "
                         "timestamp to report. Until an analyst reviews it, the AI output in this report is unverified.", "warn", title="No analyst decision")
            return
        by_id = {a.id: a for a in self.d.assessments}
        rows = []
        for dec in reversed(decs):
            linked = by_id.get(dec.assessment_id) if dec.assessment_id else None
            if linked is None:
                rel = "Not compared (no linked assessment)"
            elif DECISION_AS_AI.get(dec.decision) == linked.suggested_classification:
                rel = f"Consistent with the AI suggestion (v{linked.version}: {AI_CLASS_LABEL.get(linked.suggested_classification)})"
            else:
                rel = (f"Differs from the AI suggestion (v{linked.version}: {AI_CLASS_LABEL.get(linked.suggested_classification)}); "
                       "the AI recommendation was not adopted")
            rows.append([self.P(fmt_dt(dec.created_at)), self.P(self.person(dec.reviewer_id)), self.P(DECISION_LABEL.get(dec.decision, dec.decision), "cellb"),
                         self.P(rel), self.val(dec.reviewer_note)])
        final = decs[-1]
        self.kv([
            ("Final classification", DECISION_LABEL.get(final.decision, final.decision)), ("Reviewer", self.person(final.reviewer_id)),
            ("Review timestamp", fmt_dt(final.created_at)), ("Reviewer notes", final.reviewer_note),
        ])
        self.h2("All recorded decisions (newest first)" if len(decs) > 1 else "Recorded decision")
        self.grid(["Recorded", "Reviewer", "Decision", "Relation to AI suggestion", "Reviewer notes"], rows, [17, 14, 14, 29, 26])
        self.text("The relation is derived by comparing the recorded decision with the linked AI assessment. ThreatIQ does not store a separate "
                  "accept or reject action.", "small")

    def timeline(self) -> None:
        d, a = self.d, self.alert
        self.h1("Investigation timeline")

        def first(*types):
            return next((e for e in d.events if e.event_type in types), None)

        def stamp(e):
            return fmt_dt(e.created_at) if e else NOT_RECORDED

        if d.received_at:
            received = f"{fmt_dt(d.received_at)} (received by ThreatIQ)"
        elif first("alert_created"):
            received = f"{fmt_dt(first('alert_created').created_at)} (alert record)"
        else:
            received = f"{fmt_dt(a.first_seen_at or a.created_at)} (alert record)"
        enrich = first("enrichment_completed")
        pulled = sorted(e.retrieved_at for e in d.evidence if e.source_type in ("cisa_kev", "nvd", "virustotal") and e.retrieved_at)
        if enrich:
            enriched = fmt_dt(enrich.created_at)
        elif pulled:  # analysis enriches as its first step without a separate audit event
            enriched = f"{fmt_dt(pulled[0])} (earliest provider result stored; no enrichment event in the audit log)"
        else:
            enriched = NOT_RECORDED
        self.h2("Milestones")
        self.grid(["Milestone", "Time (UTC)"], [
            [self.P("Alert received"), self.P(received)],
            [self.P("Enrichment performed"), self.P(enriched)],
            [self.P("AI analysis started"), self.P(stamp(first("assessment_started")))],
            [self.P("AI analysis completed / assessment generated"), self.P(stamp(first("assessment_completed")))],
            [self.P("Analyst decision recorded"), self.P(stamp(first("decision_recorded")))],
        ], [45, 55])
        self.h2("Recorded events")
        if not d.events:
            self.text("No audit events are recorded for this alert.", "muted")
            return
        rows = [[self.P(fmt_dt(e.created_at)), self.P(self.actor(e)), self.P(self.event_text(e))] for e in d.events]
        self.grid(["Time (UTC)", "Actor", "Event"], rows, [29, 23, 48])
        self.text("Timeline entries come from ThreatIQ's append-only audit log. Alert content is not repeated here.", "small")

    def event_text(self, e: AuditEvent) -> str:
        det = e.details or {}
        label = TIMELINE_LABEL.get(e.event_type, e.event_type.replace("_", " ").capitalize())
        extra = ""
        if e.event_type == "alert_created" and det.get("source"):
            extra = f" from {det['source']} (source event time)"
        elif e.event_type == "alert_occurrence_recorded":
            extra = f" (occurrence {det.get('occurrence_count')}, {det.get('outcome')})"
        elif e.event_type == "severity_changed":
            extra = f": {det.get('from')} to {det.get('to')}"
        elif e.event_type == "status_changed":
            extra = f": {STATUS_LABEL.get(det.get('from'), det.get('from'))} to {STATUS_LABEL.get(det.get('to'), det.get('to'))}"
        elif e.event_type == "enrichment_completed":
            extra = f": {det.get('items', 0)} evidence item(s) from {', '.join(det.get('providers') or []) or 'no providers'}"
        elif e.event_type == "retrieval_completed":
            extra = f": mode {det.get('mode')}, {det.get('cases_supplied', 0)} case(s) supplied"
        elif e.event_type == "assessment_completed":
            extra = f": {AI_CLASS_LABEL.get(det.get('suggested_classification'), det.get('suggested_classification'))} (v{det.get('version')})"
        elif e.event_type == "assessment_failed":
            extra = f" (error code {det.get('error_code')})"
        elif e.event_type == "decision_recorded":
            extra = f": {DECISION_LABEL.get(det.get('decision'), det.get('decision'))}"
        elif e.event_type in ("auto_triage_failed", "auto_triage_skipped"):
            extra = f" ({det.get('error_code') or det.get('reason') or det.get('stage') or 'see audit log'})"
        elif e.event_type in ("report_generated", "report_downloaded") and det.get("report_number"):
            extra = f" ({det['report_number']})"
        return label + extra

    def limitations(self) -> None:
        d, a = self.d, self.alert
        self.h1("Limitations and disclaimer")
        self.h2("Facts, interpretation and verification")
        self.bullets([
            ("Observed facts in this report are stored records: the alert as received, threat-intelligence results exactly as retrieved, and "
             "analyst decisions. They are shown with their source and time."),
            "AI interpretation (section 4) is the model's inference from that evidence. It is separate from fact and can be wrong or incomplete.",
            "AI recommendations are not independently verified unless an analyst has reviewed them. "
            + (f"An analyst review by {self.person(self.latest_decision.reviewer_id)} is recorded on {fmt_dt(self.latest_decision.created_at)}."
               if self.latest_decision else "No analyst review is recorded for this alert."),
            "'No record' from a threat-intelligence provider means the provider holds no entry. It is not evidence that an indicator is safe.",
        ], "")
        self.h2("Evidence not available for this report")
        gaps = self.gaps()
        self.bullets(gaps, "No gaps were identified in the stored records beyond what this report already states.")
        self.h2("Scope of ThreatIQ")
        self.bullets([
            (f"The alert was raised by '{a.source}'. ThreatIQ received it and supports its investigation. ThreatIQ did not detect the underlying "
             "activity, and this report does not state that any attack was detected, blocked or prevented by ThreatIQ."),
            ("ThreatIQ takes no response actions. Any containment or remediation described as a recommended step must be decided and carried out "
             "by people and other tools."),
            f"This report is a snapshot generated at {fmt_dt(d.generated_at)}. Alert, assessment and decision records may change after that time.",
        ], "")
        if self.t.replaced:
            self.bullets([(f"{self.t.replaced} character(s) in the stored text could not be drawn with this report's font (for example non-Latin "
                           "scripts) and are shown as '?'. The stored records are unchanged.")], "")

    def gaps(self) -> list[str]:
        d = self.d
        out = []
        cves = [i for i in d.indicators if i.type == "cve"]
        by_type = {k: [e for e in d.evidence if e.source_type == k] for k in ("cisa_kev", "nvd", "virustotal")}
        prov = {p["provider"]: p for p in d.providers}
        if not d.indicators:
            out.append("No indicators are stored, so no indicator-based lookups could apply.")
        if not [e for e in d.evidence if e.source_type != "alert"]:
            out.append("No enrichment or historical evidence is stored. Enrichment or analysis may not have been run.")
        if cves and not by_type["cisa_kev"]:
            out.append("CVE identifiers were extracted but no CISA KEV result is stored.")
        if cves and not by_type["nvd"]:
            nvd = prov.get("nvd")
            out.append("CVE identifiers were extracted but no NIST NVD result is stored." + (" External enrichment is disabled for this organization." if nvd and not nvd.get("available") else ""))
        vt = prov.get("virustotal")
        if not by_type["virustotal"]:
            out.append("VirusTotal: no results. " + ("It is not configured for this deployment." if vt and not vt.get("configured") else
                                                   "It is disabled for this organization." if vt and not vt.get("available") else "No lookup is stored."))
        for e in d.evidence:
            if e.provider_status == "error":
                out.append(f"{SOURCE_LABEL.get(e.source_type, e.source_type)} lookup for {e.source_id} failed, so that evidence is unavailable.")
        if not [e for e in d.evidence if e.source_type in ("historical_alert", "demo_incident")]:
            out.append("No related historical cases are stored.")
        if not d.assessments:
            out.append("No AI assessment exists.")
        elif d.assessments[-1].missing_information:
            out.append("The AI model reported missing information (section 4).")
        if not d.decisions:
            out.append("No analyst decision exists.")
        out.append("Endpoint, network and log telemetry beyond the alert fields are not part of ThreatIQ's stored records and are not included.")
        return out


def render(data: ReportData) -> bytes:
    """Build the PDF. Raises on any rendering problem; the caller records the failure."""
    b = _Builder(data)
    b.cover()
    b.executive_summary()
    b.alert_details()
    b.evidence()
    b.ai_investigation()
    b.analyst_review()
    b.timeline()
    b.limitations()

    buf = io.BytesIO()
    meta = {"classification": data.classification, "report_number": data.report_number, "organization": b.t.clean(data.organization_name)[:60]}
    doc = BaseDocTemplate(
        buf, pagesize=A4, title=f"ThreatIQ Incident Investigation Report {data.report_number}", author="ThreatIQ",
        subject=f"Investigation of alert {data.alert.id}", creator="ThreatIQ", leftMargin=MARGIN_X, rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP, bottomMargin=MARGIN_BOTTOM,
    )
    cover = Frame(MARGIN_X, MARGIN_BOTTOM, FRAME_W, PAGE_H - MARGIN_BOTTOM - 10 * mm, id="cover", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    body = Frame(MARGIN_X, MARGIN_BOTTOM, FRAME_W, PAGE_H - MARGIN_TOP - MARGIN_BOTTOM + 6 * mm, id="body", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="cover", frames=[cover], onPage=_draw_cover), PageTemplate(id="body", frames=[body])])
    doc.build(b.story, canvasmaker=lambda *a, **k: _NumberedCanvas(*a, meta=meta, **k))
    return buf.getvalue()
