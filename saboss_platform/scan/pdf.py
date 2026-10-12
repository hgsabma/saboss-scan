"""PDF export of a scan report (reportlab).

reportlab's Paragraph understands a small XML-like markup, so every value from
the scanned website is escaped first; otherwise a hostile header value could
break or alter the document.
"""

from __future__ import annotations

from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

STATUS_LABELS = {
    "pass": "Pass",
    "warning": "Warning",
    "fail": "Fail",
    "not_checked": "Not checked",
    "not_applicable": "N/A",
}
STATUS_COLORS = {
    "pass": colors.HexColor("#1a7f37"),
    "warning": colors.HexColor("#8a5a00"),
    "fail": colors.HexColor("#b42318"),
}
CATEGORY_TITLES = {
    "tls": "HTTPS / TLS",
    "http_headers": "HTTP security",
    "dns": "DNS",
    "email": "E-mail security",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _t(value: Any) -> str:
    """Escape text for reportlab and drop characters the base fonts cannot draw."""
    text = "" if value is None else str(value)
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    return escape(text, quote=False)  # reportlab markup only needs &, < and > escaped


def render_pdf(report: dict[str, Any], scope_note: str = "") -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"Saboss Scan report: {report['domain']}",
        author="Saboss Scan",
    )
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8.5, leading=11)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    h1, h2 = styles["Title"], styles["Heading2"]
    score = report["score"]

    story: list[Any] = [
        Paragraph("Saboss Scan - Security report", small),
        Paragraph(_t(report["domain"]), h1),
        Paragraph(
            f"Scanned {_t(report.get('scanned_at'))} UTC with Saboss Scan {_t(report.get('version'))}. "
            f"{score['checks_completed']} of {score['checks_total']} applicable checks completed "
            f"({score.get('coverage', 0)}% coverage).",
            small,
        ),
        Spacer(1, 6 * mm),
        Paragraph("Executive summary", h2),
    ]

    if score["percentage"] is None:
        headline = "No score could be calculated because no checks completed."
    else:
        headline = f"Overall grade <b>{_t(score['grade'])}</b> ({score['percentage']}%)."
    counts = score.get("counts", {})
    story.append(
        Paragraph(
            f"{headline} {counts.get('fail', 0)} failed, {counts.get('warning', 0)} warnings, "
            f"{counts.get('pass', 0)} passed, {counts.get('not_checked', 0)} could not be checked.",
            body,
        )
    )
    if score.get("critical_failed"):
        story.append(Paragraph("A critical check failed, so the grade is capped at E.", body))
    elif score.get("high_risk_failed"):
        story.append(Paragraph("A high-severity check failed, so the grade is capped at D.", body))

    category_rows = [["Category", "Points"]]
    for key, title in CATEGORY_TITLES.items():
        points = score["categories"].get(key)
        if points:
            category_rows.append([title, f"{points['earned']} / {points['possible']}"])
    story += [Spacer(1, 3 * mm), _table(category_rows, [110 * mm, 40 * mm])]

    story += [Spacer(1, 5 * mm), Paragraph("Prioritized recommendations", h2)]
    if report["recommendations"]:
        for index, recommendation in enumerate(report["recommendations"], start=1):
            story.append(Paragraph(f"{index}. {_t(recommendation)}", body))
    else:
        story.append(Paragraph("No issues were found in the checked settings.", body))

    story += [Spacer(1, 5 * mm), Paragraph("Technical findings", h2)]
    story.append(
        Paragraph(
            "<i>Observed</i> is what the scanner actually saw (a fact). <i>Risk</i> explains why it matters "
            "(an inference). Heuristic checks are educated guesses and are marked as such.",
            small,
        )
    )
    findings = sorted(
        report["findings"],
        key=lambda f: (
            ["fail", "warning", "not_checked", "pass", "not_applicable"].index(f["status"]),
            SEVERITY_ORDER.get(f["severity"], 9),
        ),
    )
    rows = [["Status", "Finding"]]
    styles_extra = []
    for row_index, finding in enumerate(findings, start=1):
        parts = [f"<b>{_t(finding['title'])}</b> ({_t(finding['severity'])})"]
        if finding.get("detail") and finding["status"] != "pass":
            parts.append(_t(finding["detail"]))
        if finding.get("evidence"):
            parts.append(f"<i>Observed:</i> {_t(finding['evidence'])}")
        if finding.get("explanation") and finding["status"] in ("fail", "warning"):
            parts.append(f"<i>Risk:</i> {_t(finding['explanation'])}")
        if finding.get("recommendation") and finding["status"] in ("fail", "warning"):
            parts.append(f"<i>Fix:</i> {_t(finding['recommendation'])}")
        if finding.get("confidence") == "heuristic":
            parts.append("<i>Heuristic check.</i>")
        rows.append([STATUS_LABELS.get(finding["status"], finding["status"]), Paragraph("<br/>".join(parts), small)])
        color = STATUS_COLORS.get(finding["status"])
        if color:
            styles_extra.append(("TEXTCOLOR", (0, row_index), (0, row_index), color))
    story.append(_table(rows, [24 * mm, 150 * mm], styles_extra))

    story += [Spacer(1, 5 * mm), Paragraph("Scope, methodology and limitations", h2)]
    story.append(
        Paragraph(
            "Scoring: critical = 20, high = 10, medium = 5, low = 2 points, info is not scored. Pass earns full "
            "points, warning half, fail none. Checks that could not run or do not apply are excluded. "
            "Grades: A from 85%, B from 70%, C from 55%, D from 40%, otherwise E.",
            small,
        )
    )
    for limitation in report.get("limitations", []):
        story.append(Paragraph(f"- {_t(limitation)}", small))
    if scope_note:
        story.append(Paragraph(_t(scope_note), small))

    doc.build(story)
    return buffer.getvalue()


def _table(rows: list[list[Any]], widths: list[float], extra: list | None = None) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d0d5dd")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
            + (extra or [])
        )
    )
    return table
