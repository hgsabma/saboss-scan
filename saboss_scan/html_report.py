"""Render a scan report as a single, self-contained HTML file.

Security note: the report contains text that comes from the scanned website
(for example header values). A hostile site could put HTML or JavaScript in
those values, so EVERY dynamic value goes through _e() (html.escape). As a
second layer of defence, the page has a Content-Security-Policy that blocks
all scripts and external resources.

The file has no external dependencies (no fonts, scripts or images), so it
works offline and does not leak to third parties that someone opened it.
"""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any

CATEGORY_TITLES = {
    "tls": "HTTPS / TLS",
    "http_headers": "HTTP security headers",
    "dns": "DNS",
    "email": "E-mail security",
}
STATUS_LABELS = {
    "pass": "Pass",
    "warning": "Warning",
    "fail": "Fail",
    "not_checked": "Not checked",
    "not_applicable": "Not applicable",
}
STATUS_ORDER = {"fail": 0, "warning": 1, "not_checked": 2, "pass": 3, "not_applicable": 4}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CSS = """
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #1b1f24; --muted: #5b6470; --border: #dde1e6;
  --accent: #1f4fd1;
  --pass: #1a7f37; --pass-bg: #e6f4ea; --warn: #8a5a00; --warn-bg: #fff4d6;
  --fail: #b42318; --fail-bg: #fde8e7; --na: #545d68; --na-bg: #eceff2;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --card: #171b21; --text: #e6e9ed; --muted: #9aa4b1; --border: #2a3039;
    --accent: #7aa2ff;
    --pass: #6fdd8b; --pass-bg: #12301c; --warn: #f2c94c; --warn-bg: #3a2f0b;
    --fail: #ff8a80; --fail-bg: #3d1513; --na: #b5bec9; --na-bg: #242a32;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 900px; margin: 0 auto; padding: 32px 16px 48px; }
header.top { display: flex; flex-wrap: wrap; gap: 24px; align-items: center; justify-content: space-between; }
.brand { font-size: 14px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 0; }
h1 { font-size: 28px; margin: 4px 0 4px; word-break: break-all; }
h2 { font-size: 20px; margin: 0 0 12px; }
.meta { color: var(--muted); font-size: 14px; margin: 0; }
.grade {
  width: 112px; height: 112px; border-radius: 50%; display: grid; place-content: center; text-align: center;
  border: 6px solid var(--accent); background: var(--card);
}
.grade b { font-size: 40px; line-height: 1; }
.grade span { font-size: 14px; color: var(--muted); }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-top: 20px; }
.notice { border-left: 4px solid var(--warn); }
.counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.count { border-radius: 8px; padding: 12px; }
.count b { display: block; font-size: 24px; }
.badge {
  display: inline-block; min-width: 92px; text-align: center; font-size: 13px; font-weight: 600;
  padding: 2px 8px; border-radius: 999px; white-space: nowrap;
}
.s-pass { color: var(--pass); background: var(--pass-bg); }
.s-warning { color: var(--warn); background: var(--warn-bg); }
.s-fail { color: var(--fail); background: var(--fail-bg); }
.s-not_checked, .s-not_applicable { color: var(--na); background: var(--na-bg); }
.category-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
.points { color: var(--muted); font-size: 14px; }
ul.findings { list-style: none; margin: 0; padding: 0; }
ul.findings li { padding: 12px 0; border-top: 1px solid var(--border); display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; }
.title { font-weight: 600; }
.severity { color: var(--muted); font-size: 13px; font-weight: 400; margin-left: 6px; }
.detail, .fix { grid-column: 2; font-size: 14px; margin: 0; overflow-wrap: anywhere; }
.detail { color: var(--muted); }
ol.recommendations { margin: 0; padding-left: 22px; }
ol.recommendations li { margin: 6px 0; }
footer { color: var(--muted); font-size: 13px; margin-top: 32px; }
@media (max-width: 520px) {
  ul.findings li { grid-template-columns: 1fr; }
  .detail, .fix { grid-column: 1; }
}
@media print {
  body { background: #fff; }
  .card { break-inside: avoid; }
}
"""


def _e(value: Any) -> str:
    """Escape any value for safe use in HTML text and attributes."""
    return escape("" if value is None else str(value), quote=True)


def _format_date(iso_value: str | None) -> str:
    try:
        return datetime.fromisoformat(iso_value or "").strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso_value or "unknown date"


def _badge(status: str) -> str:
    return f'<span class="badge s-{_e(status)}">{_e(STATUS_LABELS.get(status, status))}</span>'


def _finding_item(finding: dict[str, Any]) -> str:
    parts = [
        "<li>",
        _badge(finding["status"]),
        f'<div class="title">{_e(finding["title"])}'
        f'<span class="severity">{_e(finding["severity"])} severity</span></div>',
    ]
    if finding.get("detail"):
        parts.append(f'<p class="detail">{_e(finding["detail"])}</p>')
    if finding.get("evidence"):
        parts.append(f'<p class="detail"><strong>Observed:</strong> {_e(finding["evidence"])}</p>')
    if finding.get("explanation") and finding["status"] in ("fail", "warning"):
        parts.append(f'<p class="detail"><strong>Why it matters:</strong> {_e(finding["explanation"])}</p>')
    if finding.get("confidence") == "heuristic":
        parts.append(
            '<p class="detail"><em>Heuristic check: the result is an educated guess, not a confirmed fact.</em></p>'
        )
    if finding.get("recommendation") and finding["status"] in ("fail", "warning"):
        parts.append(f'<p class="fix"><strong>Fix:</strong> {_e(finding["recommendation"])}</p>')
    parts.append("</li>")
    return "".join(parts)


def render_html(report: dict[str, Any]) -> str:
    """Return the complete HTML document for a scan report."""
    score = report["score"]
    findings = report["findings"]
    domain = report["domain"]

    if score["percentage"] is None:
        grade_html = '<div class="grade" role="img" aria-label="No score"><b>–</b><span>no score</span></div>'
    else:
        grade_html = (
            f'<div class="grade" role="img" aria-label="Grade {_e(score["grade"])}, {_e(score["percentage"])} percent">'
            f"<b>{_e(score['grade'])}</b><span>{_e(score['percentage'])}%</span></div>"
        )

    notices = []
    if not score["complete"]:
        notices.append(
            f"{_e(score['checks_total'] - score['checks_completed'])} check(s) could not run and are "
            "not included in the score."
        )
    if score.get("critical_failed"):
        notices.append("A critical check failed, so the grade is capped at E.")
    elif score["high_risk_failed"]:
        notices.append("A high-severity check failed, so the grade is capped at D.")
    notice_html = (
        '<section class="card notice" aria-label="Notes about this score"><ul>'
        + "".join(f"<li>{n}</li>" for n in notices)
        + "</ul></section>"
        if notices
        else ""
    )

    counts = {status: 0 for status in STATUS_LABELS}
    for finding in findings:
        counts[finding["status"]] = counts.get(finding["status"], 0) + 1
    counts_html = "".join(
        f'<div class="count s-{_e(status)}"><b>{counts[status]}</b>{_e(label)}</div>'
        for status, label in (
            ("fail", "Failed"),
            ("warning", "Warnings"),
            ("pass", "Passed"),
            ("not_checked", "Not checked"),
        )
    )

    category_sections = []
    for category, title in CATEGORY_TITLES.items():
        items = [f for f in findings if f["category"] == category]
        if not items:
            continue
        items.sort(key=lambda f: (STATUS_ORDER.get(f["status"], 9), SEVERITY_ORDER.get(f["severity"], 9)))
        points = score["categories"].get(category, {})
        category_sections.append(
            '<section class="card">'
            f'<div class="category-head"><h2>{_e(title)}</h2>'
            f'<span class="points">{_e(points.get("earned", 0))} / {_e(points.get("possible", 0))} points</span></div>'
            '<ul class="findings">' + "".join(_finding_item(f) for f in items) + "</ul></section>"
        )

    if report["recommendations"]:
        recommendations_html = (
            '<ol class="recommendations">' + "".join(f"<li>{_e(r)}</li>" for r in report["recommendations"]) + "</ol>"
        )
    else:
        recommendations_html = "<p>No issues were found in the checked settings.</p>"

    limitations_html = "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in report["limitations"]) + "</ul>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Saboss Scan report: {_e(domain)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header class="top">
  <div>
    <p class="brand">Saboss Scan · Security report</p>
    <h1>{_e(domain)}</h1>
    <p class="meta">Scanned {_e(_format_date(report.get("scanned_at")))} ·
      {_e(score["checks_completed"])} of {_e(score["checks_total"])} checks completed ·
      Saboss Scan {_e(report.get("version"))}</p>
  </div>
  {grade_html}
</header>

{notice_html}

<section class="card" aria-label="Summary">
  <h2>Summary</h2>
  <div class="counts">{counts_html}</div>
</section>

<section class="card">
  <h2>What to fix first</h2>
  {recommendations_html}
</section>

{"".join(category_sections)}

<section class="card">
  <h2>Scope and limitations</h2>
  {limitations_html}
</section>

<footer>
  <p>Generated by Saboss Scan, Saboss Technologies. Grades: A ≥ 85%, B ≥ 70%, C ≥ 55%, D ≥ 40%, otherwise E. A failed critical check caps the grade at E, a failed high check at D.
  Only scan domains you own or are authorized to assess.</p>
</footer>
</main>
</body>
</html>
"""
