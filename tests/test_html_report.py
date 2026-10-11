from html.parser import HTMLParser

from conftest import build_report
from saboss_scan.html_report import render_html


class TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def tags_in(html):
    collector = TagCollector()
    collector.feed(html)
    return collector.tags


def test_report_contains_domain_grade_and_all_findings(sample_report):
    html = render_html(sample_report)
    assert "<title>Saboss Scan report: example.com</title>" in html
    assert f'<b>{sample_report["score"]["grade"]}</b>' in html
    for finding in sample_report["findings"]:
        assert finding["title"].replace("'", "&#x27;") in html


def test_report_includes_limitations(sample_report):
    html = render_html(sample_report)
    assert "Scope and limitations" in html
    assert "does not mean the website is secure" in html


def test_hostile_header_values_are_escaped():
    # A malicious website controls its own header values.
    attack = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    report = build_report(headers={
        "strict-transport-security": f"max-age=0 {attack}",
        "x-frame-options": attack,
    })
    html = render_html(report)
    assert "<script" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "script" not in tags_in(html)
    assert "img" not in tags_in(html)


def test_report_blocks_scripts_with_content_security_policy(sample_report):
    html = render_html(sample_report)
    assert "default-src 'none'" in html


def test_report_has_no_external_resources(sample_report):
    html = render_html(sample_report)
    assert "http://" not in html
    assert "https://" not in html


def test_report_without_score():
    report = build_report(ssl={"error_type": "timeout", "error": "timeout"})
    for finding in report["findings"]:
        finding["status"] = "not_checked"
    report["score"].update(percentage=None, grade="N/A", checks_completed=0, complete=False)
    html = render_html(report)
    assert "no score" in html
    assert "could not run" in html
