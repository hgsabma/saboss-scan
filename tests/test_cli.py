import json

import main as cli
from saboss_scan.utils import InvalidTargetError


def test_invalid_target_exits_with_code_2(monkeypatch, capsys):
    def reject(domain):
        raise InvalidTargetError("'localhost' is a local or reserved name and cannot be scanned.")

    monkeypatch.setattr(cli, "scan_domain", reject)
    assert cli.main(["localhost"]) == 2
    assert "cannot be scanned" in capsys.readouterr().err


def test_scan_prints_summary_and_saves_reports(monkeypatch, tmp_path, capsys, sample_report):
    monkeypatch.setattr(cli, "scan_domain", lambda domain: sample_report)
    json_file = tmp_path / "report.json"
    html_file = tmp_path / "report.html"

    exit_code = cli.main(["example.com", "--json", str(json_file), "--html", str(html_file)])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "SABOSS SCAN" in output
    assert json.loads(json_file.read_text(encoding="utf-8"))["domain"] == "example.com"
    assert html_file.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_unwritable_report_path_exits_with_code_1(monkeypatch, tmp_path, capsys, sample_report):
    monkeypatch.setattr(cli, "scan_domain", lambda domain: sample_report)
    missing_folder = tmp_path / "does-not-exist" / "report.html"

    assert cli.main(["example.com", "--html", str(missing_folder)]) == 1
    assert "could not save" in capsys.readouterr().err


def test_non_ascii_website_text_does_not_crash_legacy_console(monkeypatch):
    import io
    import sys

    from conftest import build_report

    report = build_report(headers={"x-frame-options": "ALLOW-FROM https://bücher.例え"})
    monkeypatch.setattr(cli, "scan_domain", lambda domain: report)
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)

    assert cli.main(["example.com"]) == 0
    legacy.flush()
    assert b"b\xfccher.??" in legacy.buffer.getvalue()
