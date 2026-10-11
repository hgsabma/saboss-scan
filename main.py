from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from saboss_scan.html_report import render_html
from saboss_scan.scanner import scan_domain
from saboss_scan.utils import InvalidTargetError


CATEGORY_TITLES = {
    "tls": "HTTPS / TLS",
    "http_headers": "HTTP security headers",
    "dns": "DNS",
    "email": "E-mail security",
}
STATUS_LABELS = {
    "pass": "PASS",
    "warning": "WARN",
    "fail": "FAIL",
    "not_checked": "N/A ",
}


def print_summary(report: dict) -> None:
    """Print a readable scan summary in the terminal."""
    score = report["score"]
    print("\n================ SABOSS SCAN ================")
    print(f"Domain: {report['domain']}")
    if score["percentage"] is None:
        print("Score:  not available (no checks could be completed)")
    else:
        print(f"Score:  {score['percentage']}% (grade {score['grade']})")
    print(f"Checks: {score['checks_completed']} of {score['checks_total']} completed")
    if not score["complete"]:
        print("        Some checks could not run (N/A) and are not included in the score.")
    if score["high_risk_failed"]:
        print("        A high-severity check failed, so the grade is capped at D.")

    for category, title in CATEGORY_TITLES.items():
        category_score = score["categories"].get(category, {})
        print(f"\n{title}  ({category_score.get('earned', 0)}/{category_score.get('possible', 0)} points)")
        for finding in report["findings"]:
            if finding["category"] != category:
                continue
            label = STATUS_LABELS[finding["status"]]
            print(f"  [{label}] {finding['title']} ({finding['severity']})")
            if finding["detail"] and finding["status"] != "pass":
                print(f"         {finding['detail']}")

    print("\nRecommendations:")
    if not report["recommendations"]:
        print("  No issues found in the checked settings.")
    for index, recommendation in enumerate(report["recommendations"], start=1):
        print(f"  {index}. {recommendation}")

    print("\nScope and limitations:")
    for limitation in report["limitations"]:
        print(f"  - {limitation}")
    print("=============================================\n")


def _save(path_text: str, content: str, label: str) -> bool:
    path = Path(path_text)
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        print(f"Error: could not save the {label} report to {path}: {exc.strerror}", file=sys.stderr)
        return False
    print(f"Saved {label} report to: {path}")
    return True


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return the exit code.

    Exit codes: 0 = scan completed, 1 = report could not be saved,
    2 = invalid or unsafe target.
    """
    parser = argparse.ArgumentParser(
        description="Saboss Scan - passive security check for a domain you own or may assess."
    )
    parser.add_argument("domain", help="Domain to scan, for example example.com")
    parser.add_argument("--json", dest="json_path", metavar="FILE", help="Save the full report as JSON")
    parser.add_argument("--html", dest="html_path", metavar="FILE", help="Save a readable HTML report")
    args = parser.parse_args(argv)

    # Text from scanned websites can contain any character. On Windows, output
    # redirected to a file uses an old encoding that cannot show all of them;
    # replace those characters with "?" instead of crashing.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    try:
        report = scan_domain(args.domain)
    except InvalidTargetError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print_summary(report)

    saved = True
    if args.json_path:
        saved &= _save(args.json_path, json.dumps(report, indent=2, ensure_ascii=False), "JSON")
    if args.html_path:
        saved &= _save(args.html_path, render_html(report), "HTML")
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
