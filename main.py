from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Saboss Scan - simple domain security scanner")
    parser.add_argument("domain", help="Domain to scan, for example example.com")
    parser.add_argument("--json", dest="json_path", help="Save full report as JSON file")
    args = parser.parse_args()

    try:
        report = scan_domain(args.domain)
    except InvalidTargetError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    print_summary(report)

    if args.json_path:
        path = Path(args.json_path)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved JSON report to: {path}")


if __name__ == "__main__":
    main()
