from __future__ import annotations

import argparse
import json
from pathlib import Path

from saboss_scan.scanner import scan_domain


def print_summary(report: dict) -> None:
    """Print a readable scan summary in the terminal."""
    score = report["score"]
    print("\n========== SABOSS SCAN ==========")
    print(f"Domain: {report['domain']}")
    print(f"Score: {score['percentage']}% ({score['grade']})")
    print("\nCategory scores:")
    for name, points in score["categories"].items():
        max_points = score["max_points"][name]
        print(f"- {name}: {points}/{max_points}")

    print("\nSSL/TLS:")
    print(f"- HTTPS: {report['ssl'].get('https')}")
    print(f"- Certificate valid: {report['ssl'].get('certificate_valid')}")
    print(f"- Expires: {report['ssl'].get('expires_at')}")

    print("\nSecurity headers:")
    print(f"- Present: {', '.join(report['headers'].get('present', [])) or 'None'}")
    print(f"- Missing: {', '.join(report['headers'].get('missing', [])) or 'None'}")

    print("\nDNS / Email security:")
    print(f"- A records: {len(report['dns'].get('a', []))}")
    print(f"- AAAA records: {len(report['dns'].get('aaaa', []))}")
    print(f"- MX records: {len(report['dns'].get('mx', []))}")
    print(f"- SPF: {'Yes' if report['dns'].get('spf') else 'No'}")
    print(f"- DMARC: {'Yes' if report['dns'].get('dmarc') else 'No'}")
    print(f"- DKIM found: {'Yes' if report['dns'].get('dkim') else 'No / unknown'}")

    print("\nRecommendations:")
    for index, recommendation in enumerate(report["recommendations"], start=1):
        print(f"{index}. {recommendation}")
    print("=================================\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Saboss Scan - simple domain security scanner")
    parser.add_argument("domain", help="Domain to scan, for example example.com")
    parser.add_argument("--json", dest="json_path", help="Save full report as JSON file")
    args = parser.parse_args()

    report = scan_domain(args.domain)
    print_summary(report)

    if args.json_path:
        path = Path(args.json_path)
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Saved JSON report to: {path}")


if __name__ == "__main__":
    main()
