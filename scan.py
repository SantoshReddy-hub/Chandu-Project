"""Command-line entry point.

Usage:
    python scan.py https://example.com --mode quick
"""
import argparse

from scanner.orchestrator import FULL, QUICK, STANDARD, run_scan
from scanner.report import build_pdf

SHORT = {"quick": QUICK, "standard": STANDARD, "full": FULL}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Automated Web-Application Vulnerability Scanner")
    ap.add_argument("target")
    ap.add_argument("--mode", choices=SHORT, default="quick")
    args = ap.parse_args()

    scan_id, findings = run_scan(args.target, SHORT[args.mode])
    print(f"\nScan #{scan_id}: {len(findings)} findings")
    for f in findings:
        param = f" [{f.param}]" if f.param else ""
        print(f"  [{f.severity:8}] {f.title}{param}  ({f.source})  {f.url}")
    print("PDF report:", build_pdf(scan_id))
