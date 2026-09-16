#!/usr/bin/env python3
"""
Mini-CSPM — AWS Cloud Security Posture Scanner
Read-only scanner: S3 + Security Groups + IAM, scored against a
CIS-AWS-Foundations-style benchmark.

Usage:
    python main.py                     # default profile, us-east-1
    python main.py --profile myprofile --region ap-south-1
    python main.py --output report.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from scanner.aws_client import get_session, get_clients
from scanner.s3_checks import run_s3_checks
from scanner.sg_checks import run_sg_checks
from scanner.iam_checks import run_iam_checks
from scanner.correlation import find_attack_paths
from scanner.scoring import build_report


def parse_args():
    parser = argparse.ArgumentParser(description="Mini-CSPM: AWS posture scanner")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1", help="AWS region to scan")
    parser.add_argument("--output", default="report.json", help="Path to write JSON report")
    return parser.parse_args()


def print_summary(report: dict):
    print("\n" + "=" * 60)
    print(" MINI-CSPM — RISK REPORT SUMMARY")
    print("=" * 60)
    print(f" Risk Score : {report['risk_score']} / 100")
    print(f" Grade      : {report['grade']}")
    t = report["totals"]
    print(f" Checks     : {t['total_checks']} total | "
          f"{t['passed']} passed | {t['failed']} failed | "
          f"{t['warnings']} warnings | {t['errors']} errors")
    sc = report["severity_counts"]
    print(f" Failures   : Critical={sc['Critical']}  High={sc['High']}  "
          f"Medium={sc['Medium']}  Low={sc['Low']}")
    print("=" * 60)

    if report.get("attack_paths"):
        print("\n *** CORRELATED ATTACK PATH(S) DETECTED ***\n")
        for p in report["attack_paths"]:
            print(f" [{p['severity'].upper()}] {p['title']}")
            print(f"   Chain: {p['chain']}")
            print(f"   Fix:   {p['fix']}\n")

    failures = [f for f in report["findings"] if f["status"] == "FAIL"]
    if failures:
        print("\n TOP FINDINGS:\n")
        for f in sorted(failures, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4))[:10]:
            print(f" [{f['severity'].upper():>8}] {f['resource']}  —  {f['check']}")
            print(f"            {f['detail']}")
            print(f"            Fix: {f['fix']}")
            print()
    else:
        print("\n No failing checks found. Nice posture!\n")


def main():
    args = parse_args()

    print(f"Mini-CSPM starting scan — profile={args.profile or 'default'}, region={args.region}")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")

    try:
        session = get_session(profile=args.profile, region=args.region)
        clients = get_clients(session)
    except Exception as e:
        print(f"ERROR: could not create AWS session/clients: {e}", file=sys.stderr)
        sys.exit(1)

    print("Scanning S3 buckets...")
    s3_findings = run_s3_checks(clients["s3"])

    print("Scanning EC2 Security Groups...")
    sg_findings = run_sg_checks(clients["ec2"])

    print("Scanning IAM users...")
    iam_findings = run_iam_checks(clients["iam"])

    print("Correlating findings into attack paths...")
    all_findings = s3_findings + sg_findings + iam_findings
    attack_paths = find_attack_paths(all_findings)

    report = build_report(s3_findings, sg_findings, iam_findings, attack_paths)
    report["metadata"] = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "region": args.region,
        "profile": args.profile or "default",
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nFull report written to: {args.output}")
    print_summary(report)


if __name__ == "__main__":
    main()
