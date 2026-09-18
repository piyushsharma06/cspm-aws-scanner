
from datetime import datetime, timezone

import boto3
from fastapi import FastAPI, HTTPException, Query

from scanner.aws_client import get_clients
from scanner.s3_checks import run_s3_checks
from scanner.sg_checks import run_sg_checks
from scanner.iam_checks import run_iam_checks
from scanner.correlation import find_attack_paths
from scanner.scoring import build_report

app = FastAPI(
    title="Mini-CSPM AWS Scanner",
    version="1.0.0",
)


@app.get("/")
def root():
    return {
        "message": "Mini-CSPM AWS Scanner API",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def run_scan(
    region: str = Query(default="us-east-1")
):
    # Validate AWS region input
    if not region or len(region) > 32:
        raise HTTPException(
            status_code=400,
            detail="Invalid AWS region",
        )

    try:
        # Uses AWS credentials from the environment
        # or the default AWS credential provider chain.
        session = boto3.Session(region_name=region)
        clients = get_clients(session)

        s3_findings = run_s3_checks(clients["s3"])
        sg_findings = run_sg_checks(clients["ec2"])
        iam_findings = run_iam_checks(clients["iam"])

        all_findings = (
            s3_findings + sg_findings + iam_findings
        )

        attack_paths = find_attack_paths(all_findings)

        report = build_report(
            s3_findings,
            sg_findings,
            iam_findings,
            attack_paths,
        )

        report["metadata"] = {
            "scanned_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "region": region,
        }

        return report

    except Exception:
        # Avoid returning internal details or credentials
        # to API clients.
        raise HTTPException(
            status_code=500,
            detail="Scan failed. Check server logs.",
        )
