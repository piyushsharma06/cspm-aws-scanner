"""
scoring.py
Turns raw findings from s3_checks / sg_checks / iam_checks into a single
risk-scored report, similar in spirit to how Prisma Cloud / CSPM tools
roll findings up into a posture score.
"""

# Intrinsic importance of each *type* of check, independent of whether it
# passed or failed. This is what the score is weighted against, so one
# critical failure doesn't automatically wipe the whole score out — it's
# a "what % of your weighted posture is healthy" model, similar to how
# CSPM tools like Prisma Cloud report compliance percentage.
CHECK_WEIGHTS = {
    "S3_PUBLIC_ACCESS": 15,
    "S3_ENCRYPTION": 5,
    "SG_OPEN_TO_WORLD_RISKY_PORT": 15,
    "SG_OPEN_TO_WORLD_OTHER_PORT": 5,
    "SG_OPEN_TO_WORLD": 15,
    "IAM_MFA": 15,
    "IAM_EXCESSIVE_PRIVILEGE": 10,
}
DEFAULT_WEIGHT = 5

MAX_SCORE = 100


def _weight_for(finding: dict) -> float:
    return CHECK_WEIGHTS.get(finding["check"], DEFAULT_WEIGHT)


def build_report(s3_findings: list[dict], sg_findings: list[dict], iam_findings: list[dict],
                  attack_paths: list[dict] = None) -> dict:
    all_findings = s3_findings + sg_findings + iam_findings
    attack_paths = attack_paths or []

    failures = [f for f in all_findings if f["status"] == "FAIL"]
    warnings = [f for f in all_findings if f["status"] == "WARN"]
    errors = [f for f in all_findings if f["status"] == "ERROR"]
    scored = [f for f in all_findings if f["status"] in ("PASS", "FAIL", "WARN")]

    total_weight = sum(_weight_for(f) for f in scored) or 1
    # PASS = full credit, WARN = half credit, FAIL = no credit
    earned_weight = 0.0
    for f in scored:
        w = _weight_for(f)
        if f["status"] == "PASS":
            earned_weight += w
        elif f["status"] == "WARN":
            earned_weight += w * 0.5

    risk_score = max(0, min(MAX_SCORE, (earned_weight / total_weight) * MAX_SCORE))

    # Correlated attack paths make the score reflect combined risk, not
    # just the sum of isolated findings.
    from scanner.correlation import apply_correlation_penalty
    risk_score = apply_correlation_penalty(risk_score, attack_paths)

    if risk_score >= 90:
        grade = "A (Strong posture)"
    elif risk_score >= 75:
        grade = "B (Minor issues)"
    elif risk_score >= 50:
        grade = "C (Needs attention)"
    elif risk_score >= 25:
        grade = "D (Poor posture)"
    else:
        grade = "F (Critical exposure)"

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in failures:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    return {
        "risk_score": round(risk_score, 1),
        "grade": grade,
        "totals": {
            "total_checks": len(all_findings),
            "failed": len(failures),
            "warnings": len(warnings),
            "errors": len(errors),
            "passed": len(all_findings) - len(failures) - len(warnings) - len(errors),
        },
        "severity_counts": severity_counts,
        "findings": all_findings,
        "attack_paths": attack_paths,
    }
