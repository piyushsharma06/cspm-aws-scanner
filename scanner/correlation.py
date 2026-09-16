"""
correlation.py
Correlation layer: looks across ALL findings from a scan and detects when
several individually-scored weaknesses combine into a higher-impact
attack path — the core differentiator described in the attack-path deck.

SCOPE NOTE (be upfront about this in interviews):
This is ACCOUNT-LEVEL pattern correlation, not full resource-graph
correlation. It answers "does this account simultaneously have an
internet-exposed entry point, an over-privileged identity, and exposed
sensitive data?" rather than tracing a specific EC2 instance -> its
exact attached IAM role -> the exact S3 buckets that role can reach.
True resource-graph correlation would require additional EC2
(describe_instances, instance profiles) and IAM policy-simulation checks
that aren't built yet — noted as a natural next step.
"""

ENTRY_POINT_CHECKS = {"SG_OPEN_TO_WORLD_RISKY_PORT"}
PRIVILEGE_CHECKS = {"IAM_EXCESSIVE_PRIVILEGE", "IAM_MFA"}
DATA_EXPOSURE_CHECKS = {"S3_PUBLIC_ACCESS"}


def find_attack_paths(findings: list[dict]) -> list[dict]:
    """
    Look for the classic chain:
        Internet-exposed entry point  -->  Over-privileged / weakly-secured identity  -->  Exposed sensitive data

    Returns a list of correlated attack-path findings (usually 0 or 1 for
    a small account, but written to generalize).
    """
    entry_points = [f for f in findings if f["check"] in ENTRY_POINT_CHECKS and f["status"] == "FAIL"]
    privilege_issues = [f for f in findings if f["check"] in PRIVILEGE_CHECKS and f["status"] == "FAIL"]
    data_exposures = [f for f in findings if f["check"] in DATA_EXPOSURE_CHECKS and f["status"] == "FAIL"]

    paths = []

    if entry_points and privilege_issues and data_exposures:
        chain = (
            f"Internet -> {entry_points[0]['resource']} (open entry point) "
            f"-> {privilege_issues[0]['resource']} (privilege weakness) "
            f"-> {data_exposures[0]['resource']} (sensitive data exposure)"
        )
        paths.append({
            "type": "ATTACK_PATH",
            "severity": "Critical",
            "title": "Correlated attack path: exposed entry point + weak identity + exposed data",
            "chain": chain,
            "contributing_findings": [
                entry_points[0]["resource"],
                privilege_issues[0]["resource"],
                data_exposures[0]["resource"],
            ],
            "explanation": (
                "Individually these three findings are High/Critical alerts. Together, they "
                "describe a realistic path an attacker could take: get in through the exposed "
                "port, use the weak/over-privileged identity to move further, then reach the "
                "exposed data. This combination should be investigated before isolated findings "
                "of the same severity."
            ),
            "fix": (
                "Break the chain at any link: close the exposed port to 0.0.0.0/0, enforce MFA "
                "and least privilege on the identity, and remove public access from the data store. "
                "Fixing all three removes the path entirely, not just one alert."
            ),
        })
    elif entry_points and data_exposures:
        paths.append({
            "type": "ATTACK_PATH",
            "severity": "High",
            "title": "Correlated risk: exposed entry point + exposed data (no privilege escalation link found)",
            "chain": f"Internet -> {entry_points[0]['resource']} -> {data_exposures[0]['resource']}",
            "contributing_findings": [entry_points[0]["resource"], data_exposures[0]["resource"]],
            "explanation": (
                "An open entry point and publicly exposed data exist in the same account. "
                "No over-privileged identity was found linking them, but both should still "
                "be remediated as they raise the account's overall exposure."
            ),
            "fix": "Close the exposed port and remove public access from the data store.",
        })

    return paths


def apply_correlation_penalty(risk_score: float, attack_paths: list[dict]) -> float:
    """
    Correlated Critical attack paths push the score down further than the
    sum of their individual findings would, since the combination is more
    dangerous than any single finding alone.
    """
    penalty = 0
    for p in attack_paths:
        penalty += 15 if p["severity"] == "Critical" else 8
    return max(0, risk_score - penalty)
