"""
iam_checks.py
Read-only checks against every IAM user in the account.

Maps loosely to CIS AWS Foundations Benchmark:
  1.10 - MFA is enabled for all IAM users that have a console password
  1.16 - IAM policies attached to users are not directly administrative
         (AdministratorAccess should be via a group/role, and rarely at all)
"""

from botocore.exceptions import ClientError

ADMIN_POLICY_NAMES = {"AdministratorAccess"}


def _user_has_mfa(iam_client, username: str) -> bool:
    devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])
    return len(devices) > 0


def _user_has_console_access(iam_client, username: str) -> bool:
    try:
        iam_client.get_login_profile(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        return False


def _user_admin_policies(iam_client, username: str) -> list[str]:
    admin_hits = []

    attached = iam_client.list_attached_user_policies(UserName=username)
    for p in attached.get("AttachedPolicies", []):
        if p["PolicyName"] in ADMIN_POLICY_NAMES:
            admin_hits.append(p["PolicyName"])

    # Also check group memberships, since AdministratorAccess is very often
    # granted via a group rather than directly on the user
    groups = iam_client.list_groups_for_user(UserName=username).get("Groups", [])
    for g in groups:
        group_policies = iam_client.list_attached_group_policies(GroupName=g["GroupName"])
        for p in group_policies.get("AttachedPolicies", []):
            if p["PolicyName"] in ADMIN_POLICY_NAMES:
                admin_hits.append(f"{p['PolicyName']} (via group {g['GroupName']})")

    return admin_hits


def run_iam_checks(iam_client) -> list[dict]:
    findings = []

    try:
        paginator = iam_client.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except ClientError as e:
        findings.append({
            "resource": "IAM (account)",
            "check": "IAM.LIST_USERS",
            "status": "ERROR",
            "severity": "N/A",
            "detail": f"Could not list IAM users: {e.response['Error']['Code']}",
            "cis_control": "N/A",
            "fix": "Ensure the scanning role has iam:ListUsers permission.",
        })
        return findings

    for u in users:
        username = u["UserName"]
        resource = f"iam-user/{username}"

        has_console = _user_has_console_access(iam_client, username)
        has_mfa = _user_has_mfa(iam_client, username)

        if has_console and not has_mfa:
            findings.append({
                "resource": resource,
                "check": "IAM_MFA",
                "status": "FAIL",
                "severity": "Critical",
                "detail": "User has console password but no MFA device enabled",
                "cis_control": "CIS 1.10",
                "fix": "Enforce MFA for this user (virtual or hardware token).",
            })
        else:
            findings.append({
                "resource": resource,
                "check": "IAM_MFA",
                "status": "PASS",
                "severity": "Info",
                "detail": "MFA enabled or user has no console access",
                "cis_control": "CIS 1.10",
                "fix": "",
            })

        admin_hits = _user_admin_policies(iam_client, username)
        if admin_hits:
            findings.append({
                "resource": resource,
                "check": "IAM_EXCESSIVE_PRIVILEGE",
                "status": "FAIL",
                "severity": "High",
                "detail": f"User effectively has AdministratorAccess via: {', '.join(admin_hits)}",
                "cis_control": "CIS 1.16",
                "fix": "Apply least privilege — scope this user to only the "
                       "permissions their role requires, use roles for elevated access.",
            })
        else:
            findings.append({
                "resource": resource,
                "check": "IAM_EXCESSIVE_PRIVILEGE",
                "status": "PASS",
                "severity": "Info",
                "detail": "No direct or group-based AdministratorAccess found",
                "cis_control": "CIS 1.16",
                "fix": "",
            })

    return findings
