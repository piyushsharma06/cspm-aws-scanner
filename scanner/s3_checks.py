"""
s3_checks.py
Read-only checks against every S3 bucket in the account.

Maps loosely to CIS AWS Foundations Benchmark:
  2.1.1 - S3 Bucket Policy is set to deny HTTP requests (not checked here, noted as extension)
  2.1.2 - S3 Bucket has public access disabled
  2.1.3 - S3 Bucket has server-side encryption enabled
"""

from botocore.exceptions import ClientError


def _bucket_is_public(s3_client, bucket_name: str) -> tuple[bool, str]:
    """
    A bucket is treated as PUBLIC if:
      - It has no "Block Public Access" configuration at all, OR
      - Any of the four block-public-access flags is False, OR
      - Its bucket ACL grants access to AllUsers / AuthenticatedUsers
    Returns (is_public, reason)
    """
    # 1. Check the Block Public Access configuration
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab["PublicAccessBlockConfiguration"]
        all_blocked = all(
            cfg.get(flag, False)
            for flag in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
        if not all_blocked:
            return True, "Block Public Access is not fully enabled on this bucket"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return True, "No Block Public Access configuration exists on this bucket"
        # If we can't determine it (permissions issue), don't silently pass it
        return True, f"Could not verify Block Public Access ({e.response['Error']['Code']})"

    # 2. Check the bucket ACL for public grants
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True, "Bucket ACL grants access to AllUsers/AuthenticatedUsers"
    except ClientError:
        pass

    return False, "Public access appears blocked"


def _bucket_is_encrypted(s3_client, bucket_name: str) -> bool:
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        return False


def run_s3_checks(s3_client) -> list[dict]:
    """Scan every bucket and return a list of findings (dicts)."""
    findings = []

    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except ClientError as e:
        findings.append({
            "resource": "S3 (account)",
            "check": "S3.LIST_BUCKETS",
            "status": "ERROR",
            "severity": "N/A",
            "detail": f"Could not list buckets: {e.response['Error']['Code']}",
            "cis_control": "N/A",
            "fix": "Ensure the scanning role has s3:ListAllMyBuckets permission.",
        })
        return findings

    for b in buckets:
        name = b["Name"]

        is_public, reason = _bucket_is_public(s3_client, name)
        findings.append({
            "resource": f"s3://{name}",
            "check": "S3_PUBLIC_ACCESS",
            "status": "FAIL" if is_public else "PASS",
            "severity": "Critical" if is_public else "Info",
            "detail": reason,
            "cis_control": "CIS 2.1.2",
            "fix": "Enable S3 Block Public Access at the bucket (and account) level, "
                   "and remove any ACL grants to AllUsers/AuthenticatedUsers.",
        })

        encrypted = _bucket_is_encrypted(s3_client, name)
        findings.append({
            "resource": f"s3://{name}",
            "check": "S3_ENCRYPTION",
            "status": "PASS" if encrypted else "FAIL",
            "severity": "Medium" if not encrypted else "Info",
            "detail": "Default encryption is enabled" if encrypted
                      else "No default server-side encryption configured",
            "cis_control": "CIS 2.1.3",
            "fix": "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
        })

    return findings
