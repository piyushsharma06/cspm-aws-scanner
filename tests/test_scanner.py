"""
End-to-end test of the Mini-CSPM scanner logic using moto (mocked AWS).
Sets up a deliberately misconfigured fake AWS account, runs the real
scanner code against it, and checks the findings/scoring come out right.

Run with: pytest -v tests/test_scanner.py
"""

import boto3
from moto import mock_aws

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scanner.s3_checks import run_s3_checks
from scanner.sg_checks import run_sg_checks
from scanner.iam_checks import run_iam_checks
from scanner.correlation import find_attack_paths
from scanner.scoring import build_report


@mock_aws
def test_full_scan_flags_expected_issues():
    region = "us-east-1"

    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam")

    # --- Set up a BAD bucket (public, unencrypted) ---
    s3.create_bucket(Bucket="totally-public-bucket")
    s3.put_bucket_acl(
        Bucket="totally-public-bucket",
        AccessControlPolicy={
            "Grants": [{
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ",
            }],
            "Owner": {"DisplayName": "owner", "ID": "owner-id"},
        },
    )

    # --- Set up a GOOD bucket (blocked + encrypted) ---
    s3.create_bucket(Bucket="locked-down-bucket")
    s3.put_public_access_block(
        Bucket="locked-down-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket="locked-down-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    # --- Set up a BAD security group (SSH open to the world) ---
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
    sg = ec2.create_security_group(
        GroupName="bad-sg", Description="bad", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    # --- Set up a BAD IAM user (admin, no MFA, has console password) ---
    iam.create_user(UserName="risky-admin")
    iam.create_login_profile(UserName="risky-admin", Password="TempPassw0rd!")
    # moto doesn't preload real AWS managed policies, so create a stand-in
    # policy with the same name Mini-CSPM looks for ("AdministratorAccess")
    admin_policy = iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
    )
    iam.attach_user_policy(
        UserName="risky-admin",
        PolicyArn=admin_policy["Policy"]["Arn"],
    )

    # --- Set up a GOOD IAM user (no console access at all) ---
    iam.create_user(UserName="service-account")

    # --- Run the real scanner code ---
    s3_findings = run_s3_checks(s3)
    sg_findings = run_sg_checks(ec2)
    iam_findings = run_iam_checks(iam)
    attack_paths = find_attack_paths(s3_findings + sg_findings + iam_findings)
    report = build_report(s3_findings, sg_findings, iam_findings, attack_paths)

    # This scenario has an open SSH port + an over-privileged no-MFA admin
    # + a public bucket, so it should trip the correlation engine.
    assert len(report["attack_paths"]) >= 1
    assert report["attack_paths"][0]["severity"] == "Critical"

    # --- Assertions ---
    fail_resources = {f["resource"] for f in report["findings"] if f["status"] == "FAIL"}

    assert "s3://totally-public-bucket" in fail_resources
    assert not any(
        f["resource"] == "s3://locked-down-bucket" and f["status"] == "FAIL"
        for f in report["findings"]
    )
    assert any("bad-sg" in r for r in fail_resources)
    assert "iam-user/risky-admin" in fail_resources

    assert report["risk_score"] < 100
    assert report["severity_counts"]["Critical"] >= 2  # public bucket + SSH open + no MFA

    print("\nRisk score:", report["risk_score"], "| Grade:", report["grade"])
    print("Total findings:", len(report["findings"]), "| Failed:", report["totals"]["failed"])
