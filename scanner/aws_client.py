"""
aws_client.py
Central place that creates read-only boto3 clients for the scanner.

Mini-CSPM NEVER calls any mutating AWS API. Every client here is only
ever used with Describe*/List*/Get* calls.
"""

import boto3


def get_session(profile: str = None, region: str = "us-east-1") -> boto3.Session:
    """
    Build a boto3 session.

    - profile: name of an AWS CLI profile configured in ~/.aws/credentials
               (leave as None to use the default profile / env vars)
    - region:  AWS region to scan (S3 is global-ish but bucket location
               lookups and SG/IAM calls need a region)
    """
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    return boto3.Session(region_name=region)


def get_clients(session: boto3.Session) -> dict:
    """Return the three read-only service clients the scanner needs."""
    return {
        "s3": session.client("s3"),
        "ec2": session.client("ec2"),
        "iam": session.client("iam"),
    }
