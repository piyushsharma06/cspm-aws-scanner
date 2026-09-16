"""
sg_checks.py
Read-only checks against every EC2 Security Group in the region.

Maps loosely to CIS AWS Foundations Benchmark:
  5.2 - Security Groups do not allow ingress from 0.0.0.0/0 to port 22 (SSH)
  5.3 - Security Groups do not allow ingress from 0.0.0.0/0 to port 3389 (RDP)
  (extended here to common DB ports as well, since that's a very common
   real-world misconfiguration Prisma-style tools flag)
"""

RISKY_PORTS = {
    22: ("SSH", "Critical"),
    3389: ("RDP", "Critical"),
    3306: ("MySQL", "High"),
    5432: ("PostgreSQL", "High"),
    1433: ("MSSQL", "High"),
    27017: ("MongoDB", "High"),
    6379: ("Redis", "High"),
    9200: ("Elasticsearch", "High"),
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_in_range(port: int, from_port, to_port) -> bool:
    if from_port is None or to_port is None:
        # Rule with no port restriction (e.g. -1 protocol = all traffic)
        return True
    return from_port <= port <= to_port


def run_sg_checks(ec2_client) -> list[dict]:
    findings = []

    try:
        paginator = ec2_client.get_paginator("describe_security_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
    except Exception as e:
        findings.append({
            "resource": "EC2 (account)",
            "check": "SG.DESCRIBE",
            "status": "ERROR",
            "severity": "N/A",
            "detail": f"Could not list security groups: {e}",
            "cis_control": "N/A",
            "fix": "Ensure the scanning role has ec2:DescribeSecurityGroups permission.",
        })
        return findings

    for sg in groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        resource = f"{sg_name} ({sg_id})"

        open_to_world = False
        flagged_ports = []

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            protocol = perm.get("IpProtocol")

            ranges = [r["CidrIp"] for r in perm.get("IpRanges", [])] + \
                     [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]

            is_open = any(r in OPEN_CIDRS for r in ranges)
            if not is_open:
                continue

            open_to_world = True

            if protocol == "-1":
                flagged_ports.append(("ALL", "Critical"))
                continue

            for port, (label, sev) in RISKY_PORTS.items():
                if _port_in_range(port, from_port, to_port):
                    flagged_ports.append((f"{label} ({port})", sev))

        if flagged_ports:
            worst_sev = "Critical" if any(s == "Critical" for _, s in flagged_ports) else "High"
            ports_desc = ", ".join(sorted({p for p, _ in flagged_ports}))
            findings.append({
                "resource": resource,
                "check": "SG_OPEN_TO_WORLD_RISKY_PORT",
                "status": "FAIL",
                "severity": worst_sev,
                "detail": f"Open to 0.0.0.0/0 on sensitive port(s): {ports_desc}",
                "cis_control": "CIS 5.2 / 5.3",
                "fix": "Restrict inbound rules to known IP ranges (e.g. office/VPN CIDR) "
                       "instead of 0.0.0.0/0, especially for SSH/RDP/DB ports.",
            })
        elif open_to_world:
            findings.append({
                "resource": resource,
                "check": "SG_OPEN_TO_WORLD_OTHER_PORT",
                "status": "WARN",
                "severity": "Medium",
                "detail": "Open to 0.0.0.0/0 on a non-sensitive port",
                "cis_control": "General hardening",
                "fix": "Confirm this port genuinely needs to be public "
                       "(e.g. 80/443 on a web server); otherwise restrict it.",
            })
        else:
            findings.append({
                "resource": resource,
                "check": "SG_OPEN_TO_WORLD",
                "status": "PASS",
                "severity": "Info",
                "detail": "No rules open to 0.0.0.0/0",
                "cis_control": "CIS 5.2 / 5.3",
                "fix": "",
            })

    return findings
