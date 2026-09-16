# Mini-CSPM

**A read-only AWS Cloud Security Posture Scanner** — finds misconfigurations in S3, EC2 Security Groups and IAM, and scores them against a CIS AWS Foundations Benchmark-style rubric.

Built as a hands-on demonstration of the same problem space Prisma Cloud (CSPM) solves: continuously verifying that cloud resources are configured safely, not just that the network perimeter is secure.

---

## What it does

```
AWS Account (S3 · Security Groups · IAM)
              │
              ▼
   Python Scanner (boto3, read-only)
   checks vs. CIS AWS Foundations Benchmark
              │
              ▼
     Risk Report (JSON + Streamlit dashboard)
     scored findings + fix recommendations
```

1. **Scan** — discovers every S3 bucket, EC2 security group, and IAM user in the account.
2. **Detect** — runs each resource through CIS-style checks (see table below).
3. **Report** — produces a weighted risk score (0–100), a letter grade, and a fix for every failing check.

The scanner **never calls a mutating AWS API**. Every call is a `Describe*` / `List*` / `Get*` call — see [`iam-read-only-policy.json`](iam-read-only-policy.json) for the exact, minimal permission set it needs.

---

## Checks implemented

| Area | Check | CIS Control | Severity |
|---|---|---|---|
| S3 | Bucket allows public access (ACL or missing Block Public Access) | 2.1.2 | Critical |
| S3 | Bucket has no default encryption | 2.1.3 | Medium |
| Security Groups | Ingress open to `0.0.0.0/0` on SSH/RDP/DB ports | 5.2 / 5.3 | Critical / High |
| Security Groups | Ingress open to `0.0.0.0/0` on other ports | General hardening | Medium |
| IAM | User has console password but no MFA | 1.10 | Critical |
| IAM | User has `AdministratorAccess` (direct or via group) | 1.16 | High |

---

## Setup

```bash
git clone <this-repo>
cd mini-cspm
pip install -r requirements.txt
```

### AWS credentials

Create a dedicated IAM user/role for the scanner and attach only the permissions in
[`iam-read-only-policy.json`](iam-read-only-policy.json) — don't use your admin credentials.

```bash
aws configure --profile mini-cspm
# paste the scanner's Access Key ID / Secret Access Key when prompted
```

---

## Usage

**Run a real scan against your AWS account:**
```bash
python main.py --profile mini-cspm --region ap-south-1 --output report.json
```

This prints a summary to the terminal and writes the full findings to `report.json`.

**View the results in the dashboard:**
```bash
streamlit run report/dashboard.py
```
Point the sidebar's "Report JSON path" field at `report.json` (or leave it on `sample_report.json` to see a pre-baked demo report without needing AWS access at all).

**Run the test suite** (uses `moto` to mock AWS — no real account or network access needed):
```bash
pytest -v tests/
```

---

## Project structure

```
mini-cspm/
├── main.py                    # CLI entry point — runs the scan end to end
├── scanner/
│   ├── aws_client.py          # boto3 session/client setup (read-only)
│   ├── s3_checks.py           # public access + encryption checks
│   ├── sg_checks.py           # open security group checks
│   ├── iam_checks.py          # MFA + excessive privilege checks
│   └── scoring.py             # weighted risk scoring engine
├── report/
│   └── dashboard.py           # Streamlit dashboard
├── tests/
│   └── test_scanner.py        # end-to-end test using moto (mocked AWS)
├── iam-read-only-policy.json  # least-privilege policy the scanner needs
├── sample_report.json         # pre-baked demo report (no AWS needed)
└── requirements.txt
```

---

## Why this matters (mapping to CSPM tools like Prisma Cloud)

| Mini-CSPM | Prisma Cloud equivalent |
|---|---|
| CIS-style checks on S3/SG/IAM | Policy engine checking hundreds of rules across every major cloud provider |
| Weighted risk score per account | Compliance dashboards & posture scores across the whole org |
| JSON findings with a suggested fix | Findings with remediation guidance, some auto-remediable |
| Single-account, on-demand scan | Continuous, multi-account, multi-cloud monitoring |

Mini-CSPM is intentionally the smallest version of this problem: it proves out the core loop (discover → check against a benchmark → score → recommend a fix) that every CSPM product is built around.

## Attack-path correlation

Beyond individual checks, Mini-CSPM includes a lightweight **correlation layer**
(`scanner/correlation.py`) that looks across all findings in a scan and flags
when they combine into a realistic attack path:

```
Internet -> open SSH/RDP security group -> over-privileged/no-MFA IAM user -> public S3 bucket
```

Instead of three separate High/Critical alerts, this becomes one Critical
"attack path" finding with its own explanation and fix — the dashboard
surfaces it in a dedicated "Correlated Attack Paths" section above the
regular findings list.

**Honest scope note:** this is *account-level pattern correlation* — it
detects that these three categories of weakness co-exist somewhere in the
account. It does not yet trace a *specific* EC2 instance to its *exact*
attached IAM role to the *exact* S3 buckets that role's policy can reach
(true resource-graph correlation). That would require adding
`ec2:DescribeInstances` / instance-profile checks and IAM policy simulation —
see Future enhancements below.

## Future enhancements

- **Resource-graph correlation** — trace specific EC2 instance → its exact IAM role → the exact S3 buckets that role's policy permits, instead of account-level pattern matching.
- **Multi-cloud support** — extend the same check/score pattern to Azure and GCP.
- **Auto-remediation** — for safe, low-risk findings (e.g. flip Block Public Access on), offer a `--fix` flag.
- **Continuous monitoring** — run on a schedule (e.g. via a Lambda + EventBridge cron) instead of on-demand only, and diff findings run-over-run.

---

## Author

Piyush Sharma — B.Tech CSE (Cybersecurity), G.L. Bajaj Institute of Technology and Management
