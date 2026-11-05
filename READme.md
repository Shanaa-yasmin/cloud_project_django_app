# BlastRadius

**SSRF-to-cloud-metadata detection, impact analysis, and remediation pipeline.**

BlastRadius detects Server-Side Request Forgery (SSRF) vulnerabilities capable of reaching AWS's cloud metadata service, exploits them to demonstrate real credential theft, quantifies exactly what an attacker would gain (blast-radius analysis via IAM policy simulation), and generates remediation — all wired into a CI/CD gate and visualized in a dashboard.

This mirrors the real-world attack pattern behind the 2019 Capital One breach: SSRF → cloud metadata service → stolen IAM credentials → unauthorized access to cloud resources.

---

## Why this project

SSRF detection tools and AWS's own IAM tooling already exist individually. This project's value isn't novel vulnerability detection — it's the **pipeline connecting detection, real impact quantification, and remediation into one workflow**, which existing tools don't do together. Most scanners stop at "SSRF found here." This goes further: *exactly* what can an attacker do with it, and here's the fix.

---

## Architecture

```
Scan Engine → Blast-Radius Analyzer → Remediation Engine
     ↓                  ↓                     ↓
  CI/CD Gate      (real stolen        (IMDSv2 fix +
 (GitHub Actions)  credentials)      Access Analyzer)
     ↓                  ↓                     ↓
              Dashboard (React + Django)
```

**Stage 1 — Scan Engine** (`scanner.py`)
Crawls the target app, tests discovered and common parameter names (GET query params and JSON POST bodies) for SSRF, then checks confirmed-vulnerable endpoints for internal network reachability and cloud metadata reachability (including IMDSv1 vs IMDSv2 detection).

**Stage 2 — Blast-Radius Analyzer** (`blast_radius.py`)
Takes a confirmed metadata-reachable finding, steals the role's real temporary credentials through the actual exploit path, then uses `boto3` + `iam:SimulatePrincipalPolicy` to compute exactly what those credentials can access (S3 buckets, other services), producing a weighted risk score.

**Stage 3 — Remediation Engine** (`remediation_imds.py`, `remediation_iam.py`)
- IMDSv2 enforcement: checks the instance's metadata configuration and generates the exact CLI/Terraform fix if IMDSv1 is still allowed.
- IAM least-privilege: integrates with AWS Access Analyzer's policy generation API to recommend a narrower IAM policy based on real CloudTrail activity, rather than reimplementing least-privilege diffing logic.

**CI/CD Integration** (`.github/workflows/ssrf-scan.yml`)
Runs the scanner on every push and fails the build if a critical finding (metadata reachable) is detected — verified working in both directions (blocks a vulnerable build, passes a remediated one).

**Dashboard** (`core/dashboard_views.py`, `core/templates/dashboard.html`)
A Django-served, React-powered (via CDN, no build step) single-page dashboard displaying scan findings, blast-radius results, and remediation recommendations.

---

## Setup

```bash
python -m venv venv
venv\Scripts\Activate.ps1       # Windows
pip install -r requirements.txt
```

Configure AWS credentials locally (`aws configure`) with an IAM user that has admin access to your sandbox AWS account — this is used by the remediation scripts and for reading infrastructure state, separate from the deliberately narrow, exploited demo role.

Set `TARGET_BASE` in `scanner.py` and `blast_radius.py` to your deployed vulnerable app's URL.

### Running the pipeline
```bash
python scanner.py           # Stage 1
python blast_radius.py      # Stage 2 (requires a metadata-reachable finding)
python remediation_imds.py  # Stage 3a
python remediation_iam.py   # Stage 3b (see Known Limitations)
```

### Running the dashboard
```bash
python manage.py runserver
```
Visit `http://127.0.0.1:8000/`

### CI/CD
Add a repository secret `SCAN_TARGET_BASE` (your deployed target's URL) under Settings → Secrets and variables → Actions. The workflow runs automatically on push, or manually via Actions → Run workflow.

---

## Scope — what this project does and does not do

**This project specifically targets one vulnerability class:** SSRF chained to cloud metadata credential theft. It is **not** a general vulnerability scanner — it does not check for SQL injection, XSS, dependency vulnerabilities, or misconfigurations unrelated to this specific attack chain.

**The scanner does not find every SSRF vulnerability in an app.** Like any automated scanner, it tests known patterns (common parameter names, GET and JSON POST bodies, on crawlable endpoints) — it cannot discover SSRF behind authentication, in JavaScript-rendered forms, or using unpredictable parameter names. No automated tool — this one or any commercial equivalent — can claim exhaustive coverage.

**The remediation addresses the consequence of SSRF, not the underlying code flaw.** IMDSv2 enforcement and IAM least-privilege tightening reduce what an attacker gains *if* SSRF is exploited — they don't fix the vulnerable application code itself (which would require input validation, URL allowlisting, or IP-range blocking at the application layer — a separate, code-level fix outside this pipeline's scope).

**This pipeline is scoped to AWS accounts under the operator's own administrative control.** The blast-radius and remediation stages require legitimate IAM access to inspect and act on the exploited role — running this against infrastructure you don't own or have authorization to test would be unauthorized access, not security testing.

---

## Known limitations

- **IAM Access Analyzer integration (`remediation_iam.py`)**: the integration code is complete and correctly implements the full async policy-generation workflow (job submission, polling, result extraction). During testing, it consistently failed with `AUTHORIZATION_ERROR` despite correctly configuring the access role's IAM policy, the CloudTrail bucket's resource policy, and the role's trust policy — likely requiring CloudTrail Data Events (a paid feature) rather than the free Management Events used here. The dashboard gracefully reports this as "not available" rather than failing silently.
- **Scan result ambiguity**: the scanner currently cannot distinguish between "target unreachable" and "target secure" — both result in a clean "no findings" result. A production version would add explicit connectivity validation before running security checks.
- **Single-instance CI/CD testing**: the CI workflow depends on the target EC2 instance being running and reachable at scan time; it isn't itself kept persistently running as part of this project's scope.

---

## Tech stack

Python, Django, boto3, BeautifulSoup4, React (CDN), GitHub Actions, AWS (EC2, IAM, S3, CloudTrail, Access Analyzer)

---

## Disclaimer

Built entirely against a personal AWS sandbox account with a deliberately vulnerable test application created for this purpose. Not tested against, and not intended for use against, any infrastructure the operator does not own or have explicit authorization to test.