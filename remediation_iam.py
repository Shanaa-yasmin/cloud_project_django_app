"""
IAM Remediation via AWS Access Analyzer

Rather than reimplementing least-privilege policy diffing, this triggers
AWS Access Analyzer's native policy generation for the exposed role, which
looks at real CloudTrail activity and recommends a narrower policy.

Uses your personal admin credentials (default boto3 session), same as
remediation_imds.py.
"""

import boto3
import json
import time
from datetime import datetime, timezone, timedelta

AWS_REGION = "us-east-1"
ROLE_NAME = "ssrf-demo-app-role"
ACCOUNT_ID = "461776754465"
# The role you created in Part 1 above, that Access Analyzer assumes
# to read your CloudTrail logs.
ACCESS_ANALYZER_SERVICE_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/access-analyzer-policy-gen-role"
CLOUDTRAIL_ARN = f"arn:aws:cloudtrail:{AWS_REGION}:{ACCOUNT_ID}:trail/ssrf-demo-trail"  # adjust to your trail name

OUTPUT_FILE = "remediation_iam_results.json"
POLL_INTERVAL_SECONDS = 15
MAX_POLL_ATTEMPTS = 40  # ~10 minutes total — policy generation can take a while,
                         # especially for a newly-created trail


def get_current_role_policy(iam_client, role_name):
    """Fetch the role's current inline/managed policies, for the 'before' side of the diff."""
    attached = iam_client.list_attached_role_policies(RoleName=role_name)
    inline = iam_client.list_role_policies(RoleName=role_name)

    documents = []
    for policy_name in inline["PolicyNames"]:
        doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        documents.append({"name": policy_name, "type": "inline", "document": doc["PolicyDocument"]})

    for policy in attached["AttachedPolicies"]:
        detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
        version_id = detail["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=version_id)
        documents.append({"name": policy["PolicyName"], "type": "managed", "document": version["PolicyVersion"]["Document"]})

    return documents


def start_policy_generation(analyzer_client, role_arn, lookback_days=7):
    """Kick off Access Analyzer's policy generation job for this role."""
    # Back off end_time by a buffer — CloudTrail delivers logs with a delay
    # (typically 5-15 minutes), so requesting data right up to "now" is rejected
    # since those logs may not be delivered to S3 yet.
    end_dt = datetime.now(timezone.utc) - timedelta(minutes=20)
    start_dt = end_dt - timedelta(days=lookback_days)

    # AWS requires exactly yyyy-MM-dd'T'HH:mm:ssZ (no microseconds, no +00:00 offset) —
    # Python's default isoformat() output doesn't match this, so format explicitly.
    start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    response = analyzer_client.start_policy_generation(
        policyGenerationDetails={"principalArn": role_arn},
        cloudTrailDetails={
            "trails": [
                {
                    "cloudTrailArn": CLOUDTRAIL_ARN,
                    "allRegions": True,
                }
            ],
            "accessRole": ACCESS_ANALYZER_SERVICE_ROLE_ARN,
            "startTime": start_time,
            "endTime": end_time,
        },
    )
    return response["jobId"]


def poll_for_completion(analyzer_client, job_id):
    """Policy generation is async — poll until it's done."""
    for attempt in range(MAX_POLL_ATTEMPTS):
        response = analyzer_client.get_generated_policy(jobId=job_id, includeResourcePlaceholders=True)
        status = response["jobDetails"]["status"]  # IN_PROGRESS | SUCCEEDED | FAILED | CANCELED
        print(f"  [{attempt + 1}/{MAX_POLL_ATTEMPTS}] status: {status}")

        if status == "SUCCEEDED":
            return response
        if status in ("FAILED", "CANCELED"):
            failure_reason = response["jobDetails"].get("jobError", {})
            raise RuntimeError(f"Policy generation job {job_id} ended with status: {status}. Details: {failure_reason}")

        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(f"Policy generation job {job_id} did not complete in time")


def extract_generated_policy(result):
    """Pull the actual generated policy document(s) out of the job result."""
    generated = result.get("generatedPolicyResult", {})
    policies = generated.get("generatedPolicies", [])
    return [p["policy"] for p in policies]  # list of policy documents as JSON strings


def generate_iam_remediation(role_name, existing_job_id=None):
    iam = boto3.client("iam", region_name=AWS_REGION)
    analyzer = boto3.client("accessanalyzer", region_name=AWS_REGION)

    role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"

    current_policies = get_current_role_policy(iam, role_name)

    if existing_job_id:
        # Don't start a new job — AWS limits concurrent policy generation jobs,
        # and a prior run is likely still in progress. Just poll the existing one.
        job_id = existing_job_id
        print(f"Resuming existing job: {job_id}. Polling for completion...")
    else:
        print(f"Starting Access Analyzer policy generation for {role_arn} ...")
        job_id = start_policy_generation(analyzer, role_arn)
        print(f"Job started: {job_id}. Polling for completion...")

    result = poll_for_completion(analyzer, job_id)
    generated_policies = extract_generated_policy(result)

    finding = {
        "check": "iam_least_privilege_recommendation",
        "role_name": role_name,
        "role_arn": role_arn,
        "job_id": job_id,
        "current_policies": current_policies,
        "recommended_policies": [json.loads(p) if isinstance(p, str) else p for p in generated_policies],
        "source": "AWS IAM Access Analyzer (policy generation from CloudTrail activity)",
        "apply_mode": "suggest",
        "note": (
            "This recommendation reflects only the actions observed in CloudTrail during "
            "the lookback window. Review before applying — it may not cover legitimate but "
            "infrequent usage patterns outside that window."
        ),
    }

    return finding


if __name__ == "__main__":
    # Previous job failed due to a missing S3 bucket policy grant (separate from
    # the access role's own IAM policy) — now fixed, so start a fresh job.
    finding = generate_iam_remediation(ROLE_NAME)
    print(json.dumps(finding, indent=2, default=str))

    with open(OUTPUT_FILE, "w") as f:
        json.dump(finding, f, indent=2, default=str)
    print(f"\nSaved to {OUTPUT_FILE}")