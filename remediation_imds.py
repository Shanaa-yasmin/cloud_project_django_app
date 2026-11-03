"""
IMDSv2 Remediation Template

Checks whether a given EC2 instance enforces IMDSv2 (token-required metadata
access). If IMDSv1 is still allowed ("optional"), generates the exact fix as
both an AWS CLI command and a Terraform snippet.

This uses your personal admin IAM credentials (via the default boto3 session /
AWS CLI config), NOT the stolen credentials from blast_radius.py — checking
and fixing instance configuration requires ec2:DescribeInstances and
ec2:ModifyInstanceMetadataOptions, which the deliberately-narrow demo role
should not have.
"""

import boto3
import json
from datetime import datetime, timezone

INSTANCE_ID = "i-04459a5b9931f6f43"  # your SSRF_demo instance
AWS_REGION = "us-east-1"
OUTPUT_FILE = "remediation_imds_results.json"


def get_metadata_options(instance_id, region=AWS_REGION):
    """Query the instance's current IMDS configuration."""
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances(InstanceIds=[instance_id])

    reservations = resp.get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        raise ValueError(f"Instance {instance_id} not found")

    instance = reservations[0]["Instances"][0]
    metadata_options = instance.get("MetadataOptions", {})

    return {
        "instance_id": instance_id,
        "http_tokens": metadata_options.get("HttpTokens"),       # "required" | "optional"
        "http_endpoint": metadata_options.get("HttpEndpoint"),    # "enabled" | "disabled"
        "http_put_response_hop_limit": metadata_options.get("HttpPutResponseHopLimit"),
    }


def generate_remediation(metadata_state):
    """Given the current state, decide if a fix is needed and generate it."""
    instance_id = metadata_state["instance_id"]
    http_tokens = metadata_state["http_tokens"]

    finding = {
        "check": "imds_v2_enforcement",
        "instance_id": instance_id,
        "current_http_tokens": http_tokens,
        "vulnerable": http_tokens != "required",
    }

    if not finding["vulnerable"]:
        finding["severity"] = "info"
        finding["message"] = "IMDSv2 is already enforced (http_tokens=required). No action needed."
        finding["remediation"] = None
        return finding

    finding["severity"] = "critical"
    finding["message"] = (
        "IMDSv1 is still reachable (http_tokens is not 'required'), which allows "
        "credential theft via simple SSRF (no token/PUT request needed). "
        "Enforcing IMDSv2 requires the attacker to perform a token-based PUT "
        "request first, which most basic SSRF vectors cannot do."
    )

    cli_fix = (
        f"aws ec2 modify-instance-metadata-options "
        f"--instance-id {instance_id} "
        f"--http-tokens required "
        f"--http-endpoint enabled "
        f"--region {AWS_REGION}"
    )

    terraform_fix = f'''resource "aws_instance" "this" {{
  # ... existing instance configuration ...

  metadata_options {{
    http_tokens                 = "required"
    http_endpoint                = "enabled"
    http_put_response_hop_limit = 1
  }}
}}

# If managing metadata options independently of the instance resource:
resource "aws_instance_metadata_defaults" "this" {{
  http_tokens   = "required"
  http_endpoint = "enabled"
}}'''

    finding["remediation"] = {
        "type": "imds_v2_enforcement",
        "cli_command": cli_fix,
        "terraform_snippet": terraform_fix,
        "apply_mode": "suggest",  # never auto-apply without human review
    }

    return finding


def apply_remediation(instance_id, region=AWS_REGION, confirm=False):
    """Actually apply the fix. Requires explicit confirm=True — never runs silently."""
    if not confirm:
        raise RuntimeError(
            "Refusing to apply remediation without explicit confirm=True. "
            "This is a deliberate safety gate — review the suggested fix first."
        )

    ec2 = boto3.client("ec2", region_name=region)
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpEndpoint="enabled",
    )
    return {"applied": True, "instance_id": instance_id, "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    state = get_metadata_options(INSTANCE_ID)
    print("Current metadata configuration:")
    print(json.dumps(state, indent=2))

    finding = generate_remediation(state)
    print("\nRemediation finding:")
    print(json.dumps(finding, indent=2))

    with open(OUTPUT_FILE, "w") as f:
        json.dump(finding, f, indent=2)
    print(f"\nSaved to {OUTPUT_FILE}")

    # Example of applying it yourself, only when ready (uncomment to use):
    # if finding["vulnerable"]:
    #     result = apply_remediation(INSTANCE_ID, confirm=True)
    #     print(json.dumps(result, indent=2))