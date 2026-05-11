import json
import os
import boto3

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# Optional comma-separated allowlist of known automation or service role ARNs.
# These roles are treated as Low severity because their AssumeRole activity is
# expected and approved. This list should be maintained intentionally as part of
# IAM governance, not auto-discovered.
TRUSTED_ROLE_ARNS = [
    arn.strip()
    for arn in os.environ.get("TRUSTED_ROLE_ARNS", "").split(",")
    if arn.strip()
]


def safe_get(data, path, default="N/A"):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def calculate_severity(principal_account, target_account, principal_arn, role_arn):
    """
    Classify AssumeRole activity based on trust context and account boundaries.

    Why this matters:
    AssumeRole is common in AWS, so alerting on every event with the same
    priority creates noise. Severity scoring helps separate expected automation
    from cross-account access patterns that may indicate lateral movement,
    privilege escalation, or credential misuse.

    Severity rules:
    - Low: principal ARN or target role ARN is explicitly allowlisted
    - High: principal account differs from target account
    - Medium: principal account matches target account or account context is incomplete
    """
    if principal_arn in TRUSTED_ROLE_ARNS or role_arn in TRUSTED_ROLE_ARNS:
        return "Low"

    if principal_account != "N/A" and target_account != "N/A":
        if principal_account != target_account:
            return "High"

    return "Medium"
    print(f"Severity: {severity}")

def build_message(event):
    detail = event.get("detail", {})

    event_time = detail.get("eventTime", "N/A")
    event_name = detail.get("eventName", "N/A")
    aws_region = detail.get("awsRegion", event.get("region", "N/A"))
    account_id = detail.get("recipientAccountId", event.get("account", "N/A"))
    source_ip = detail.get("sourceIPAddress", "N/A")
    user_agent = detail.get("userAgent", "N/A")

    principal_type = safe_get(detail, ["userIdentity", "type"])
    principal_arn = safe_get(detail, ["userIdentity", "arn"])
    principal_account = safe_get(detail, ["userIdentity", "accountId"])

    role_arn = safe_get(detail, ["requestParameters", "roleArn"])
    role_session_name = safe_get(detail, ["requestParameters", "roleSessionName"])

    severity = calculate_severity(
        principal_account=principal_account,
        target_account=account_id,
        principal_arn=principal_arn,
        role_arn=role_arn,
    )

    subject = f"[AWS Alert][{severity}] AssumeRole detected in account {account_id}"

    body = f"""AWS AssumeRole activity detected.

Time:               {event_time}
Event Name:         {event_name}
Account ID:         {account_id}
Region:             {aws_region}
Source IP:          {source_ip}
User Agent:         {user_agent}

Principal Type:     {principal_type}
Principal ARN:      {principal_arn}
Principal Account:  {principal_account}

Target Role ARN:    {role_arn}
Role Session Name:  {role_session_name}
Severity:           {severity}
"""

    return subject[:100], body


def lambda_handler(event, context):
    print(json.dumps(event))

    subject, body = build_message(event)

    response = sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body,
    )

    return {
        "statusCode": 200,
        "messageId": response["MessageId"],
    }
