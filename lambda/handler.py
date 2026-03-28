import json
import os
import boto3

sns = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def safe_get(data, path, default="N/A"):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


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

    subject = f"[AWS Alert] AssumeRole detected in account {account_id}"

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
