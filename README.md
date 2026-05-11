# IAM Cross-Account Detection Pipeline

Hands-on AWS cloud security engineering projects focused on identity monitoring, detection engineering, and security automation with Python CDK.

---

## Featured Project: Real-Time AssumeRole Detection Pipeline

Detects AWS `AssumeRole` activity from CloudTrail in near real time, extracts investigation-relevant context, and delivers a formatted SNS email alert for rapid triage.

**Stack:** CloudTrail → EventBridge → Lambda → SNS  
**IaC:** AWS CDK (Python)

---

## Why AssumeRole matters

`AssumeRole` is a high-signal identity event that can appear in credential theft, lateral movement, privilege escalation, and cross-account access abuse scenarios. Near-real-time visibility improves investigation speed and reduces time-to-detect.

---

## What this demonstrates

- AWS-native detection engineering
- Identity-focused monitoring in AWS
- Event-driven security automation
- Serverless alerting with Lambda
- Infrastructure as code with Python CDK

---

## Threat-informed detection mapping

This detection is mapped to adversary behaviors described in the MITRE ATT&CK framework.

| Framework | Technique | Why it matters |
|---|---|---|
| MITRE ATT&CK | T1078 - Valid Accounts | AssumeRole activity can indicate use of valid cloud credentials for persistence, privilege escalation, or lateral movement. |
| MITRE ATT&CK | T1550.001 - Application Access Token | Temporary credentials and session-based access can be abused when attackers obtain or replay valid authentication material. |

AssumeRole is a normal AWS operation, so the goal is not to treat every event as malicious. The goal is to identify role assumption activity that deserves faster review based on account boundaries, known automation, and risk context.

---

## Severity scoring

The Lambda function adds basic severity scoring so the alert is more actionable.

| Severity | Condition | Triage meaning |
|---|---|---|
| High | Principal account differs from the target role account | Potential cross-account access risk requiring faster review. |
| Medium | Principal account matches the target role account | Expected same-account role activity, but still useful for audit and monitoring. |
| Low | Principal ARN or target role ARN is explicitly allowlisted | Known automation or approved service role activity. |

This reduces alert noise by separating expected automation from higher-risk cross-account AssumeRole activity.

---

## Trusted role allowlist

Known automation or approved service roles can be passed into the Lambda function using the `TRUSTED_ROLE_ARNS` environment variable. In this CDK project, the value can be supplied through CDK context:

```bash
cdk deploy \
  -c alert_email=you@example.com \
  -c trusted_roles=arn:aws:iam::123456789012:role/GitHubActionsDeploymentRole,arn:aws:iam::123456789012:role/SecurityAuditRole
```

The allowlist is intentionally configured by the security team or cloud owner. It is not auto-discovered. This keeps the classification decision tied to approved IAM governance rather than assuming every existing role is trusted.

---

## Compliance and control mapping

This detection also supports security monitoring and audit evidence use cases by mapping AWS identity activity to common control frameworks.

| Framework | Control | How this project supports it |
|---|---|---|
| NIST CSF | DE.CM-3 | Monitors personnel activity through CloudTrail AssumeRole events and generates near-real-time alerts. |
| SOC 2 | CC7.2 | Detects anomalous identity activity and provides alert context for investigation and risk assessment. |
| CIS Controls | Audit Log Management | Uses CloudTrail events to support log-based monitoring, alerting, and review of security-relevant activity. |

This creates a bridge between detection engineering and GRC by showing how cloud telemetry can produce evidence for security monitoring and control effectiveness.

---

## Architecture

![Real-Time AWS AssumeRole Detection and Alerting Architecture](evidence/architecture-diagram.png)

Pipeline flow:

```text
CloudTrail (API events)
    → EventBridge (AssumeRole filter)
        → Lambda (parse + enrich)
            → SNS (email alert)
```

### EventBridge rule pattern
```json
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": ["AssumeRole"]
  }
}
```

---

## Alert fields

Each alert includes:

- Event time and name
- Account ID and region
- Source IP and user agent
- Principal type and ARN
- Principal account
- Target role ARN
- Role session name
- Severity score

---

## Example alert
```
Subject: [AWS Alert][High] AssumeRole detected in account 123456789012

AWS AssumeRole activity detected.

Time:               2025-03-27T18:42:11Z
Event Name:         AssumeRole
Account ID:         123456789012
Region:             us-east-1
Source IP:          203.0.113.10
User Agent:         aws-cli/2.15.0

Principal Type:     IAMUser
Principal ARN:      arn:aws:iam::111111111111:user/admin-user
Principal Account:  111111111111

Target Role ARN:    arn:aws:iam::123456789012:role/SecurityAuditRole
Role Session Name:  security-audit-session
Severity:           High
```

---

## Evidence

Deployment and testing proof:

- `evidence/01-sns-subscription-confirmed.png` — SNS subscription confirmed
- `evidence/02-cdk-deploy-success.png` — CDK deploy: 15/15 resources CREATE_COMPLETE
- `evidence/03-lambda-test-success.png` — Lambda test: statusCode 200, messageId returned
- `evidence/04-alert-email.png` — Alert email delivered to inbox with full context
- `evidence/05-eventbridge-rule.png` — EventBridge rule enabled and pattern confirmed
- `evidence/06-cloudtrail-trail.png` — CloudTrail trail active and logging

---

## Deploy
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cdk bootstrap
cdk deploy -c alert_email=you@example.com
```

This deploys the CloudTrail trail, EventBridge rule, Lambda function, SNS topic, and email subscription.

After deploy, confirm the SNS subscription email before alerts will arrive.

---

## Roadmap

This project now includes threat mapping, severity scoring, trusted role allowlisting, compliance framework mapping, and unit tests for severity classification. Future improvements will focus on expanding detection coverage and operational resilience.

- Add additional EventBridge detections for root login, IAM policy changes, and S3 public access changes
- Add advanced suspicious activity logic for off-hours access and privileged role usage
- Add remediation guidance directly into SNS alert messages
- Add a dead-letter queue for failed Lambda invocations
- Publish high-severity findings to AWS Security Hub
- Expand unit tests for full CloudTrail event parsing and alert formatting

---

## Repository structure
```
iam-cross-account-detection-pipeline/
├── README.md
├── app.py
├── requirements.txt
├── assumerole_alerting/
│   ├── __init__.py
│   └── assumerole_alerting_stack.py
├── lambda/
│   └── handler.py
├── examples/
│   └── sample-cloudtrail-assumerole-event.json
├── tests/
│   └── unit/
│       └── test_severity.py
└── evidence/
    ├── architecture-diagram.png
    ├── 01-sns-subscription-confirmed.png
    ├── 02-cdk-deploy-success.png
    ├── 03-lambda-test-success.png
    ├── 04-alert-email.png
    └── 05-eventbridge-rule.png
```
