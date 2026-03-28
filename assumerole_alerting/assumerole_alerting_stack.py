from pathlib import Path

import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Duration,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as _lambda,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_cloudtrail as cloudtrail,
    aws_s3 as s3,
)


class AssumeRoleAlertingStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        alert_email = self.node.try_get_context("alert_email")
        if not alert_email:
            raise ValueError(
                "Provide alert_email via CDK context: -c alert_email=you@example.com"
            )

        # CloudTrail trail (self-contained — no pre-existing trail needed)
        trail_bucket = s3.Bucket(
            self,
            "CloudTrailBucket",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        cloudtrail.Trail(
            self,
            "SecurityTrail",
            bucket=trail_bucket,
            is_multi_region_trail=False,
            include_global_service_events=True,
        )

        # SNS topic + email subscription
        topic = sns.Topic(
            self,
            "AssumeRoleAlertsTopic",
            topic_name="aws-assumerole-alerts",
        )

        topic.add_subscription(
            subscriptions.EmailSubscription(alert_email)
        )

        # Lambda function
        lambda_code_path = str(
            Path(__file__).resolve().parent.parent / "lambda"
        )

        fn = _lambda.Function(
            self,
            "AssumeRoleAlertFunction",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset(lambda_code_path),
            timeout=Duration.seconds(30),
            environment={
                "SNS_TOPIC_ARN": topic.topic_arn,
            },
            description="Formats CloudTrail AssumeRole events and sends SNS alerts",
        )

        topic.grant_publish(fn)

        # EventBridge rule
        rule = events.Rule(
            self,
            "AssumeRoleEventRule",
            description="Match CloudTrail AssumeRole API calls",
            event_pattern=events.EventPattern(
                source=["aws.sts"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["sts.amazonaws.com"],
                    "eventName": ["AssumeRole"],
                },
            ),
        )

        rule.add_target(targets.LambdaFunction(fn))

        # Outputs
        cdk.CfnOutput(self, "SnsTopicArn", value=topic.topic_arn)
        cdk.CfnOutput(self, "LambdaFunctionName", value=fn.function_name)