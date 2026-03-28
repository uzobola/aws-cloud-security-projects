#!/usr/bin/env python3
import aws_cdk as cdk

from assumerole_alerting.assumerole_alerting_stack import AssumeRoleAlertingStack

app = cdk.App()

AssumeRoleAlertingStack(
    app,
    "AssumeRoleAlertingStack",
    env=cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region"),
    ),
)

app.synth()