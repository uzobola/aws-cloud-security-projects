import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_cloud_security_projects.aws_cloud_security_projects_stack import AwsCloudSecurityProjectsStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_cloud_security_projects/aws_cloud_security_projects_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsCloudSecurityProjectsStack(app, "aws-cloud-security-projects")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
