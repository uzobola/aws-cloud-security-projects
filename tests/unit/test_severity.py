import os
import sys
import importlib
from pathlib import Path


# Add the lambda directory to Python's import path so we can import handler.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAMBDA_DIR = PROJECT_ROOT / "lambda"
sys.path.insert(0, str(LAMBDA_DIR))


# The handler module expects SNS_TOPIC_ARN to exist at import time.
# In AWS, CDK injects this as a Lambda environment variable.
# Locally, we provide a safe fake value so the module can be imported.
os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test-topic"


def load_handler_with_trusted_roles(trusted_roles=""):
    """
    Reload handler.py with a specific TRUSTED_ROLE_ARNS value.

    Why this matters:
    TRUSTED_ROLE_ARNS is read when the module imports. Reloading lets us test
    different allowlist configurations without deploying to AWS.
    """
    os.environ["TRUSTED_ROLE_ARNS"] = trusted_roles

    if "handler" in sys.modules:
        del sys.modules["handler"]

    return importlib.import_module("handler")


def test_cross_account_assume_role_is_high():
    handler = load_handler_with_trusted_roles()

    severity = handler.calculate_severity(
        principal_account="111111111111",
        target_account="222222222222",
        principal_arn="arn:aws:iam::111111111111:user/alice",
        role_arn="arn:aws:iam::222222222222:role/AdminRole",
    )

    assert severity == "High"


def test_same_account_assume_role_is_medium():
    handler = load_handler_with_trusted_roles()

    severity = handler.calculate_severity(
        principal_account="111111111111",
        target_account="111111111111",
        principal_arn="arn:aws:iam::111111111111:user/alice",
        role_arn="arn:aws:iam::111111111111:role/ReadOnlyRole",
    )

    assert severity == "Medium"


def test_trusted_role_is_low():
    trusted_role = "arn:aws:iam::111111111111:role/GitHubActionsDeploymentRole"
    handler = load_handler_with_trusted_roles(trusted_roles=trusted_role)

    severity = handler.calculate_severity(
        principal_account="111111111111",
        target_account="222222222222",
        principal_arn="arn:aws:iam::111111111111:user/alice",
        role_arn=trusted_role,
    )

    assert severity == "Low"