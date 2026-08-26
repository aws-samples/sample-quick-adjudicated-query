#!/usr/bin/env python3
"""CDK app entry point for the Quick lease-compliance PoC.

Region is pinned to us-east-1 to match the Amazon Quick subscription -- Quick Sight's VPC
connection to Aurora (task 8) is region-local, so this is not a free choice.
"""

import os

import aws_cdk as cdk

from infra.stack import QuickPocStack

app = cdk.App()

QuickPocStack(
    app,
    "QuickPocStack",
    env=cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region="us-east-1",
    ),
    description="Lease compliance PoC: MCP server for Amazon Quick (synthetic data only)",
    tags={
        "project": "quick-lease-compliance-poc",
        "environment": "sandbox",
        "data-classification": "synthetic-only",
    },
)

app.synth()
