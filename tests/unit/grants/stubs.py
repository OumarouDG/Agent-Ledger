"""Shared offline helpers: a stubbed DynamoDB client and raw grant items. All values are fakes."""

from __future__ import annotations

import boto3
from botocore.stub import Stubber

TABLE = "agentledger-grants-test"
NOW = 1_800_000_000  # fake clock, unix seconds
FUTURE = NOW + 3600
PAST = NOW - 1


def stubbed_client():
    client = boto3.client("dynamodb", region_name="us-east-1",
                          aws_access_key_id="fake", aws_secret_access_key="fake")
    return client, Stubber(client)


def expect_get(stubber: Stubber, grant_id: str, item: dict | None) -> None:
    """Queue one GetItem; the stub refuses the call unless ConsistentRead=True."""
    expected = {"TableName": TABLE, "Key": {"grant_id": {"S": grant_id}}, "ConsistentRead": True}
    stubber.add_response("get_item", {"Item": item} if item is not None else {}, expected)


def item(gid: str = "gr_test1", **overrides) -> dict:
    """A well-formed raw item; an override of None removes that attribute."""
    base = {
        "grant_id": {"S": gid},
        "agent_id": {"S": "agent_coder"},
        "workflow_id": {"S": "wf_test"},
        "human_id": {"S": "alice"},
        "status": {"S": "active"},
        "expires_at": {"N": str(FUTURE)},
        "tools": {"L": [{"S": "get_issue"}]},
        "delegable_tools": {"L": []},
        "resources": {"M": {"repository": {"S": "acme/demo"}}},
    }
    for k, v in overrides.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return base
