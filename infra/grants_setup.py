"""Create the AgentLedger grants table in DynamoDB. Idempotent: a second run says "exists".

Table `agentledger-grants`: PK `grant_id` (S), on-demand billing,
GSI `workflow_id-index` on `workflow_id` (S), all attributes projected.
Region comes from shared/cognito.json.

Usage: python infra/grants_setup.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
from botocore.exceptions import BotoCoreError, ClientError  # noqa: E402

from controlplane.auth.config import load_config  # noqa: E402
from controlplane.grants.store import TABLE_NAME, WORKFLOW_INDEX  # noqa: E402

GSI_WAIT_SECONDS = 300


def code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


def describe(client, table: str) -> dict | None:
    try:
        return client.describe_table(TableName=table)["Table"]
    except ClientError as e:
        if code(e) == "ResourceNotFoundException":
            return None
        raise


def create(client, table: str) -> None:
    client.create_table(
        TableName=table,
        AttributeDefinitions=[
            {"AttributeName": "grant_id", "AttributeType": "S"},
            {"AttributeName": "workflow_id", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "grant_id", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        GlobalSecondaryIndexes=[{
            "IndexName": WORKFLOW_INDEX,
            "KeySchema": [{"AttributeName": "workflow_id", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
    )


def gsi_status(desc: dict) -> str | None:
    for gsi in desc.get("GlobalSecondaryIndexes", []):
        if gsi["IndexName"] == WORKFLOW_INDEX:
            return gsi.get("IndexStatus")
    return None


def wait_active(client, table: str) -> dict:
    client.get_waiter("table_exists").wait(TableName=table)
    deadline = time.time() + GSI_WAIT_SECONDS
    while True:
        desc = describe(client, table)
        if desc and desc["TableStatus"] == "ACTIVE" and gsi_status(desc) == "ACTIVE":
            return desc
        if time.time() > deadline:
            raise TimeoutError(f"{table} or {WORKFLOW_INDEX} not ACTIVE after {GSI_WAIT_SECONDS} s")
        time.sleep(5)


def main() -> int:
    region = load_config()["region"]
    client = boto3.client("dynamodb", region_name=region)
    try:
        desc = describe(client, TABLE_NAME)
        if desc is None:
            print(f"creating table {TABLE_NAME} in {region} ...")
            create(client, TABLE_NAME)
            desc = wait_active(client, TABLE_NAME)
            print(f"  created table: {TABLE_NAME} status={desc['TableStatus']}")
        else:
            print(f"  table exists: {TABLE_NAME} status={desc['TableStatus']}")
    except (ClientError, BotoCoreError) as e:
        why = code(e) if isinstance(e, ClientError) else type(e).__name__
        print(f"Can't reach AWS ({why}). Paste fresh Workshop Studio credentials and retry.")
        return 1

    status = gsi_status(desc)
    billing = desc.get("BillingModeSummary", {}).get("BillingMode", "unknown")
    keys = [(k["AttributeName"], k["KeyType"]) for k in desc["KeySchema"]]
    print(f"  key={keys} billing={billing}")
    if status is None:
        print(f"WARNING: {TABLE_NAME} has no {WORKFLOW_INDEX}; `grant list --workflow` will fail. "
              f"Run infra/grants_teardown.py, then this script again.")
        return 1
    print(f"  index {WORKFLOW_INDEX}: {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
