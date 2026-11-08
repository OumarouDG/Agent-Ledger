"""Delete the AgentLedger grants table and every grant in it. Asks first; cannot be undone."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from controlplane.auth.config import load_config  # noqa: E402
from controlplane.grants.store import TABLE_NAME  # noqa: E402


def main() -> int:
    region = load_config()["region"]
    if input(f"Delete DynamoDB table {TABLE_NAME} in {region} and every grant in it? "
             "Type 'delete': ").strip() != "delete":
        print("Cancelled.")
        return 1
    client = boto3.client("dynamodb", region_name=region)
    try:
        client.delete_table(TableName=TABLE_NAME)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            print(f"No table {TABLE_NAME}; nothing to delete.")
            return 0
        raise
    client.get_waiter("table_not_exists").wait(TableName=TABLE_NAME)
    print(f"deleted table {TABLE_NAME}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
