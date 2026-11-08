"""Delete the AgentLedger Cognito pool, its domain and the agent secrets. Asks first."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "shared" / "cognito.json"
REGION = os.environ.get("AWS_REGION", "us-east-1")


def main() -> None:
    if not CONFIG.exists():
        sys.exit("No shared/cognito.json; nothing to tear down.")
    cfg = json.loads(CONFIG.read_text())
    pool_id = cfg["user_pool_id"]
    if input(f"Delete user pool {pool_id} and all agent secrets? Type 'delete': ").strip() != "delete":
        sys.exit("Cancelled.")

    cognito = boto3.client("cognito-idp", region_name=cfg.get("region", REGION))
    sm = boto3.client("secretsmanager", region_name=cfg.get("region", REGION))

    domain = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("Domain")
    if domain:
        cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        print(f"deleted domain {domain}")
    cognito.delete_user_pool(UserPoolId=pool_id)
    print(f"deleted pool {pool_id}")

    for agent in cfg.get("agents", {}).values():
        ref = agent.get("secret_ref", "")
        if ref.startswith("secretsmanager:"):
            try:
                sm.delete_secret(SecretId=ref.split(":", 1)[1], ForceDeleteWithoutRecovery=True)
                print(f"deleted secret {ref}")
            except ClientError as e:
                print(f"skip {ref}: {e.response['Error']['Code']}")

    for path in (CONFIG, ROOT / "infra" / "out" / "demo-users.local.json",
                 ROOT / "infra" / "out" / "agent-secrets.local.json"):
        path.unlink(missing_ok=True)
    print("Done.")


if __name__ == "__main__":
    main()
