"""Create or update the AgentLedger identity provider in Amazon Cognito.

Idempotent: safe to re-run. Creates:
  - user pool + managed-login domain
  - resource server `agentledger` with scopes tools, llm, messages
  - groups engineer, reviewer, security-admin and demo users alice, bob, dana
  - public app clients for the CLI (PKCE, localhost callback) and the Console
  - one confidential app client per agent (ALLOW_CLIENT_TOKEN_AUTH only)
  - agent secrets in Secrets Manager (falls back to a gitignored local file)

Writes shared/cognito.json (IDs only, safe to commit) and
infra/out/demo-users.local.json (passwords, never commit).

Usage: AWS_REGION=us-east-1 python infra/cognito_setup.py
"""

from __future__ import annotations

import json
import os
import secrets
import string
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
SHARED_CONFIG = ROOT / "shared" / "cognito.json"
OUT_DIR = ROOT / "infra" / "out"
USERS_FILE = OUT_DIR / "demo-users.local.json"
LOCAL_SECRETS_FILE = OUT_DIR / "agent-secrets.local.json"

REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
POOL_NAME = "agentledger-pool"
RESOURCE_SERVER_ID = "agentledger"
SCOPES = {
    "tools": "Call MCP tools through the gateway",
    "llm": "Call /llm/converse through the gateway",
    "messages": "Send agent-to-agent messages through the broker",
}
# Agent capability ceiling at the token level. Grants narrow this per workflow.
AGENTS = {
    "agent_lead": ["tools", "llm", "messages"],
    "agent_coder": ["tools", "llm", "messages"],
    "agent_tester": ["tools", "llm"],
    "agent_rogue": ["tools", "llm", "messages"],
    "agent_triage": ["tools", "llm"],
}
GROUPS = {
    "engineer": "Read code, branch, commit, open PRs, run tests, delete feature branches",
    "reviewer": "Engineer permissions plus approve and merge",
    "security-admin": "Revoke, quarantine, suspend, view all audit logs",
}
USERS = {"alice": "engineer", "bob": "reviewer", "dana": "security-admin"}
CLI_CALLBACK = "http://localhost:8765/callback"
CONSOLE_CALLBACKS = ["http://localhost:5173/callback"]
AGENT_TOKEN_HOURS = 12  # long on purpose: the demo proves revoke works with a valid token
SECRET_PREFIX = "agentledger/agents/"

cognito = boto3.client("cognito-idp", region_name=REGION)
sm = boto3.client("secretsmanager", region_name=REGION)
sts = boto3.client("sts", region_name=REGION)


def log(msg: str) -> None:
    print(f"  {msg}")


def code(err: ClientError) -> str:
    return err.response.get("Error", {}).get("Code", "")


def find_pool() -> str | None:
    for page in cognito.get_paginator("list_user_pools").paginate(MaxResults=60):
        for pool in page["UserPools"]:
            if pool["Name"] == POOL_NAME:
                return pool["Id"]
    return None


def ensure_pool() -> str:
    pool_id = find_pool()
    if pool_id:
        log(f"user pool exists: {pool_id}")
        return pool_id
    resp = cognito.create_user_pool(
        PoolName=POOL_NAME,
        Policies={"PasswordPolicy": {
            "MinimumLength": 12, "RequireUppercase": True, "RequireLowercase": True,
            "RequireNumbers": True, "RequireSymbols": True,
        }},
        UsernameConfiguration={"CaseSensitive": False},
        AdminCreateUserConfig={"AllowAdminCreateUserOnly": True},
        AutoVerifiedAttributes=["email"],
        DeletionProtection="INACTIVE",
    )
    pool_id = resp["UserPool"]["Id"]
    log(f"created user pool: {pool_id}")
    return pool_id


def ensure_domain(pool_id: str, account_id: str) -> str:
    existing = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("Domain")
    if existing:
        log(f"domain exists: {existing}")
        return existing
    prefix = f"agentledger-{account_id[-8:]}"
    # ManagedLoginVersion 1 is the classic hosted UI: works with no branding setup.
    cognito.create_user_pool_domain(Domain=prefix, UserPoolId=pool_id, ManagedLoginVersion=1)
    log(f"created domain: {prefix}")
    return prefix


def ensure_resource_server(pool_id: str) -> None:
    scopes = [{"ScopeName": k, "ScopeDescription": v} for k, v in SCOPES.items()]
    try:
        cognito.describe_resource_server(UserPoolId=pool_id, Identifier=RESOURCE_SERVER_ID)
        cognito.update_resource_server(
            UserPoolId=pool_id, Identifier=RESOURCE_SERVER_ID, Name="AgentLedger gateway", Scopes=scopes
        )
        log("resource server updated")
    except ClientError as e:
        if code(e) != "ResourceNotFoundException":
            raise
        cognito.create_resource_server(
            UserPoolId=pool_id, Identifier=RESOURCE_SERVER_ID, Name="AgentLedger gateway", Scopes=scopes
        )
        log("resource server created")


def ensure_groups(pool_id: str) -> None:
    for name, desc in GROUPS.items():
        try:
            cognito.create_group(UserPoolId=pool_id, GroupName=name, Description=desc)
            log(f"group created: {name}")
        except ClientError as e:
            if code(e) != "GroupExistsException":
                raise


def make_password() -> str:
    alphabet = string.ascii_letters + string.digits
    core = "".join(secrets.choice(alphabet) for _ in range(14))
    return f"Al{core}9!"


def ensure_users(pool_id: str) -> None:
    saved = json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else {}
    for username, group in USERS.items():
        try:
            cognito.admin_create_user(
                UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS",
                UserAttributes=[
                    {"Name": "email", "Value": f"{username}@acme.test"},
                    {"Name": "email_verified", "Value": "true"},
                ],
            )
            password = make_password()
            cognito.admin_set_user_password(
                UserPoolId=pool_id, Username=username, Password=password, Permanent=True
            )
            saved[username] = {"password": password, "group": group}
            log(f"user created: {username} ({group})")
        except ClientError as e:
            if code(e) != "UsernameExistsException":
                raise
        cognito.admin_add_user_to_group(UserPoolId=pool_id, Username=username, GroupName=group)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(saved, indent=2))


def find_client(pool_id: str, name: str) -> str | None:
    for page in cognito.get_paginator("list_user_pool_clients").paginate(UserPoolId=pool_id, MaxResults=60):
        for c in page["UserPoolClients"]:
            if c["ClientName"] == name:
                return c["ClientId"]
    return None


def ensure_public_client(pool_id: str, name: str, callbacks: list[str]) -> str:
    settings = dict(
        UserPoolId=pool_id,
        ClientName=name,
        ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH"],
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["openid", "email", "profile"],
        AllowedOAuthFlowsUserPoolClient=True,
        CallbackURLs=callbacks,
        LogoutURLs=callbacks,
        SupportedIdentityProviders=["COGNITO"],
        PreventUserExistenceErrors="ENABLED",
        AccessTokenValidity=60,
        IdTokenValidity=60,
        RefreshTokenValidity=12,
        TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "hours"},
    )
    client_id = find_client(pool_id, name)
    if client_id:
        cognito.update_user_pool_client(ClientId=client_id, **settings)
        log(f"client updated: {name}")
        return client_id
    client_id = cognito.create_user_pool_client(GenerateSecret=False, **settings)["UserPoolClient"]["ClientId"]
    log(f"client created: {name}")
    return client_id


def ensure_agent_client(pool_id: str, agent_id: str, scopes: list[str]) -> tuple[str, str, str]:
    """Returns (client_id, client_secret, token_mode)."""
    name = f"agentledger-{agent_id}"
    full_scopes = [f"{RESOURCE_SERVER_ID}/{s}" for s in scopes]
    base = dict(
        UserPoolId=pool_id,
        ClientName=name,
        AllowedOAuthFlows=["client_credentials"],
        AllowedOAuthScopes=full_scopes,
        AllowedOAuthFlowsUserPoolClient=True,
        AccessTokenValidity=AGENT_TOKEN_HOURS,
        TokenValidityUnits={"AccessToken": "hours"},
        PreventUserExistenceErrors="ENABLED",
    )
    token_mode = "get_client_token"
    client_id = find_client(pool_id, name)
    for flows in (["ALLOW_CLIENT_TOKEN_AUTH"], None):
        settings = dict(base, ExplicitAuthFlows=flows) if flows else base
        try:
            if client_id:
                cognito.update_user_pool_client(ClientId=client_id, **settings)
            else:
                client_id = cognito.create_user_pool_client(GenerateSecret=True, **settings)[
                    "UserPoolClient"]["ClientId"]
            break
        except ClientError as e:
            if flows and code(e) == "InvalidParameterException":
                log(f"{agent_id}: ALLOW_CLIENT_TOKEN_AUTH rejected ({e.response['Error']['Message']}); "
                    "falling back to the /oauth2/token client_credentials flow")
                token_mode = "oauth2_token"
                continue
            raise
    desc = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    log(f"agent client ready: {agent_id} -> {client_id}")
    return client_id, desc["ClientSecret"], token_mode


def store_secret(agent_id: str, client_id: str, client_secret: str, local: dict) -> str:
    name = SECRET_PREFIX + agent_id
    value = json.dumps({"client_id": client_id, "client_secret": client_secret})
    try:
        try:
            sm.put_secret_value(SecretId=name, SecretString=value)
        except ClientError as e:
            if code(e) != "ResourceNotFoundException":
                raise
            sm.create_secret(Name=name, SecretString=value, Description=f"AgentLedger {agent_id} client secret")
        return f"secretsmanager:{name}"
    except ClientError as e:
        if code(e) not in ("AccessDeniedException", "UnrecognizedClientException"):
            raise
        log(f"Secrets Manager not available ({code(e)}); storing {agent_id} secret in {LOCAL_SECRETS_FILE.name}")
        local[agent_id] = {"client_id": client_id, "client_secret": client_secret}
        return f"local:{agent_id}"


def main() -> None:
    try:
        account_id = sts.get_caller_identity()["Account"]
    except Exception as e:  # noqa: BLE001
        sys.exit(f"Can't reach AWS ({e}). Paste the Workshop Studio credentials into this shell first.")

    if not hasattr(cognito, "get_client_token"):
        print("Note: this boto3 has no get_client_token. Run `pip install -U boto3` for the newest API; "
              "token minting will fall back to /oauth2/token until then.")

    print(f"Setting up AgentLedger IdP in {REGION} (account ...{account_id[-4:]})")
    pool_id = ensure_pool()
    domain = ensure_domain(pool_id, account_id)
    ensure_resource_server(pool_id)
    ensure_groups(pool_id)
    ensure_users(pool_id)
    cli_client = ensure_public_client(pool_id, "agentledger-cli", [CLI_CALLBACK])
    console_client = ensure_public_client(pool_id, "agentledger-console", CONSOLE_CALLBACKS)

    local_secrets: dict = json.loads(LOCAL_SECRETS_FILE.read_text()) if LOCAL_SECRETS_FILE.exists() else {}
    agents_out = {}
    for agent_id, scopes in AGENTS.items():
        client_id, client_secret, token_mode = ensure_agent_client(pool_id, agent_id, scopes)
        where = store_secret(agent_id, client_id, client_secret, local_secrets)
        agents_out[agent_id] = {
            "client_id": client_id,
            "scopes": [f"{RESOURCE_SERVER_ID}/{s}" for s in scopes],
            "secret_ref": where,
            "token_mode": token_mode,
        }
    if local_secrets:
        LOCAL_SECRETS_FILE.write_text(json.dumps(local_secrets, indent=2))

    issuer = f"https://cognito-idp.{REGION}.amazonaws.com/{pool_id}"
    config = {
        "region": REGION,
        "user_pool_id": pool_id,
        "issuer": issuer,
        "jwks_url": f"{issuer}/.well-known/jwks.json",
        "domain": f"https://{domain}.auth.{REGION}.amazoncognito.com",
        "resource_server": RESOURCE_SERVER_ID,
        "cli": {"client_id": cli_client, "callback": CLI_CALLBACK, "scopes": ["openid", "email", "profile"]},
        "console": {"client_id": console_client, "callbacks": CONSOLE_CALLBACKS},
        "groups": list(GROUPS),
        "agents": agents_out,
    }
    SHARED_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    SHARED_CONFIG.write_text(json.dumps(config, indent=2) + "\n")
    print(f"\nDone. Wrote {SHARED_CONFIG.relative_to(ROOT)} (commit this) "
          f"and {USERS_FILE.relative_to(ROOT)} (never commit).")
    print("Next: python infra/smoke_test.py, then python infra/human_login.py")


if __name__ == "__main__":
    main()
