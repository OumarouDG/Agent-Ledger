"""Mint agent access tokens. Backend only: agent secrets never leave this process.

Primary path: Cognito GetClientToken (no domain needed, client must allow only
ALLOW_CLIENT_TOKEN_AUTH). Fallback: the domain's /oauth2/token endpoint with the
client_credentials grant, used only when shared/cognito.json says
token_mode "oauth2_token" (setup records that when it had to fall back).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import boto3
import requests
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from .config import ROOT, load_config

LOCAL_SECRETS_FILE = ROOT / "infra" / "out" / "agent-secrets.local.json"
TOKEN_MODES = ("get_client_token", "oauth2_token")

# Error codes AWS returns when the caller's credentials are expired, wrong or unsigned.
CREDENTIAL_ERROR_CODES = {
    "ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException",
    "InvalidClientTokenId", "InvalidSignatureException", "MissingAuthenticationToken",
}


@dataclass(frozen=True)
class AgentToken:
    access_token: str
    expires_in: int
    agent_id: str
    client_id: str

    def __repr__(self) -> str:  # never print the token
        return f"AgentToken(agent_id={self.agent_id!r}, client_id={self.client_id!r}, expires_in={self.expires_in})"


class AgentNotRegistered(Exception):
    pass


class AwsCredentialsError(RuntimeError):
    """AWS refused our credentials. The message says how to fix it."""


def _aws_call(what: str, fn, **kwargs):
    """Run one AWS call; turn credential failures into AwsCredentialsError with the fix."""
    try:
        return fn(**kwargs)
    except (NoCredentialsError, PartialCredentialsError) as e:
        raise AwsCredentialsError(
            f"{what}: no AWS credentials found. Paste fresh Workshop Studio credentials and retry.") from e
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in CREDENTIAL_ERROR_CODES:
            raise AwsCredentialsError(
                f"{what}: AWS rejected the credentials ({code}). "
                "Paste fresh Workshop Studio credentials and retry.") from e
        raise


def _client_secret(agent_id: str, secret_ref: str, region: str) -> tuple[str, str]:
    kind, _, name = secret_ref.partition(":")
    if kind == "secretsmanager":
        sm = boto3.client("secretsmanager", region_name=region)
        resp = _aws_call(f"reading {agent_id} secret", sm.get_secret_value, SecretId=name)
        data = json.loads(resp["SecretString"])
    elif kind == "local":
        data = json.loads(Path(LOCAL_SECRETS_FILE).read_text())[name]
    else:
        raise ValueError(f"unknown secret_ref for {agent_id}")
    return data["client_id"], data["client_secret"]


def mint_agent_token(agent_id: str, scopes: list[str] | None = None) -> AgentToken:
    cfg = load_config()
    agent = cfg["agents"].get(agent_id)
    if not agent:
        raise AgentNotRegistered(agent_id)
    mode = agent.get("token_mode")
    if mode not in TOKEN_MODES:
        raise ValueError(f"{agent_id}: token_mode {mode!r} in shared/cognito.json is not one of {TOKEN_MODES}. "
                         "Rerun `python infra/cognito_setup.py`.")
    region = cfg["region"]
    client_id, secret = _client_secret(agent_id, agent["secret_ref"], region)
    scopes = scopes or agent["scopes"]

    if mode == "get_client_token":
        cognito = boto3.client("cognito-idp", region_name=region)
        if not hasattr(cognito, "get_client_token"):
            raise RuntimeError(f"{agent_id}: token_mode is get_client_token but this boto3 has no "
                               "get_client_token. Run `pip install -r requirements.txt` to upgrade boto3.")
        result = _aws_call(f"minting {agent_id} token", cognito.get_client_token,
                           ClientId=client_id, Secret=secret, Scopes=scopes)["ClientAuthenticationResult"]
        return AgentToken(result["AccessToken"], int(result["ExpiresIn"]), agent_id, client_id)

    resp = requests.post(
        f"{cfg['domain']}/oauth2/token",
        auth=(client_id, secret),
        data={"grant_type": "client_credentials", "scope": " ".join(scopes)},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    return AgentToken(body["access_token"], int(body["expires_in"]), agent_id, client_id)
