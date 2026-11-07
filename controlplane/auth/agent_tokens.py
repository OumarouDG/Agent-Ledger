"""Mint agent access tokens. Backend only: agent secrets never leave this process.

Primary path: Cognito GetClientToken (no domain needed, client must allow only
ALLOW_CLIENT_TOKEN_AUTH). Fallback: the domain's /oauth2/token endpoint with the
client_credentials grant, for older boto3 or if the flow was rejected at setup.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import boto3
import requests

from .config import ROOT, load_config

LOCAL_SECRETS_FILE = ROOT / "infra" / "out" / "agent-secrets.local.json"


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


def _client_secret(agent_id: str, secret_ref: str, region: str) -> tuple[str, str]:
    kind, _, name = secret_ref.partition(":")
    if kind == "secretsmanager":
        sm = boto3.client("secretsmanager", region_name=region)
        data = json.loads(sm.get_secret_value(SecretId=name)["SecretString"])
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
    region = cfg["region"]
    client_id, secret = _client_secret(agent_id, agent["secret_ref"], region)
    scopes = scopes or agent["scopes"]

    cognito = boto3.client("cognito-idp", region_name=region)
    if agent.get("token_mode") == "get_client_token" and hasattr(cognito, "get_client_token"):
        result = cognito.get_client_token(ClientId=client_id, Secret=secret, Scopes=scopes)[
            "ClientAuthenticationResult"]
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
