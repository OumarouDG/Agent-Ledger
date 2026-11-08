"""Live token checks against the workshop Cognito pool. Run with: pytest -q --live

Mints a real token for each agent and verifies it the way the gateway will
(signature from the pool's JWKS, issuer, token_use, client_id, scope).

The human ID token case creates a throwaway user and a throwaway app client
(ADMIN_USER_PASSWORD_AUTH, no secret) in the pool, signs in once, and deletes
both when the module finishes. The password is generated here and never printed.
No test asserts on or prints a token string.
"""

from __future__ import annotations

import secrets
import string

import boto3
import pytest
from botocore.exceptions import ClientError

from controlplane.auth.agent_tokens import mint_agent_token
from controlplane.auth.config import load_config
from controlplane.auth.jwt_verify import AuthError, Verifier, agent_client_ids

pytestmark = pytest.mark.live

# Same list as AGENTS in infra/cognito_setup.py. Hard-coded so collection works without shared/cognito.json.
AGENTS = ["agent_lead", "agent_coder", "agent_tester", "agent_rogue", "agent_triage"]
WITHOUT_MESSAGES = ["agent_tester", "agent_triage"]
AGENT_TOKEN_SECONDS = 12 * 3600  # AGENT_TOKEN_HOURS in infra/cognito_setup.py


@pytest.fixture(scope="module")
def cfg() -> dict:
    load_config.cache_clear()
    cfg = load_config()
    try:
        boto3.client("sts", region_name=cfg["region"]).get_caller_identity()
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"Can't reach AWS ({type(e).__name__}): paste fresh Workshop Studio credentials", pytrace=False)
    return cfg


@pytest.fixture(scope="module")
def verifier(cfg) -> Verifier:
    return Verifier.from_config()


@pytest.fixture(scope="module")
def tokens(cfg) -> dict:
    """One real token per agent, minted once for the module."""
    return {agent_id: mint_agent_token(agent_id) for agent_id in AGENTS}


def scope(cfg: dict, name: str) -> str:
    return f"{cfg['resource_server']}/{name}"


def test_config_lists_the_expected_agents(cfg):
    assert sorted(cfg["agents"]) == sorted(AGENTS)
    assert all(a["token_mode"] == "get_client_token" for a in cfg["agents"].values())


# --- mint and verify each agent ----------------------------------------------

@pytest.mark.parametrize("agent_id", AGENTS)
def test_mint_and_verify_agent(cfg, verifier, tokens, agent_id):
    tok = tokens[agent_id]
    expected_client = cfg["agents"][agent_id]["client_id"]
    assert tok.agent_id == agent_id
    assert tok.client_id == expected_client
    assert tok.expires_in == AGENT_TOKEN_SECONDS

    claims = verifier.verify_agent(tok.access_token, {expected_client}, required_scope=scope(cfg, "tools"))

    assert claims["iss"] == cfg["issuer"]
    assert claims["token_use"] == "access"
    assert claims["client_id"] == expected_client
    assert claims["sub"] == expected_client  # machine tokens: subject is the client itself
    assert "username" not in claims
    assert set(claims["scope"].split()) == set(cfg["agents"][agent_id]["scopes"])
    assert claims["exp"] - claims["iat"] == AGENT_TOKEN_SECONDS
    assert agent_client_ids()[claims["client_id"]] == agent_id


# --- required scope -----------------------------------------------------------

@pytest.mark.parametrize("agent_id", WITHOUT_MESSAGES)
def test_missing_scope_rejected(cfg, verifier, tokens, agent_id):
    client = cfg["agents"][agent_id]["client_id"]
    with pytest.raises(AuthError) as e:
        verifier.verify_agent(tokens[agent_id].access_token, {client}, required_scope=scope(cfg, "messages"))
    assert e.value.reason == "missing_scope"


@pytest.mark.parametrize("agent_id", sorted(set(AGENTS) - set(WITHOUT_MESSAGES)))
def test_messages_scope_present_where_granted(cfg, verifier, tokens, agent_id):
    client = cfg["agents"][agent_id]["client_id"]
    claims = verifier.verify_agent(tokens[agent_id].access_token, {client}, required_scope=scope(cfg, "messages"))
    assert scope(cfg, "messages") in claims["scope"].split()


def test_narrowed_mint_only_carries_requested_scope(cfg, verifier):
    tok = mint_agent_token("agent_coder", scopes=[scope(cfg, "tools")])
    client = cfg["agents"]["agent_coder"]["client_id"]
    claims = verifier.verify_agent(tok.access_token, {client}, required_scope=scope(cfg, "tools"))
    assert claims["scope"].split() == [scope(cfg, "tools")]
    with pytest.raises(AuthError) as e:
        verifier.verify_agent(tok.access_token, {client}, required_scope=scope(cfg, "llm"))
    assert e.value.reason == "missing_scope"


def test_mint_beyond_agent_ceiling_does_not_grant_scope(cfg, verifier):
    # agent_tester's client is not allowed `messages`. Either Cognito refuses, or the scope must be absent.
    client = cfg["agents"]["agent_tester"]["client_id"]
    try:
        tok = mint_agent_token("agent_tester", scopes=[scope(cfg, "tools"), scope(cfg, "messages")])
    except ClientError as e:
        assert e.response["Error"]["Code"] in {"InvalidParameterException", "NotAuthorizedException",
                                               "InvalidScopeException"}, e.response["Error"]["Code"]
        return
    with pytest.raises(AuthError) as e:
        verifier.verify_agent(tok.access_token, {client}, required_scope=scope(cfg, "messages"))
    assert e.value.reason == "missing_scope"


# --- cross-agent rejection ----------------------------------------------------

CROSS_PAIRS = [(a, b) for a in AGENTS for b in AGENTS if a != b]


@pytest.mark.parametrize("holder, allowed_only", CROSS_PAIRS, ids=[f"{a}-as-{b}" for a, b in CROSS_PAIRS])
def test_token_rejected_when_only_another_agent_allowed(cfg, verifier, tokens, holder, allowed_only):
    other_client = cfg["agents"][allowed_only]["client_id"]
    with pytest.raises(AuthError) as e:
        verifier.verify_agent(tokens[holder].access_token, {other_client})
    assert e.value.reason == "unknown_client"


# --- human ID token must not pass as an agent ---------------------------------

def _make_password() -> str:
    # Pool policy: 12+ chars with upper, lower, digit and symbol.
    alphabet = string.ascii_letters + string.digits
    return "Lt" + "".join(secrets.choice(alphabet) for _ in range(20)) + "7#"


@pytest.fixture(scope="module")
def human_id_token(cfg) -> tuple[str, str]:
    """(id_token, client_id) for a throwaway user; user and client are deleted afterwards."""
    cg = boto3.client("cognito-idp", region_name=cfg["region"])
    pool = cfg["user_pool_id"]
    suffix = secrets.token_hex(4)
    username = f"livetest-{suffix}"
    client_id = None
    user_created = False
    try:
        client_id = cg.create_user_pool_client(
            UserPoolId=pool, ClientName=f"agentledger-livetest-{suffix}", GenerateSecret=False,
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        )["UserPoolClient"]["ClientId"]
        cg.admin_create_user(UserPoolId=pool, Username=username, MessageAction="SUPPRESS")
        user_created = True
        password = _make_password()
        cg.admin_set_user_password(UserPoolId=pool, Username=username, Password=password, Permanent=True)
        auth = cg.admin_initiate_auth(
            UserPoolId=pool, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )["AuthenticationResult"]
        del password
        yield auth["IdToken"], client_id
    finally:
        leftovers = []
        if user_created:
            try:
                cg.admin_delete_user(UserPoolId=pool, Username=username)
            except ClientError as e:
                leftovers.append(f"user {username} ({e.response['Error']['Code']})")
        if client_id:
            try:
                cg.delete_user_pool_client(UserPoolId=pool, ClientId=client_id)
            except ClientError as e:
                leftovers.append(f"client {client_id} ({e.response['Error']['Code']})")
        if leftovers:
            print(f"\nWARNING: live test could not clean up: {', '.join(leftovers)}. Delete them in the console.")


def test_human_id_token_is_genuine(verifier, human_id_token):
    # Control: the same token verifies as a human token, so the rejection below is about token_use.
    id_token, client_id = human_id_token
    claims = verifier.verify_human(id_token, client_id)
    assert claims["token_use"] == "id"
    assert claims["cognito:username"].startswith("livetest-")


def test_human_id_token_rejected_by_verify_agent(cfg, verifier, human_id_token):
    id_token, client_id = human_id_token
    all_clients = set(agent_client_ids()) | {client_id}  # even if the human's client were allowed
    with pytest.raises(AuthError) as e:
        verifier.verify_agent(id_token, all_clients)
    assert e.value.reason == "wrong_token_use"
