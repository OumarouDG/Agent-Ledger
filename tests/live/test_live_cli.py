"""Live CLI session checks against the workshop Cognito pool. Run with: pytest -q --live

Uses the real /oauth2/token and /oauth2/revoke endpoints and the pool's real JWKS.
A throwaway user and a throwaway public app client (ADMIN_USER_PASSWORD_AUTH plus
refresh, revocation on) are created for the module and deleted afterwards; the
password is generated here and never printed. No test prints a token.
"""

from __future__ import annotations

import secrets
import string

import boto3
import pytest
from botocore.exceptions import ClientError

from agentledger import session
from controlplane.auth.config import load_config
from controlplane.auth.jwt_verify import Verifier

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def cfg() -> dict:
    load_config.cache_clear()
    cfg = load_config()
    try:
        boto3.client("sts", region_name=cfg["region"]).get_caller_identity()
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"Can't reach AWS ({type(e).__name__}): paste fresh Workshop Studio credentials", pytrace=False)
    return cfg


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Lt" + "".join(secrets.choice(alphabet) for _ in range(20)) + "7#"


@pytest.fixture(scope="module")
def signed_in(cfg):
    """Yields a function returning (fresh AuthenticationResult, client_id). Cleans up user and client."""
    cg = boto3.client("cognito-idp", region_name=cfg["region"])
    pool = cfg["user_pool_id"]
    suffix = secrets.token_hex(4)
    username = f"livetest-cli-{suffix}"
    client_id = None
    user_created = False
    password = _password()
    try:
        client_id = cg.create_user_pool_client(
            UserPoolId=pool, ClientName=f"agentledger-livetest-cli-{suffix}", GenerateSecret=False,
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            EnableTokenRevocation=True,
        )["UserPoolClient"]["ClientId"]
        cg.admin_create_user(UserPoolId=pool, Username=username, MessageAction="SUPPRESS")
        user_created = True
        cg.admin_set_user_password(UserPoolId=pool, Username=username, Password=password, Permanent=True)

        def sign_in() -> tuple[dict, str]:
            return cg.admin_initiate_auth(
                UserPoolId=pool, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password},
            )["AuthenticationResult"], client_id

        yield sign_in
    finally:
        password = None
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


def test_real_refresh_returns_verifiable_tokens(cfg, signed_in):
    auth, client_id = signed_in()
    new = session.refresh(cfg, auth["RefreshToken"], client_id=client_id)
    claims = Verifier.from_config().verify_human(new["id_token"], client_id)
    assert claims["token_use"] == "id"
    assert claims["cognito:username"].startswith("livetest-cli-")


def test_revoked_refresh_token_cannot_refresh(cfg, signed_in):
    auth, client_id = signed_in()
    rt = auth["RefreshToken"]
    session.refresh(cfg, rt, client_id=client_id)  # control: works before revoke
    session.revoke(cfg, rt, client_id=client_id)
    with pytest.raises(session.SessionExpired, match=r"refused the refresh \(invalid_grant\)"):
        session.refresh(cfg, rt, client_id=client_id)


def test_second_revoke_of_same_token_still_returns_200(cfg, signed_in):
    # Documents why logout says "revoke accepted", not "revoked": Cognito answers 200
    # for a token that is already revoked, so HTTP 200 does not prove a live token was revoked.
    auth, client_id = signed_in()
    session.revoke(cfg, auth["RefreshToken"], client_id=client_id)
    session.revoke(cfg, auth["RefreshToken"], client_id=client_id)
