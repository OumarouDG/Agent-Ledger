"""Offline tests for the gateway's JWT checks, using a locally generated RSA key."""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from controlplane.auth.jwt_verify import AuthError, Verifier

ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST"
CODER = "coderclient123"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key()
V = Verifier(issuer=ISS, jwks_url="unused")


def make(**overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISS, "token_use": "access", "client_id": CODER, "sub": CODER,
              "scope": "agentledger/tools agentledger/llm", "iat": now, "exp": now + 3600}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, KEY, algorithm="RS256")


def test_valid_agent_token():
    claims = V.verify_agent(make(), {CODER}, "agentledger/tools", key=PUB)
    assert claims["client_id"] == CODER


@pytest.mark.parametrize("overrides, reason", [
    ({"exp": int(time.time()) - 3600}, "token_expired"),
    ({"iss": "https://evil.example"}, "wrong_issuer"),
    ({"token_use": "id"}, "wrong_token_use"),
    ({"client_id": "someoneelse"}, "unknown_client"),
    ({"username": "alice"}, "not_an_agent_token"),
    ({"scope": "agentledger/llm"}, "missing_scope"),
])
def test_rejections(overrides, reason):
    with pytest.raises(AuthError) as e:
        V.verify_agent(make(**overrides), {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == reason


def test_tampered_signature_rejected():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({"iss": ISS, "token_use": "access", "client_id": CODER,
                        "iat": int(time.time()), "exp": int(time.time()) + 60}, other, algorithm="RS256")
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, key=PUB)
    assert e.value.reason == "invalid_token"


def test_human_id_token():
    token = make(token_use="id", aud="cliclient", **{"cognito:groups": ["engineer"]})
    claims = V.verify_human(token, "cliclient", key=PUB)
    assert claims["cognito:groups"] == ["engineer"]
    with pytest.raises(AuthError):
        V.verify_human(token, "otherclient", key=PUB)
