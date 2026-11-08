"""Offline tests for the gateway's JWT checks, using a locally generated RSA key."""

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from controlplane.auth.jwt_verify import AuthError, Verifier

ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST"
CODER = "coderclient123"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUB = KEY.public_key()
V = Verifier(issuer=ISS, jwks_url="https://example.test/unused/jwks.json")  # key= is always passed


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


# --- IdP-1 edge cases --------------------------------------------------------

OTHER_POOL_ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OTHERPOOL"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def handmade(header: dict, claims: dict, signature: bytes = b"") -> str:
    """Build a JWT by hand so PyJWT's own encode-side guards don't stop us making a bad one."""
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    return f"{signing_input}.{b64url(signature)}"


def base_claims(**overrides) -> dict:
    now = int(time.time())
    claims = {"iss": ISS, "token_use": "access", "client_id": CODER, "sub": CODER,
              "scope": "agentledger/tools", "iat": now, "exp": now + 3600}
    claims.update(overrides)
    return claims


def test_other_pool_issuer_rejected_even_with_valid_signature():
    # Signature checks out against our key; only the issuer is wrong. Proves iss is enforced.
    with pytest.raises(AuthError) as e:
        V.verify_agent(make(iss=OTHER_POOL_ISS), {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "wrong_issuer"


def test_other_pool_token_with_other_key_rejected():
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(base_claims(iss=OTHER_POOL_ISS), other, algorithm="RS256")
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "invalid_token"


def test_human_token_wrong_issuer_rejected():
    token = make(iss=OTHER_POOL_ISS, token_use="id", aud="cliclient")
    with pytest.raises(AuthError) as e:
        V.verify_human(token, "cliclient", key=PUB)
    assert e.value.reason == "wrong_issuer"


@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "token_use"])
def test_missing_required_claim_rejected(claim):
    with pytest.raises(AuthError) as e:
        V.verify_agent(make(**{claim: None}), {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "invalid_token"


def test_missing_exp_rejected_for_human_token():
    token = make(exp=None, token_use="id", aud="cliclient")
    with pytest.raises(AuthError) as e:
        V.verify_human(token, "cliclient", key=PUB)
    assert e.value.reason == "invalid_token"


@pytest.mark.parametrize("alg", ["none", "None", "NONE"])
def test_alg_none_rejected(alg):
    token = handmade({"alg": alg, "typ": "JWT"}, base_claims())
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "invalid_token"


def test_alg_none_rejected_for_human_token():
    token = handmade({"alg": "none", "typ": "JWT"}, base_claims(token_use="id", aud="cliclient"))
    with pytest.raises(AuthError) as e:
        V.verify_human(token, "cliclient", key=PUB)
    assert e.value.reason == "invalid_token"


def _hs256_with_public_key(claims: dict) -> str:
    """Classic key-confusion forgery: HMAC-sign with the RSA public key's PEM bytes."""
    pem = PUB.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    sig = hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


def test_hs256_signed_with_public_key_rejected_agent():
    token = _hs256_with_public_key(base_claims())
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "invalid_token"


def test_hs256_signed_with_public_key_rejected_human():
    token = _hs256_with_public_key(base_claims(token_use="id", aud="cliclient"))
    with pytest.raises(AuthError) as e:
        V.verify_human(token, "cliclient", key=PUB)
    assert e.value.reason == "invalid_token"


def test_hs256_forgery_rejected_when_key_is_pem_bytes():
    # Even if a caller hands the verifier PEM bytes instead of a key object, HS256 must not be accepted.
    pem = PUB.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    token = _hs256_with_public_key(base_claims())
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, "agentledger/tools", key=pem)
    assert e.value.reason == "invalid_token"


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c", "....", "eyJhbGciOiJSUzI1NiJ9.e30."])
def test_malformed_token_rejected(token):
    with pytest.raises(AuthError) as e:
        V.verify_agent(token, {CODER}, "agentledger/tools", key=PUB)
    assert e.value.reason == "invalid_token"


# --- IdP-5: a verifier with no issuer must not exist ----------------------------

@pytest.mark.parametrize("issuer", [None, "", "   ", "http://cognito-idp.us-east-1.amazonaws.com/us-east-1_X"])
def test_verifier_refuses_missing_or_bad_issuer(issuer):
    # Bad case: Verifier(issuer=None) passed issuer=None to PyJWT, which then skipped the
    # issuer check and accepted a token from any user pool.
    with pytest.raises(ValueError) as e:
        Verifier(issuer=issuer, jwks_url="https://example.test/jwks.json")
    assert "issuer" in str(e.value)


@pytest.mark.parametrize("jwks_url", [None, "", "http://example.test/jwks.json"])
def test_verifier_refuses_missing_or_bad_jwks_url(jwks_url):
    with pytest.raises(ValueError) as e:
        Verifier(issuer=ISS, jwks_url=jwks_url)
    assert "jwks_url" in str(e.value)


def test_verifier_with_issuer_rejects_other_pool():
    # Control: with the issuer set, the same other-pool token is refused.
    v = Verifier(issuer=ISS, jwks_url="https://example.test/jwks.json")
    with pytest.raises(AuthError) as e:
        v.verify_agent(make(iss=OTHER_POOL_ISS), {CODER}, key=PUB)
    assert e.value.reason == "wrong_issuer"
