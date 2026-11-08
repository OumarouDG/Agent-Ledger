"""CLI-2: current_session(), refresh and revoke, with locally signed JWTs. Offline.

The verifier is the real controlplane Verifier; only its JWKS fetch is replaced by a
local RSA public key. Token values are generated here and are not real.
"""

from __future__ import annotations

import base64
import json
import time

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

from agentledger import session
from agentledger.storage import TokenStore
from controlplane.auth.jwt_verify import Verifier

from .conftest import CFG as BASE_CFG

ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_FAKEPOOL"
CFG = {**BASE_CFG, "issuer": ISS, "jwks_url": "https://example.test/unused/jwks.json", "region": "us-east-1"}
CLIENT = CFG["cli"]["client_id"]
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class LocalVerifier(Verifier):
    """Real verification logic; signing key from KEY instead of the pool's JWKS URL."""

    def _signing_key(self, token):
        return KEY.public_key()


def verifier() -> LocalVerifier:
    return LocalVerifier(issuer=ISS, jwks_url=CFG["jwks_url"])


def id_token(key=KEY, **overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISS, "aud": CLIENT, "token_use": "id", "sub": "sub-alice", "cognito:username": "alice",
              "cognito:groups": ["engineer"], "iat": now, "exp": now + 3600}
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm="RS256")


def expired_id_token() -> str:
    return id_token(iat=int(time.time()) - 7200, exp=int(time.time()) - 3600)


def alg_none(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none', 'typ': 'JWT'})}.{enc(claims)}."


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self.body = body

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class Post:
    """Records calls to the token/revoke endpoints and returns queued replies."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, data=None, timeout=None):
        self.calls.append((url, data))
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def refusing_post(*a, **k):
    raise AssertionError("no HTTP call expected on this path")


@pytest.fixture
def store(mem) -> TokenStore:
    return TokenStore(CFG["user_pool_id"])


def save(store, id_tok, refresh="fake-refresh-1"):
    bundle = {"id_token": id_tok, "access_token": "fake-access-1"}
    if refresh:
        bundle["refresh_token"] = refresh
    store.save(bundle)
    return bundle


def current(store, post=refusing_post):
    return session.current_session(cfg=CFG, store=store, verifier=verifier(), post=post)


# --- valid ------------------------------------------------------------------------

def test_valid_session(store):
    save(store, id_token())
    s = current(store)
    assert (s.username, s.groups, s.refreshed) == ("alice", ["engineer"], False)
    assert s.access_token == "fake-access-1"
    assert s.expires_at > time.time() + 3500


def test_session_repr_hides_tokens(store):
    tok = id_token()
    save(store, tok)
    text = repr(current(store))
    assert "alice" in text and tok not in text and "fake-access-1" not in text


# --- not signed in / corrupt --------------------------------------------------------

def test_nothing_stored_is_not_signed_in(store):
    with pytest.raises(session.NotSignedIn, match="run agentledger login"):
        current(store)


def test_corrupt_store_is_not_signed_in(store, mem):
    save(store, id_token())
    mem.data[("agentledger", CFG["user_pool_id"])] = "garbage"
    with pytest.raises(session.NotSignedIn, match="run agentledger login"):
        current(store)


def test_unreadable_credential_store_is_a_session_error(store, mem):
    mem.fail_reads = True
    with pytest.raises(session.SessionError, match="OS credential store"):
        current(store)


# --- expired then refreshed -----------------------------------------------------------

def test_expired_then_refreshed_once_and_saved(store):
    save(store, expired_id_token())
    fresh = id_token()
    post = Post(Resp(200, {"id_token": fresh, "access_token": "fake-access-2", "expires_in": 3600}))
    s = current(store, post)
    assert s.refreshed and s.username == "alice" and s.access_token == "fake-access-2"
    assert len(post.calls) == 1
    url, data = post.calls[0]
    assert url == f"{CFG['domain']}/oauth2/token"
    assert data == {"grant_type": "refresh_token", "client_id": CLIENT, "refresh_token": "fake-refresh-1"}
    # Saved: next call verifies the new token without another refresh.
    assert store.load() == {"id_token": fresh, "access_token": "fake-access-2", "refresh_token": "fake-refresh-1"}
    assert current(store).refreshed is False


def test_rotated_refresh_token_is_saved(store):
    save(store, expired_id_token())
    post = Post(Resp(200, {"id_token": id_token(), "access_token": "fake-access-2",
                           "refresh_token": "fake-refresh-2"}))
    current(store, post)
    assert store.load()["refresh_token"] == "fake-refresh-2"


# --- expired, refresh fails --------------------------------------------------------------

def test_expired_refresh_refused_says_session_expired(store):
    before = save(store, expired_id_token())
    post = Post(Resp(400, {"error": "invalid_grant"}))
    with pytest.raises(session.SessionExpired, match=r"refused the refresh \(invalid_grant\); run agentledger login"):
        current(store, post)
    assert len(post.calls) == 1  # exactly one refresh attempt
    assert store.load() == before


def test_expired_without_refresh_token_does_not_call_cognito(store):
    save(store, expired_id_token(), refresh=None)
    with pytest.raises(session.SessionExpired, match="no refresh token"):
        current(store)


def test_expired_refresh_network_failure(store):
    save(store, expired_id_token())
    with pytest.raises(session.SessionExpired, match="ConnectionError.*run agentledger login"):
        current(store, Post(requests.ConnectionError("down")))


@pytest.mark.parametrize("reply", [
    Resp(200, {"access_token": "fake-access-2"}), Resp(200, []), Resp(200, ValueError("not json")),
])
def test_refresh_reply_without_tokens(store, reply):
    save(store, expired_id_token())
    with pytest.raises(session.SessionExpired, match="no tokens"):
        current(store, Post(reply))


def test_refresh_error_body_is_not_echoed(store):
    save(store, expired_id_token())
    post = Post(Resp(400, {"error": "<script>fake-secret-in-body</script>"}))
    with pytest.raises(session.SessionExpired) as e:
        current(store, post)
    assert "HTTP 400" in str(e.value) and "fake-secret" not in str(e.value)


def test_refreshed_token_that_fails_verification_is_not_saved(store):
    before = save(store, expired_id_token())
    post = Post(Resp(200, {"id_token": id_token(aud="someoneelse"), "access_token": "fake-access-2"}))
    with pytest.raises(session.InvalidSession) as e:
        current(store, post)
    assert e.value.reason == "refreshed token: wrong_audience"
    assert store.load() == before


# --- tokens that must not verify (no refresh attempted) -----------------------------------

@pytest.mark.parametrize("make, reason", [
    (lambda: id_token(iss="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_OTHER"), "wrong_issuer"),
    (lambda: id_token(aud="someoneelse"), "wrong_audience"),
    (lambda: id_token(token_use="access", aud=None, client_id=CLIENT), "wrong_token_use"),
    (lambda: alg_none({"iss": ISS, "aud": CLIENT, "token_use": "id", "cognito:username": "mallory",
                       "iat": int(time.time()), "exp": int(time.time()) + 3600}), "invalid_token"),
    (lambda: id_token(key=OTHER_KEY), "invalid_token"),
    (lambda: "not-a-jwt", "invalid_token"),
], ids=["wrong_issuer", "wrong_audience", "access_token_as_id_token", "alg_none", "wrong_key", "malformed"])
def test_bad_stored_id_token_is_rejected_with_reason(store, make, reason):
    save(store, make())
    with pytest.raises(session.InvalidSession) as e:
        current(store)  # refusing_post: a bad token must not trigger a refresh
    assert e.value.reason == reason
    assert "run agentledger login" in str(e.value)


# --- revoke ---------------------------------------------------------------------------------

def test_revoke_posts_token_and_client_id():
    post = Post(Resp(200, None))
    session.revoke(CFG, "fake-refresh-1", post=post)
    assert post.calls == [(f"{CFG['domain']}/oauth2/revoke", {"token": "fake-refresh-1", "client_id": CLIENT})]


@pytest.mark.parametrize("reply, text", [
    (Resp(400, {"error": "invalid_request"}), "invalid_request"),
    (Resp(503, ValueError("html")), "HTTP 503"),
    (requests.Timeout("slow"), "Timeout"),
])
def test_revoke_failure_raises(reply, text):
    with pytest.raises(session.RevokeFailed, match=text):
        session.revoke(CFG, "fake-refresh-1", post=Post(reply))
