"""Verify Cognito JWTs. Used by the gateway (agent access tokens) and the API (human tokens).

Step 1 of the gateway pipeline. Raises AuthError on anything wrong; callers map
that to 401 auth_failed. Never log the token itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import jwt
from jwt import PyJWKClient

from .config import load_config


class AuthError(Exception):
    """Token rejected. `reason` is safe to log and return."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Verifier:
    issuer: str
    jwks_url: str
    leeway: int = 30
    _jwks: PyJWKClient | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # Fail closed: PyJWT skips the issuer check entirely when issuer is None.
        for name in ("issuer", "jwks_url"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith("https://") or value != value.strip():
                raise ValueError(f"Verifier needs an https {name}, got {value!r}. "
                                 "Check shared/cognito.json or rerun `python infra/cognito_setup.py`.")

    @classmethod
    def from_config(cls) -> "Verifier":
        cfg = load_config()
        return cls(issuer=cfg["issuer"], jwks_url=cfg["jwks_url"])

    def _signing_key(self, token: str):
        if self._jwks is None:
            self._jwks = PyJWKClient(self.jwks_url, cache_keys=True, lifespan=3600)
        return self._jwks.get_signing_key_from_jwt(token).key

    def _decode(self, token: str, key=None) -> dict:
        try:
            key = key or self._signing_key(token)
            # Cognito access tokens have no `aud`; we check client_id ourselves.
            return jwt.decode(
                token, key, algorithms=["RS256"], issuer=self.issuer, leeway=self.leeway,
                options={"verify_aud": False, "require": ["exp", "iat", "iss", "token_use"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthError("token_expired") from e
        except jwt.InvalidIssuerError as e:
            raise AuthError("wrong_issuer") from e
        except jwt.PyJWKClientError as e:
            raise AuthError("unknown_signing_key") from e
        except jwt.InvalidTokenError as e:
            raise AuthError("invalid_token") from e

    def verify_agent(self, token: str, allowed_client_ids: set[str], required_scope: str | None = None,
                     key=None) -> dict:
        """Agent access token from GetClientToken / client_credentials."""
        claims = self._decode(token, key)
        if claims.get("token_use") != "access":
            raise AuthError("wrong_token_use")
        if claims.get("client_id") not in allowed_client_ids:
            raise AuthError("unknown_client")
        if "username" in claims:
            # Human access tokens carry `username`; machine tokens never do.
            raise AuthError("not_an_agent_token")
        if required_scope and required_scope not in claims.get("scope", "").split():
            raise AuthError("missing_scope")
        return claims

    def verify_human(self, token: str, client_id: str, key=None) -> dict:
        """Human ID token from the CLI or Console login. Returns claims incl. cognito:groups."""
        claims = self._decode(token, key)
        if claims.get("token_use") != "id":
            raise AuthError("wrong_token_use")
        if claims.get("aud") != client_id:
            raise AuthError("wrong_audience")
        return claims


def agent_client_ids() -> dict[str, str]:
    """client_id -> agent_id, for mapping a verified token back to its agent."""
    return {a["client_id"]: agent_id for agent_id, a in load_config()["agents"].items()}
