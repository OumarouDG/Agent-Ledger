"""FastMCP bearer-token adapter around controlplane.auth.Verifier (agent tokens only)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping

from fastmcp.server.auth import AccessToken, TokenVerifier

from controlplane.auth.jwt_verify import AuthError, Verifier

log = logging.getLogger("agentledger.gateway.auth")

REQUIRED_SCOPE = "agentledger/tools"
# Identity is verified; grants/revocation are not enforced yet.
AUTH_MODE = "agent_token_verified_no_grants"

# Only these claims are kept on the AccessToken. The raw token is never stored.
_KEPT_CLAIMS = ("iss", "sub", "client_id", "token_use", "scope", "iat", "exp")


class AgentTokenVerifier(TokenVerifier):
    """Accepts a Cognito machine access token for a known agent client and the tools scope."""

    def __init__(self, verifier: Verifier, client_ids: Mapping[str, str],
                 required_scope: str = REQUIRED_SCOPE):
        super().__init__(required_scopes=[required_scope])
        if not client_ids:
            raise ValueError("no agent client_ids configured")
        self._verifier = verifier
        self._client_ids = frozenset(client_ids)
        self._scope = required_scope

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # PyJWKClient does blocking HTTP on a cache miss; keep it off the event loop.
            claims = await asyncio.to_thread(
                self._verifier.verify_agent, token, set(self._client_ids), self._scope
            )
        except AuthError as e:
            log.info("token rejected: %s", e.reason)
            return None
        except Exception as e:  # fail closed on anything unexpected (JWKS outage, bad claims)
            log.warning("token verification error: %s", type(e).__name__)
            return None

        try:
            return AccessToken(
                token="[redacted]",
                client_id=claims["client_id"],
                scopes=claims.get("scope", "").split(),
                expires_at=int(claims["exp"]),
                subject=claims.get("sub"),
                claims={k: claims[k] for k in _KEPT_CLAIMS if k in claims},
            )
        except Exception as e:
            log.warning("could not build access token: %s", type(e).__name__)
            return None
