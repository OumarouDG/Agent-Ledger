"""One agent's connection to the AgentLedger gateway.

An `AgentSession` mints the agent's own token, verifies it locally, and keeps the agent ID
the verified token names. Every `call` sends that token with the session's grant and
workflow headers. A gateway denial is raised as `Denied`, never returned as a result.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable, Mapping
from typing import Any

import httpx2
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from controlplane.auth.agent_tokens import AgentToken, mint_agent_token
from controlplane.auth.jwt_verify import Verifier, agent_client_ids

DEFAULT_GATEWAY_URL = "http://127.0.0.1:18000/mcp"
GATEWAY_URL_ENV = "AGENTLEDGER_GATEWAY_URL"
REQUIRED_SCOPE = "agentledger/tools"
DENIED_PREFIX = "denied:"
DEFAULT_TIMEOUT_S = 60.0
MAX_ERROR_CHARS = 200


class GatewayError(Exception):
    """Base for every way a gateway call can fail. Never carries a token."""


class Denied(GatewayError):
    """The gateway refused the call. `reason` is the gateway's reason code."""

    def __init__(self, reason: str, tool: str, agent_id: str, grant_id: str | None):
        super().__init__(f"{agent_id} denied {tool} on grant {grant_id}: {reason}")
        self.reason = reason
        self.tool = tool
        self.agent_id = agent_id
        self.grant_id = grant_id


class GatewayUnavailable(GatewayError):
    """No connection to the gateway (tunnel down, wrong URL, timeout)."""


class GatewayRejected(GatewayError):
    """The gateway answered with an error before any tool ran. A rejected token does this."""


class ToolFailed(GatewayError):
    """The call was allowed but the tool itself failed (for example: issue not found)."""


class IdentityMismatch(GatewayError):
    """The token's verified agent is not the agent this session was opened for."""


def gateway_url(env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get(GATEWAY_URL_ENV) or "").strip() or DEFAULT_GATEWAY_URL


def _scrub(text: str, secret: str) -> str:
    """Drop the token from any text we pass on, then cap its length."""
    if secret:
        text = text.replace(secret, "[redacted]")
    return text[:MAX_ERROR_CHARS]


def _connection_failure(exc: BaseException) -> bool:
    """True if a transport-level error (refused, reset, timeout) is anywhere in the chain."""
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        e = stack.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        if isinstance(e, (httpx2.TransportError, OSError, TimeoutError)):
            return True
        if isinstance(e, BaseExceptionGroup):
            stack.extend(e.exceptions)
        for nxt in (e.__cause__, e.__context__):
            if nxt is not None:
                stack.append(nxt)
    return False


class AgentSession:
    """A verified agent identity bound to one grant and one workflow.

    `mint`, `verifier` and `client_ids` default to the real Cognito setup; tests pass fakes.
    """

    def __init__(self, agent_id: str, grant_id: str | None, workflow_id: str | None,
                 url: str | None = None, *,
                 mint: Callable[[str], AgentToken] = mint_agent_token,
                 verifier: Verifier | None = None,
                 client_ids: Mapping[str, str] | None = None,
                 timeout_s: float = DEFAULT_TIMEOUT_S):
        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("agent_id is required")
        self.grant_id = grant_id
        self.workflow_id = workflow_id
        self.url = url or gateway_url()
        self._timeout_s = timeout_s

        token = mint(agent_id)
        self.__token = token.access_token
        verifier = verifier or Verifier.from_config()
        client_ids = dict(client_ids if client_ids is not None else agent_client_ids())
        # Raises AuthError on a bad token: fail closed before anything is sent.
        claims = verifier.verify_agent(self.__token, set(client_ids), REQUIRED_SCOPE)
        verified = client_ids.get(claims["client_id"])
        if verified != agent_id:
            raise IdentityMismatch(
                f"token minted for {agent_id} verifies as {verified or 'an unknown agent'} "
                f"(client_id {claims['client_id']}). Check the agent's entry in shared/cognito.json.")
        self.agent_id: str = verified
        self.client_id: str = claims["client_id"]

    def __repr__(self) -> str:
        return (f"AgentSession(agent_id={self.agent_id!r}, grant_id={self.grant_id!r}, "
                f"workflow_id={self.workflow_id!r}, url={self.url!r})")

    __str__ = __repr__

    def _headers(self) -> dict[str, str]:
        headers = {}
        if self.grant_id:
            headers["X-Grant-Id"] = self.grant_id
        if self.workflow_id:
            headers["X-Workflow-Id"] = self.workflow_id
        return headers

    async def _call_async(self, tool: str, args: dict[str, Any]):
        transport = StreamableHttpTransport(self.url, headers=self._headers(),
                                            auth=BearerAuth(self.__token))
        async with Client(transport, timeout=self._timeout_s) as client:
            return await client.call_tool(tool, args, raise_on_error=False)

    def call(self, tool: str, **args: Any) -> Any:
        """Run one tool. Returns its result; raises Denied, ToolFailed or another GatewayError."""
        try:
            result = asyncio.run(self._call_async(tool, args))
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            detail = _scrub(f"{type(e).__name__}: {e}", self.__token)
            if _connection_failure(e):
                raise GatewayUnavailable(
                    f"can't reach the gateway at {self.url} ({detail}). Is the tunnel open? "
                    f"Run .\\scripts\\start-tunnel.ps1 or set {GATEWAY_URL_ENV}.") from None
            raise GatewayRejected(
                f"gateway at {self.url} refused {self.agent_id}'s request before {tool} ran "
                f"({detail}). A rejected or expired agent token gives this.") from None

        if result.is_error:
            text = " ".join(getattr(c, "text", "") for c in result.content).strip()
            if text.startswith(DENIED_PREFIX):
                reason = text[len(DENIED_PREFIX):].strip() or "unspecified"
                raise Denied(_scrub(reason, self.__token), tool, self.agent_id, self.grant_id)
            raise ToolFailed(f"{tool} failed for {self.agent_id}: "
                             f"{_scrub(text or 'no error text', self.__token)}")
        if result.data is not None:
            return result.data
        return result.structured_content

    def whoami(self) -> dict:
        """Ask the gateway who it thinks we are; refuse if it disagrees with our verified ID."""
        info = self.call("agentledger_whoami")
        if not isinstance(info, dict) or info.get("agent_id") != self.agent_id:
            seen = info.get("agent_id") if isinstance(info, dict) else None
            raise IdentityMismatch(f"gateway sees {seen!r}, session verified {self.agent_id!r}")
        return info
