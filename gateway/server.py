"""AgentLedger MCP gateway. Every /mcp request needs a valid agent bearer token."""

from __future__ import annotations

import logging
from collections.abc import Mapping

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token

from controlplane.auth.jwt_verify import Verifier, agent_client_ids

from .auth import AUTH_MODE, AgentTokenVerifier

HOST = "127.0.0.1"  # loopback only; reach it through a tunnel or reverse proxy
PORT = 8000


class GatewayConfigError(RuntimeError):
    """Auth config missing or unusable. The gateway refuses to start."""


def create_server(verifier: Verifier | None = None,
                  client_ids: Mapping[str, str] | None = None) -> FastMCP:
    """Build the gateway. Pass `verifier`/`client_ids` in tests; defaults load shared/cognito.json."""
    try:
        verifier = verifier or Verifier.from_config()
        client_ids = client_ids if client_ids is not None else agent_client_ids()
        auth = AgentTokenVerifier(verifier, client_ids)
    except Exception as e:  # no unauthenticated fallback
        raise GatewayConfigError(f"auth config unavailable: {type(e).__name__}: {e}") from e

    mcp = FastMCP("AgentLedger Gateway", auth=auth)
    agents = dict(client_ids)

    @mcp.tool
    def agentledger_ping() -> dict:
        """Check that Kiro can reach the AgentLedger gateway."""
        return {"connected": True, "service": "AgentLedger", "auth_mode": AUTH_MODE}

    @mcp.tool
    def agentledger_whoami() -> dict:
        """Show the verified agent identity for this connection."""
        token = get_access_token()
        if token is None:
            raise ToolError("not authenticated")
        return {
            "agent_id": agents.get(token.client_id),
            "client_id": token.client_id,
            "scopes": token.scopes,
            "auth_mode": AUTH_MODE,
        }

    return mcp


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    create_server().run(transport="http", host=HOST, port=PORT)


if __name__ == "__main__":
    main()
