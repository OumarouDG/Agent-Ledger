"""AgentLedger MCP gateway. Every /mcp request needs a valid agent bearer token."""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token, get_http_headers

from controlplane.auth.jwt_verify import Verifier, agent_client_ids

from . import audit, github
from .auth import AUTH_MODE, AgentTokenVerifier
from .authorization import Decision, authorize
from .grants import GrantStore, JsonFileGrantStore

HOST = "127.0.0.1"  # loopback only; reach it through a tunnel or reverse proxy
PORT = 8000


class GatewayConfigError(RuntimeError):
    """Auth config missing or unusable. The gateway refuses to start."""


def create_server(verifier: Verifier | None = None,
                  client_ids: Mapping[str, str] | None = None,
                  grants: GrantStore | None = None,
                  audit_path: Path | None = None,
                  github_app: github.GitHubApp | None = None) -> FastMCP:
    """Build the gateway. Pass `verifier`/`client_ids` in tests; defaults load shared/cognito.json."""
    try:
        verifier = verifier or Verifier.from_config()
        client_ids = client_ids if client_ids is not None else agent_client_ids()
        auth = AgentTokenVerifier(verifier, client_ids)
    except Exception as e:  # no unauthenticated fallback
        raise GatewayConfigError(f"auth config unavailable: {type(e).__name__}: {e}") from e

    mcp = FastMCP("AgentLedger Gateway", auth=auth)
    agents = dict(client_ids)
    grants = grants or JsonFileGrantStore(
        os.environ.get("AGENTLEDGER_GRANTS_FILE", "gateway-grants.json"))
    audit_path = audit_path or audit.default_path()
    github_app = github_app or github.from_env(os.environ)  # None = mock issues (dev only)

    def guard(tool: str, resource: dict | None = None, repo_required: bool = False):
        """Run the authorization pipeline for a protected tool. Raises ToolError on denial.

        Every outcome, allowed or denied, is written to the audit trail."""
        token = get_access_token()
        agent_id = agents.get(token.client_id) if token else None
        headers = get_http_headers()
        grant_id = headers.get("x-grant-id")
        workflow_id = headers.get("x-workflow-id")
        decision = authorize(grants, agent_id=agent_id, grant_id=grant_id,
                             workflow_id=workflow_id, tool=tool)
        resource = dict(resource or {})
        if decision.allowed and repo_required:
            repo = decision.grant.resources.get("repository")
            if not repo:
                decision = Decision(False, "resource_not_in_grant", decision.grant)
            else:
                resource["repository"] = repo
        audit.record(
            audit_path, agent_id=agent_id, grant_id=grant_id, workflow_id=workflow_id,
            human_id=decision.grant.human_id if decision.grant else None,
            tool=tool, resource=resource,
            decision="allow" if decision.allowed else "deny", reason=decision.reason,
        )
        if not decision.allowed:
            raise ToolError(f"denied: {decision.reason}")
        return decision.grant

    @mcp.tool
    def get_issue(issue_number: int) -> dict:
        """Get an issue from the repository named in your grant. You cannot choose the repository."""
        grant = guard("get_issue", {"issue": issue_number}, repo_required=github_app is not None)
        if github_app is None:  # development mock: issue #42 only, no GitHub call
            if issue_number != 42:
                raise ToolError("issue not found")
            return {"number": 42, "title": "Mock issue for gateway testing", "state": "open",
                    "mock": True}
        try:
            return github_app.get_issue(grant.resources["repository"], issue_number)
        except github.GitHubError as e:
            raise ToolError(str(e)) from e

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
