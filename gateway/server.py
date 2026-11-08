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

from . import audit, github, llm, sentinel as sentinel_mod
from .auth import AUTH_MODE, AgentTokenVerifier
from .authorization import Decision, authorize
from .grants import GrantStore
from .store_select import GrantStoreConfigError, build_grant_store

HOST = "127.0.0.1"  # loopback only; reach it through a tunnel or reverse proxy
PORT = 8000


class GatewayConfigError(RuntimeError):
    """Auth config missing or unusable. The gateway refuses to start."""


def create_server(verifier: Verifier | None = None,
                  client_ids: Mapping[str, str] | None = None,
                  grants: GrantStore | None = None,
                  audit_path: Path | None = None,
                  github_app: github.GitHubApp | None = None,
                  llm_client: llm.BedrockLLM | None = None,
                  sentinel: sentinel_mod.Sentinel | None = None) -> FastMCP:
    """Build the gateway. Pass `verifier`/`client_ids` in tests; defaults load shared/cognito.json."""
    try:
        verifier = verifier or Verifier.from_config()
        client_ids = client_ids if client_ids is not None else agent_client_ids()
        auth = AgentTokenVerifier(verifier, client_ids)
    except Exception as e:  # no unauthenticated fallback
        raise GatewayConfigError(f"auth config unavailable: {type(e).__name__}: {e}") from e

    mcp = FastMCP("AgentLedger Gateway", auth=auth)
    agents = dict(client_ids)
    try:
        grants = grants or build_grant_store(os.environ)
    except GrantStoreConfigError as e:  # no fallback to a different store
        raise GatewayConfigError(str(e)) from e
    audit_path = audit_path or audit.default_path()
    llm_client = llm_client or llm.BedrockLLM()
    try:
        sentinel = sentinel or sentinel_mod.Sentinel(sentinel_mod.default_lock_path(),
                                                     sentinel_mod.threshold_from_env(os.environ))
    except ValueError as e:
        raise GatewayConfigError(str(e)) from e
    github_app = github_app or github.from_env(os.environ)  # None = mock issues (dev only)

    def _sentinel_update(decision, agent_id, grant_id, workflow_id, tool) -> None:
        """Count violations by the grant's own agent; lock the grant when the streak is long."""
        if decision.allowed:
            sentinel.allowed(grant_id)
            return
        g = decision.grant
        if g is None or g.agent_id != agent_id:
            return  # a stranger's denial never counts against someone else's grant
        if sentinel.violation(grant_id, decision.reason):
            try:
                audit.record(audit_path, event="sentinel", agent_id=agent_id, grant_id=grant_id,
                             workflow_id=workflow_id, human_id=g.human_id, tool=tool,
                             resource={}, decision="lock", reason="repeated_violations")
            except audit.AuditError:
                pass  # the lock is already in place; the denial itself was audited above
    def guard(tool: str, resource: dict | None = None, repo_required: bool = False,
              branch: str | None = None, model: str | None = None):
        """Run the authorization pipeline for a protected tool. Raises ToolError on denial.

        Every outcome, allowed or denied, is written to the audit trail. If the event cannot be\n        written the call is denied."""
        token = get_access_token()
        agent_id = agents.get(token.client_id) if token else None
        headers = get_http_headers()
        grant_id = headers.get("x-grant-id")
        workflow_id = headers.get("x-workflow-id")
        decision = authorize(grants, agent_id=agent_id, grant_id=grant_id,
                             workflow_id=workflow_id, tool=tool)
        if decision.allowed and sentinel.is_locked(grant_id):
            decision = Decision(False, "grant_quarantined", decision.grant)
        resource = dict(resource or {})
        if decision.allowed and repo_required:
            repo = decision.grant.resources.get("repository")
            if not repo:
                decision = Decision(False, "resource_not_in_grant", decision.grant)
            else:
                resource["repository"] = repo
        if decision.allowed and branch is not None:
            prefix = decision.grant.resources.get("branch_prefix")
            ok = (isinstance(prefix, str) and prefix.endswith("/") and len(prefix) > 1
                  and github.valid_branch(branch) and branch.startswith(prefix)
                  and branch != prefix)
            resource["branch"] = branch
            if not ok:
                decision = Decision(False, "branch_not_permitted", decision.grant)
        if decision.allowed and model is not None:
            allowed_models = decision.grant.resources.get("models")
            resource["model"] = model
            if not (isinstance(allowed_models, list) and model in allowed_models):
                decision = Decision(False, "model_not_permitted", decision.grant)
        try:
            audit.record(
                audit_path, agent_id=agent_id, grant_id=grant_id, workflow_id=workflow_id,
                human_id=decision.grant.human_id if decision.grant else None,
                tool=tool, resource=resource,
                decision="allow" if decision.allowed else "deny", reason=decision.reason,
            )
        except audit.AuditError:  # fail closed: no record, no action
            raise ToolError("denied: audit_unavailable") from None
        _sentinel_update(decision, agent_id, grant_id, workflow_id, tool)
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

    def _need_github() -> github.GitHubApp:
        if github_app is None:
            raise ToolError("github is not configured on this gateway")
        return github_app

    @mcp.tool
    def create_branch(branch: str) -> dict:
        """Create a branch in the repository named in your grant, from the grant's base branch.
        The name must start with your grant's branch prefix. You cannot choose the repository."""
        grant = guard("create_branch", {}, repo_required=True, branch=branch)
        try:
            return _need_github().create_branch(
                grant.resources["repository"], branch, grant.resources.get("base_branch", "main"))
        except github.GitHubError as e:
            raise ToolError(str(e)) from e

    @mcp.tool
    def commit_file(branch: str, path: str, content: str, message: str) -> dict:
        """Create or update one text file on a branch under your grant's branch prefix.
        Cannot write to the base branch. Content is limited to 100 KB."""
        grant = guard("commit_file", {"path": path}, repo_required=True, branch=branch)
        try:
            return _need_github().commit_file(
                grant.resources["repository"], branch, path, content, message)
        except github.GitHubError as e:
            raise ToolError(str(e)) from e
    @mcp.tool
    def llm_converse(messages: list[dict], model: str | None = None,
                     system: str | None = None) -> dict:
        """Ask a language model. messages is a list of {"role": "user"|"assistant", "content": text}
        that alternates and ends with a user message. The model must be one your grant lists
        (the first one is used if you give none). Output length is capped by your grant."""
        # Peek at the grant to pick the default model; the guard still does the real check.
        token = get_access_token()
        agent_id = agents.get(token.client_id) if token else None
        headers = get_http_headers()
        try:
            g = grants.get(headers.get("x-grant-id") or "")
        except Exception:
            g = None
        listed = (g.resources.get("models") if g and g.agent_id == agent_id else None) or []
        chosen = model or (listed[0] if listed else "")
        grant = guard("llm_converse", {}, model=chosen)
        try:
            result = llm_client.converse(
                chosen, messages, system, llm.effective_max_tokens(grant.resources.get("max_tokens")))
        except llm.LLMError as e:
            raise ToolError(str(e)) from e
        try:  # after the call; the pre-call record already allowed it
            audit.record(audit_path, event="usage", agent_id=agent_id,
                         grant_id=headers.get("x-grant-id"), workflow_id=headers.get("x-workflow-id"),
                         human_id=grant.human_id, tool="llm_converse", decision="usage",
                         reason="completed", resource={"model": chosen,
                         "input_tokens": result.get("input_tokens"),
                         "output_tokens": result.get("output_tokens")})
        except audit.AuditError:
            pass  # cannot undo a finished call; the failure is logged by the audit module
        return result
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
