"""AgentLedger MCP gateway. Every /mcp request needs a valid agent bearer token."""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token, get_http_headers

from controlplane.auth.jwt_verify import Verifier, agent_client_ids

from . import audit, github, llm, sentinel as sentinel_mod
from .auth import AUTH_MODE, AgentTokenVerifier
from .authorization import Decision, authorize
from .grants import Grant, GrantStore
from .store_select import GrantStoreConfigError, build_grant_store

HOST = "127.0.0.1"  # loopback only; reach it through a tunnel or reverse proxy
PORT = 8000
MAX_ERROR_CHARS = 200


class GatewayConfigError(RuntimeError):
    """Auth config missing or unusable. The gateway refuses to start."""


@dataclass(frozen=True)
class Authorized:
    """A protected call that passed every check. `activity_id` ties its audit lines together."""
    grant: Grant
    activity_id: str
    agent_id: str | None
    grant_id: str | None
    workflow_id: str | None


def new_activity_id() -> str:
    return "act_" + uuid.uuid4().hex[:12]


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

    def _caller():
        token = get_access_token()
        return (agents.get(token.client_id) if token else None), get_http_headers()

    def _sentinel_update(decision, agent_id, grant_id, workflow_id, tool, activity_id) -> None:
        """Count violations by the grant's own agent; lock the grant when the streak is long."""
        if decision.allowed:
            sentinel.allowed(grant_id)
            return
        g = decision.grant
        if g is None or g.agent_id != agent_id:
            return  # a stranger's denial never counts against someone else's grant
        if sentinel.violation(grant_id, decision.reason):
            try:
                audit.record(audit_path, event="sentinel", activity_id=activity_id,
                             agent_id=agent_id, grant_id=grant_id, workflow_id=workflow_id,
                             human_id=g.human_id, tool=tool, resource={}, decision="lock",
                             reason="repeated_violations")
            except audit.AuditError:
                pass  # the lock is already in place; the denial itself was audited above

    def guard(tool: str, resource: dict | None = None, repo_required: bool = False,
              branch: str | None = None, model: str | None = None) -> Authorized:
        """Run the authorization pipeline for a protected tool. Raises ToolError on denial.

        Every decision, allowed or denied, is written to the audit trail before anything
        runs. If that line cannot be written the call is denied."""
        activity_id = new_activity_id()
        agent_id, headers = _caller()
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
                audit_path, event="decision", activity_id=activity_id, agent_id=agent_id,
                grant_id=grant_id, workflow_id=workflow_id,
                human_id=decision.grant.human_id if decision.grant else None,
                tool=tool, resource=resource,
                decision="allow" if decision.allowed else "deny", reason=decision.reason,
            )
        except audit.AuditError:  # fail closed: no record, no action
            raise ToolError("denied: audit_unavailable") from None
        _sentinel_update(decision, agent_id, grant_id, workflow_id, tool, activity_id)
        if not decision.allowed:
            raise ToolError(f"denied: {decision.reason}")
        return Authorized(decision.grant, activity_id, agent_id, grant_id, workflow_id)

    def _post(a: Authorized, tool: str, started: float, *, decision: str, status: str,
              resource: dict | None = None, artifact: dict | None = None,
              source: str | None = None, evidence: str | None = None,
              error: str | None = None) -> None:
        """Write the line that says what happened after the call. The action is already done
        (or has failed), so a write failure here is logged by the audit module, not raised."""
        fields = dict(
            event="outcome" if decision == "outcome" else decision,
            activity_id=a.activity_id, agent_id=a.agent_id, grant_id=a.grant_id,
            workflow_id=a.workflow_id, human_id=a.grant.human_id, tool=tool,
            decision=decision, status=status,
            reason="completed" if status == "succeeded" else "failed",
            resource=resource or {}, elapsed_ms=int((time.monotonic() - started) * 1000))
        for key, value in (("artifact", artifact), ("source", source),
                           ("evidence", evidence), ("error", error)):
            if value is not None:
                fields[key] = value
        try:
            audit.record(audit_path, **fields)
        except audit.AuditError:
            pass
    def _execute(a: Authorized, tool: str, fn: Callable[[], dict],
                 artifact_of: Callable[[dict], dict | None] = lambda r: None,
                 source: str | None = None, evidence: str | None = None,
                 success_decision: str = "outcome",
                 resource_of: Callable[[dict], dict] = lambda r: {}) -> dict:
        """Run an allowed call and record whether it succeeded. Errors the agent may see are
        the ones our own adapters raise (safe by design); anything else becomes 'internal error'."""
        started = time.monotonic()
        try:
            result = fn()
        except (github.GitHubError, llm.LLMError, ToolError) as e:
            msg = str(e)[:MAX_ERROR_CHARS]
            _post(a, tool, started, decision="outcome", status="failed", error=msg)
            raise ToolError(msg) from e
        except Exception as e:
            logging.getLogger("agentledger.gateway").exception("tool %s crashed", tool)
            _post(a, tool, started, decision="outcome", status="failed", error=type(e).__name__)
            raise ToolError("internal error") from None
        _post(a, tool, started, decision=success_decision, status="succeeded",
              resource=resource_of(result), artifact=artifact_of(result),
              source=source, evidence=evidence)
        return result

    def _identity_event(tool: str) -> None:
        """Audit the tools that need no grant (ping, whoami). Fails closed like the rest."""
        agent_id, _ = _caller()
        try:
            audit.record(audit_path, event="identity", activity_id=new_activity_id(),
                         agent_id=agent_id, grant_id=None, workflow_id=None, human_id=None,
                         tool=tool, resource={}, decision="allow", reason="authenticated")
        except audit.AuditError:
            raise ToolError("denied: audit_unavailable") from None

    @mcp.tool
    def get_issue(issue_number: int) -> dict:
        """Get an issue from the repository named in your grant. You cannot choose the repository."""
        a = guard("get_issue", {"issue": issue_number}, repo_required=github_app is not None)

        def run():
            if github_app is None:  # development mock: issue #42 only, no GitHub call
                if issue_number != 42:
                    raise ToolError("issue not found")
                return {"number": 42, "title": "Mock issue for gateway testing",
                        "state": "open", "mock": True}
            return github_app.get_issue(a.grant.resources["repository"], issue_number)

        live = github_app is not None
        return _execute(
            a, "get_issue", run, source="github_api" if live else "mock",
            evidence="external" if live else "none",
            artifact_of=lambda r: {"kind": "issue", "repository": r.get("repository"),
                                   "number": r.get("number"), "state": r.get("state")})

    def _need_github() -> github.GitHubApp:
        if github_app is None:
            raise ToolError("github is not configured on this gateway")
        return github_app

    @mcp.tool
    def create_branch(branch: str) -> dict:
        """Create a branch in the repository named in your grant, from the grant's base branch.
        The name must start with your grant's branch prefix. You cannot choose the repository."""
        a = guard("create_branch", {}, repo_required=True, branch=branch)
        return _execute(
            a, "create_branch",
            lambda: _need_github().create_branch(
                a.grant.resources["repository"], branch, a.grant.resources.get("base_branch", "main")),
            source="github_api", evidence="external",
            artifact_of=lambda r: {"kind": "git_branch", "repository": r.get("repository"),
                                   "branch": r.get("branch"), "sha": r.get("sha")})

    @mcp.tool
    def commit_file(branch: str, path: str, content: str, message: str) -> dict:
        """Create or update one text file on a branch under your grant's branch prefix.
        Cannot write to the base branch. Content is limited to 100 KB."""
        a = guard("commit_file", {"path": path}, repo_required=True, branch=branch)
        return _execute(
            a, "commit_file",
            lambda: _need_github().commit_file(
                a.grant.resources["repository"], branch, path, content, message),
            source="github_api", evidence="external",
            artifact_of=lambda r: {"kind": "git_commit", "repository": r.get("repository"),
                                   "branch": r.get("branch"), "path": r.get("path"),
                                   "sha": r.get("commit_sha")})

    @mcp.tool
    def llm_converse(messages: list[dict], model: str | None = None,
                     system: str | None = None) -> dict:
        """Ask a language model. messages is a list of {"role": "user"|"assistant", "content": text}
        that alternates and ends with a user message. The model must be one your grant lists
        (the first one is used if you give none). Output length is capped by your grant."""
        # Peek at the grant to pick the default model; the guard still does the real check.
        agent_id, headers = _caller()
        try:
            g = grants.get(headers.get("x-grant-id") or "")
        except Exception:
            g = None
        listed = (g.resources.get("models") if g and g.agent_id == agent_id else None) or []
        chosen = model or (listed[0] if listed else "")
        a = guard("llm_converse", {}, model=chosen)
        return _execute(
            a, "llm_converse",
            lambda: llm_client.converse(
                chosen, messages, system, llm.effective_max_tokens(a.grant.resources.get("max_tokens"))),
            source="bedrock", success_decision="usage",
            resource_of=lambda r: {"model": chosen, "input_tokens": r.get("input_tokens"),
                                   "output_tokens": r.get("output_tokens")})

    @mcp.tool
    def agentledger_ping() -> dict:
        """Check that Kiro can reach the AgentLedger gateway."""
        _identity_event("agentledger_ping")
        return {"connected": True, "service": "AgentLedger", "auth_mode": AUTH_MODE}

    @mcp.tool
    def agentledger_whoami() -> dict:
        """Show the verified agent identity for this connection."""
        token = get_access_token()
        if token is None:
            raise ToolError("not authenticated")
        _identity_event("agentledger_whoami")
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
