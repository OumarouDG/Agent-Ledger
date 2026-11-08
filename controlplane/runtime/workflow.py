"""Start one workflow: the root grant for Lead from the signed-in human, then Lead's children.

Grant shapes are the ones agreed with Oumarou (docs/workstreams/RUNTIME.md, "Grant shapes").
Branch prefixes are derived from the workflow ID, never hard-coded. The delegator ID for the
child grants is the agent ID verified from Lead's own token (`AgentSession.agent_id`), never a
string in code. If anything fails after the root grant is written, every grant this call
wrote is revoked before the error is raised.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from controlplane.grants.errors import GrantRefused
from controlplane.grants.service import (
    GrantRequest, GrantWriter, HumanPrincipal, RevokeResult, create_grant, revoke_grant)
from gateway.grants import Grant

from .gateway_client import AgentSession

DEMO_REPO = "OumarouDG/agentledger-demo"
MODEL = "us.amazon.nova-lite-v1:0"  # confirmed by Oumarou
MAX_TOKENS = 300
TTL_SECONDS = 60 * 60

LEAD, CODER, TESTER = "agent_lead", "agent_coder", "agent_tester"
LEAD_TOOLS = frozenset({"get_issue", "llm_converse"})
CODER_TOOLS = frozenset({"get_issue", "create_branch", "commit_file", "open_pull_request",
                         "llm_converse"})
TESTER_TOOLS = frozenset({"get_test_result", "get_pull_request"})
LEAD_DELEGABLE = CODER_TOOLS | TESTER_TOOLS

RESERVED_WORKFLOWS = frozenset({"wf_001"})  # Oumarou's Kiro demo
_WORKFLOW_ID = re.compile(r"^wf_[A-Za-z0-9_-]{1,40}$")

OpenAgent = Callable[[str, str | None, str | None], AgentSession]


class WorkflowError(ValueError):
    """Bad input to start_workflow. Nothing was written."""


def new_workflow_id() -> str:
    return "wf_" + secrets.token_hex(4)


def new_run_id() -> str:
    """Short ID for one run, so a workflow (e.g. the wf_002 demo) can be rehearsed repeatedly."""
    return secrets.token_hex(3)


def coder_branch(workflow_id: str, issue: int, run_id: str) -> str:
    return f"{coder_prefix(workflow_id)}issue-{issue}-{run_id}"


def check_workflow_id(workflow_id: str) -> str:
    if not isinstance(workflow_id, str) or not _WORKFLOW_ID.match(workflow_id):
        raise WorkflowError(f"workflow ID {workflow_id!r} must look like wf_<letters, digits, _ or ->")
    if workflow_id in RESERVED_WORKFLOWS:
        raise WorkflowError(f"{workflow_id} is reserved for the Kiro demo; use another --workflow")
    return workflow_id


def root_prefix(workflow_id: str) -> str:
    return f"agentledger/{workflow_id}/"


def coder_prefix(workflow_id: str) -> str:
    return f"{root_prefix(workflow_id)}coder/"


def _check_issue(issue: object) -> int:
    if not isinstance(issue, int) or isinstance(issue, bool) or issue < 1:
        raise WorkflowError(f"issue must be a positive whole number, got {issue!r}")
    return issue


def _open_default(agent_id: str, grant_id: str | None, workflow_id: str | None) -> AgentSession:
    return AgentSession(agent_id, grant_id, workflow_id)


@dataclass(frozen=True)
class Workflow:
    workflow_id: str
    repository: str
    issue: int
    human_id: str
    root: Grant
    coder: Grant
    tester: Grant
    lead: AgentSession
    run_id: str

    @property
    def grants(self) -> tuple[Grant, Grant, Grant]:
        return (self.root, self.coder, self.tester)

    @property
    def branch(self) -> str:
        """The branch Coder creates for this run: agentledger/<wf>/coder/issue-<n>-<run_id>."""
        return coder_branch(self.workflow_id, self.issue, self.run_id)


def delegate(lead: AgentSession, parent: Grant, req: GrantRequest, *, store: GrantWriter,
             agents: frozenset[str] | None = None, now: float | None = None) -> Grant:
    """Create a child grant. The delegator is the agent verified from `lead`'s token."""
    if not isinstance(lead, AgentSession):
        raise TypeError("delegate needs the delegating agent's AgentSession, not a name")
    if req.parent_grant_id != parent.grant_id:
        raise WorkflowError("child request must name the parent grant it delegates from")
    return create_grant(req, store=store, delegator_agent_id=lead.agent_id, agents=agents, now=now)


def start_workflow(human: HumanPrincipal | None, issue: int, repo: str = DEMO_REPO, *,
                   store: GrantWriter, workflow_id: str | None = None,
                   open_agent: OpenAgent = _open_default, agents: frozenset[str] | None = None,
                   now: float | None = None,
                   out: Callable[[str], None] | None = print) -> Workflow:
    """Create the grant tree for one run and open Lead's session. Prints the tree via `out`."""
    username = getattr(human, "username", None)
    if not isinstance(username, str) or not username:
        raise GrantRefused("no_human", "starting a workflow needs a signed-in human; run agentledger login")
    issue = _check_issue(issue)
    wf = check_workflow_id(workflow_id if workflow_id is not None else new_workflow_id())
    now = time.time() if now is None else now
    expires_at = int(now) + TTL_SECONDS

    root = create_grant(GrantRequest(
        agent_id=LEAD, workflow_id=wf, tools=LEAD_TOOLS, delegable_tools=LEAD_DELEGABLE,
        expires_at=expires_at, repository=repo, branch_prefix=root_prefix(wf),
        models=frozenset({MODEL}), max_tokens=MAX_TOKENS,
    ), store=store, human=human, agents=agents, now=now)
    written = [root]
    try:
        lead = open_agent(LEAD, root.grant_id, wf)
        coder = delegate(lead, root, GrantRequest(
            agent_id=CODER, workflow_id=wf, tools=CODER_TOOLS, expires_at=expires_at,
            repository=repo, parent_grant_id=root.grant_id, branch_prefix=coder_prefix(wf),
            # GUESS: the agreed table says only "same model"; max_tokens is set too so Coder
            # cannot get the gateway default (1024) above Lead's 300.
            models=frozenset({MODEL}), max_tokens=MAX_TOKENS,
        ), store=store, agents=agents, now=now)
        written.append(coder)
        tester = delegate(lead, root, GrantRequest(
            agent_id=TESTER, workflow_id=wf, tools=TESTER_TOOLS, expires_at=expires_at,
            repository=repo, parent_grant_id=root.grant_id, branch_prefix=root_prefix(wf),
        ), store=store, agents=agents, now=now)
        written.append(tester)
    except BaseException as e:
        left = _revoke_quietly(written, store, human)
        if left:
            e.add_note("grants NOT revoked after this failure, revoke by hand: " + ", ".join(left))
        raise

    flow = Workflow(wf, repo, issue, username, root, coder, tester, lead, new_run_id())
    if out is not None:
        out(format_tree(flow))
    return flow


def _revoke_quietly(grants: list[Grant], store: GrantWriter, human: HumanPrincipal | None) -> list[str]:
    """Revoke each grant; return the IDs that could not be revoked."""
    left = []
    for g in grants:
        try:
            revoke_grant(g.grant_id, store=store, human=human)
        except Exception as e:  # noqa: BLE001 - keep going, report every one left
            left.append(f"{g.grant_id} ({type(e).__name__})")
    return left


def revoke_workflow(flow: Workflow, *, store: GrantWriter,
                    human: HumanPrincipal | None) -> list[RevokeResult]:
    """Revoke root first (the gateway then denies both children), then each child."""
    return [revoke_grant(g.grant_id, store=store, human=human) for g in flow.grants]


def _names(tools: frozenset[str]) -> str:
    return ", ".join(sorted(tools)) or "(none)"


def _line(g: Grant) -> str:
    r = g.resources
    parts = [f"{g.grant_id}  {g.agent_id}", f"tools: {_names(g.tools)}"]
    if g.delegable_tools:
        parts.append(f"delegable: {_names(g.delegable_tools)}")
    parts.append(f"prefix: {r.get('branch_prefix', '(none)')}")
    if r.get("models"):
        parts.append(f"models: {', '.join(r['models'])}  max_tokens: {r.get('max_tokens', 'default')}")
    return "  |  ".join(parts)


def format_tree(flow: Workflow) -> str:
    """ASCII grant tree. Holds grant IDs, agents and limits only; never a token."""
    mins = max(0, int(((flow.root.expires_at or 0) - time.time()) // 60))
    return "\n".join([
        f"workflow {flow.workflow_id}  run {flow.run_id}  repo {flow.repository}  "
        f"issue #{flow.issue}  expires in {mins} min",
        f"{flow.human_id} (signed in)",
        f"  +- {_line(flow.root)}",
        f"       +- {_line(flow.coder)}",
        f"       +- {_line(flow.tester)}",
    ])
