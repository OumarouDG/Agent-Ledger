"""Rogue probe: agent_rogue tries to misuse a live workflow's grants. Every attempt must fail.

The signed-in human gives Rogue its own fresh root grant for each probe (tool get_issue,
prefix agentledger/<wf>/rogue/), so a Sentinel lock never carries over between rehearsals.
Rogue's grant is revoked when the probe ends, whatever happened.

Attacks and the refusal each must get:
  1. Coder's grant ID with Rogue's own token     -> grant_agent_mismatch (Sentinel: no)
  2. A tool call with no grant                   -> missing_grant        (Sentinel: no)
  3. Delegate a child from Lead's grant          -> not_parent_holder, at create, no gateway call
  4. create_branch main on Rogue's own grant     -> tool_not_permitted   (Sentinel: yes)

`until_locked`: the Sentinel only turns an ALLOWED call into grant_quarantined; a denied call
keeps its own reason after the lock. So the probe sends violations until it has sent
SENTINEL_THRESHOLD in a row (attack 4 is the first), then calls get_issue, which the grant
allows: it must now be denied grant_quarantined. That check call, if allowed, resets the
streak, so it is made once.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from controlplane.grants.errors import GrantRefused
from controlplane.grants.service import GrantRequest, create_grant, list_grants, revoke_grant
from gateway.grants import Grant

from .gateway_client import (
    AgentSession, Denied, GatewayError, GatewayUnavailable, ToolFailed)
from .workflow import CODER, LEAD, _open_default, check_workflow_id, delegate

ROGUE = "agent_rogue"
ROGUE_TOOLS = frozenset({"get_issue"})
ROGUE_TTL_SECONDS = 15 * 60
SENTINEL_THRESHOLD = 3  # docs/workstreams/RUNTIME.md: three denials in a row lock a grant
ALLOWED = "ALLOWED"


class ProbeError(RuntimeError):
    """The probe could not run (no live workflow, grant refused). Not an attack result."""


@dataclass(frozen=True)
class Attempt:
    name: str
    expected: str  # reason code expected, or ALLOWED for the baseline
    got: str  # reason code, or ALLOWED, or another description
    allowed: bool  # True if the gateway (or the grant service) let it through

    @property
    def ok(self) -> bool:
        return self.got == self.expected and (self.expected == ALLOWED) == self.allowed


@dataclass
class ProbeResult:
    workflow_id: str
    rogue_grant_id: str
    lead_grant_id: str
    coder_grant_id: str
    attempts: list[Attempt] = field(default_factory=list)
    revoked: bool = False

    @property
    def ok(self) -> bool:
        return bool(self.attempts) and all(a.ok for a in self.attempts)


def rogue_prefix(workflow_id: str) -> str:
    return f"agentledger/{workflow_id}/rogue/"


def find_targets(store, human, workflow_id: str, now: float | None = None) -> tuple[Grant, Grant]:
    """The newest active Lead root in the workflow and its active Coder child.

    Candidates come from list_grants (an index that can lag); each is re-read with a
    consistent get before it is used.
    """
    now = time.time() if now is None else now
    rows = list_grants(store=store, human=human, workflow_id=workflow_id)
    fresh = [g for g in (store.get(r.grant_id) for r in rows) if g is not None]
    active = [g for g in fresh if g.status == "active" and (g.expires_at or 0) > now]
    leads = sorted((g for g in active if g.agent_id == LEAD and g.parent_grant_id is None),
                   key=lambda g: g.expires_at or 0, reverse=True)
    for lead in leads:
        coders = [g for g in active if g.agent_id == CODER and g.parent_grant_id == lead.grant_id]
        if coders:
            return lead, max(coders, key=lambda g: g.expires_at or 0)
    raise ProbeError(f"no active Lead and Coder grants in {workflow_id}; "
                     f"start one with: agentledger run --issue 1 --workflow {workflow_id}")


def _gateway_attempt(name: str, expected: str, s: AgentSession, tool: str, **args) -> Attempt:
    try:
        s.call(tool, **args)
        return Attempt(name, expected, ALLOWED, True)
    except Denied as e:
        return Attempt(name, expected, e.reason, False)
    except ToolFailed as e:  # passed the guard; the tool itself then failed
        return Attempt(name, expected, f"{ALLOWED} (then the tool failed: {e})", True)
    except GatewayUnavailable:
        raise
    except GatewayError as e:
        return Attempt(name, expected, f"error before the tool ran: {e}", False)


def run_probe(human, workflow_id: str, *, store, open_agent=_open_default, issue: int = 1,
              until_locked: bool = False, agents: frozenset[str] | None = None,
              out: Callable[[str], None] | None = print, now: float | None = None) -> ProbeResult:
    """Run the attacks. Raises ProbeError if the probe cannot start, GatewayUnavailable if the
    gateway cannot be reached. Rogue's grant is revoked on the way out in every case."""
    say = out or (lambda line: None)
    check_workflow_id(workflow_id)
    now = time.time() if now is None else now
    lead, coder = find_targets(store, human, workflow_id, now)
    repo = lead.resources.get("repository")
    try:
        rogue_grant = create_grant(GrantRequest(
            agent_id=ROGUE, workflow_id=workflow_id, tools=ROGUE_TOOLS,
            expires_at=int(now) + ROGUE_TTL_SECONDS, repository=repo,
            branch_prefix=rogue_prefix(workflow_id),
        ), store=store, human=human, agents=agents, now=now)
    except GrantRefused as e:
        raise ProbeError(f"could not give {ROGUE} its own grant: {e}") from None

    result = ProbeResult(workflow_id, rogue_grant.grant_id, lead.grant_id, coder.grant_id)
    say(f"probe {workflow_id}: {ROGUE} got its own root grant {rogue_grant.grant_id} "
        f"(tools get_issue, prefix {rogue_prefix(workflow_id)}, 15 min)")
    say(f"  targets: lead {lead.grant_id}, coder {coder.grant_id}")

    def record(a: Attempt) -> None:
        result.attempts.append(a)
        if a.ok:
            mark = "OK"
        elif a.expected == ALLOWED:
            mark = "BASELINE FAILED: the probe's own grant does not work"
        elif a.allowed:
            mark = "ALLOWED (unexpected)"
        else:
            mark = f"WRONG REASON (expected {a.expected})"
        say(f"  {a.name:46} -> {a.got:22} {mark}")

    try:
        own = open_agent(ROGUE, rogue_grant.grant_id, workflow_id)
        record(_gateway_attempt("baseline: get_issue on its own grant", ALLOWED, own,
                                "get_issue", issue_number=issue))
        stolen = open_agent(ROGUE, coder.grant_id, workflow_id)
        record(_gateway_attempt("1 Coder's grant ID with Rogue's token", "grant_agent_mismatch",
                                stolen, "get_issue", issue_number=issue))
        bare = open_agent(ROGUE, None, workflow_id)
        record(_gateway_attempt("2 a tool call with no grant", "missing_grant",
                                bare, "get_issue", issue_number=issue))
        record(_delegate_attempt(own, lead, store, workflow_id, repo, agents, now, human))
        record(_gateway_attempt("4 create_branch main on its own grant", "tool_not_permitted",
                                own, "create_branch", branch="main"))
        if until_locked:
            for n in range(2, SENTINEL_THRESHOLD + 1):
                record(_gateway_attempt(f"  violation {n}/{SENTINEL_THRESHOLD}: create_branch main",
                                        "tool_not_permitted", own, "create_branch", branch="main"))
            record(_gateway_attempt("Sentinel: get_issue after the lock", "grant_quarantined",
                                    own, "get_issue", issue_number=issue))
    finally:
        try:
            revoke_grant(rogue_grant.grant_id, store=store, human=human)
            result.revoked = True
            say(f"  revoked {ROGUE}'s grant {rogue_grant.grant_id}")
        except Exception as e:  # noqa: BLE001 - report it, never hide it
            say(f"  WARNING: could not revoke {rogue_grant.grant_id} ({type(e).__name__}); "
                f"revoke it with: agentledger grant revoke {rogue_grant.grant_id}")
    return result


def _delegate_attempt(rogue: AgentSession, lead: Grant, store, workflow_id: str, repo: str,
                      agents, now: float, human) -> Attempt:
    name, expected = "3 delegate a child from Lead's grant", "not_parent_holder"
    req = GrantRequest(agent_id=ROGUE, workflow_id=workflow_id, tools=ROGUE_TOOLS,
                       expires_at=min(int(now) + ROGUE_TTL_SECONDS, lead.expires_at or 0),
                       repository=repo, parent_grant_id=lead.grant_id)
    try:
        child = delegate(rogue, lead, req, store=store, agents=agents, now=now)
    except GrantRefused as e:
        return Attempt(name, expected, e.reason, False)
    try:  # it was written: take it back at once, and report it as allowed
        revoke_grant(child.grant_id, store=store, human=human)
        note = "revoked"
    except Exception as e:  # noqa: BLE001 - report it, never hide it
        note = f"NOT revoked ({type(e).__name__}): agentledger grant revoke {child.grant_id}"
    return Attempt(name, expected, f"{ALLOWED} (child {child.grant_id} written, {note})", True)
