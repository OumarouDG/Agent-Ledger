"""Create and revoke delegation grants.

`check_request` holds every delegation rule as a pure function (no AWS), so each rule is
unit-testable. `create_grant` loads the parent chain, runs the rules, then does one
conditional write. `revoke_grant` only sets status=revoked: children die through the
gateway's parent walk, nothing is cascaded by writing, and no grant is ever deleted.

Every broken rule raises `GrantRefused(reason)` and writes nothing. Nothing is trimmed.
"""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass
from typing import Iterable, Protocol

from controlplane.auth.config import load_config
from controlplane.grants.errors import GrantNotFound, GrantRefused
from gateway.authorization import MAX_PARENT_DEPTH
from gateway.grants import Grant, GrantStoreError

MAX_TTL_SECONDS = 4 * 3600  # GUESS: demo cap on how far out a grant may expire
ROOT_ROLES = frozenset({"engineer", "security-admin"})  # GUESS: confirm with Oumarou
REVOKE_ANY_ROLE = "security-admin"  # GUESS: may revoke any grant; others only their own
# GitHub-shaped owner/name: owner 1-39 alnum or hyphen, name 1-100 of alnum . _ -
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")


class HumanPrincipal(Protocol):
    """A verified human, e.g. the CLI's `Session` from `current_session()`."""

    @property
    def username(self) -> str: ...

    @property
    def groups(self) -> Iterable[str]: ...


class GrantWriter(Protocol):
    def get(self, grant_id: str) -> Grant | None: ...
    def put_new(self, grant: Grant, *, created_at: int, created_by: str) -> None: ...
    def mark_revoked(self, grant_id: str, *, revoked_at: int, revoked_by: str) -> bool: ...


class GrantReader(Protocol):
    def get(self, grant_id: str) -> Grant | None: ...
    def by_workflow(self, workflow_id: str) -> list[Grant]: ...
    def all(self) -> list[Grant]: ...


@dataclass(frozen=True)
class GrantRequest:
    agent_id: str
    workflow_id: str
    tools: frozenset[str]
    expires_at: int
    repository: str
    delegable_tools: frozenset[str] = frozenset()
    parent_grant_id: str | None = None  # None = root grant from a human
    human_id: str | None = None  # child only, and must equal the parent's; root takes the session's


@dataclass(frozen=True)
class RevokeResult:
    grant_id: str
    already_revoked: bool
    message: str


@dataclass(frozen=True)
class Chain:
    """The parent grant first, then its ancestors. `problem` is set when the walk failed."""

    grants: tuple[Grant, ...] = ()
    problem: str | None = None  # "missing" | "cycle" | "too_deep"


def new_grant_id() -> str:
    return "gr_" + secrets.token_urlsafe(12)


def registered_agents() -> frozenset[str]:
    return frozenset(load_config().get("agents", {}))


# --- rules (pure) -------------------------------------------------------------

def _usable(g: Grant, now: float) -> bool:
    return g.status == "active" and (g.expires_at is None or g.expires_at > now)


def _tool_names(tools: object) -> bool:
    return isinstance(tools, frozenset) and all(isinstance(t, str) and t for t in tools)


def check_request(req: GrantRequest, *, human: HumanPrincipal | None,
                  delegator_agent_id: str | None, chain: Chain,
                  agents: frozenset[str], now: float) -> str:
    """Raise GrantRefused for the first broken rule. Return the human_id the grant gets."""
    if not isinstance(req.workflow_id, str) or not req.workflow_id:
        raise GrantRefused("bad_request", "workflow_id must be a non-empty string")
    if not _tool_names(req.tools) or not _tool_names(req.delegable_tools):
        raise GrantRefused("bad_request", "tools and delegable_tools must be sets of tool names")
    if req.agent_id not in agents:
        raise GrantRefused("unknown_agent", f"{req.agent_id!r} is not registered in shared/cognito.json")
    if not isinstance(req.repository, str) or not _REPO.match(req.repository):
        raise GrantRefused("bad_repository", "repository must look like owner/name")
    exp = req.expires_at
    if not isinstance(exp, int) or isinstance(exp, bool) or exp <= now or exp > now + MAX_TTL_SECONDS:
        raise GrantRefused("bad_expiry", f"expires_at must be in the future and at most "
                                         f"{MAX_TTL_SECONDS // 3600} h out")
    if not req.tools:
        raise GrantRefused("no_tools", "a grant must allow at least one tool")
    if req.parent_grant_id is None:
        return _check_root(req, human)
    return _check_child(req, delegator_agent_id, chain, now)


def _check_root(req: GrantRequest, human: HumanPrincipal | None) -> str:
    username = getattr(human, "username", None)
    if not isinstance(username, str) or not username:
        raise GrantRefused("no_human", "a root grant needs a signed-in human; run agentledger login")
    if req.human_id is not None and req.human_id != username:
        raise GrantRefused("human_mismatch", "human_id comes from the signed-in session, not the request")
    if not ROOT_ROLES & set(getattr(human, "groups", None) or ()):
        raise GrantRefused("role_not_permitted",
                           f"{username} is not in {' or '.join(sorted(ROOT_ROLES))}")
    return username


def _check_child(req: GrantRequest, delegator_agent_id: str | None, chain: Chain, now: float) -> str:
    if chain.problem in ("cycle", "too_deep"):
        raise GrantRefused("chain_too_deep", f"parent chain is invalid ({chain.problem})")
    if chain.problem or not chain.grants:
        raise GrantRefused("parent_unusable", f"parent grant {req.parent_grant_id} or an ancestor is missing")
    if len(chain.grants) > MAX_PARENT_DEPTH:
        raise GrantRefused("chain_too_deep", f"a child here would have more than {MAX_PARENT_DEPTH} ancestors")
    parent = chain.grants[0]
    for g in chain.grants:
        if not _usable(g, now):
            raise GrantRefused("parent_unusable", f"grant {g.grant_id} in the chain is {g.status} or expired")
    if not delegator_agent_id or delegator_agent_id != parent.agent_id:
        raise GrantRefused("not_parent_holder", "only the agent holding the parent grant may delegate from it")
    if req.workflow_id != parent.workflow_id:
        raise GrantRefused("workflow_mismatch", "child must use the parent's workflow_id")
    if req.human_id is not None and req.human_id != parent.human_id:
        raise GrantRefused("human_mismatch", "child must keep the parent's human_id")
    for name, asked in (("tools", req.tools), ("delegable_tools", req.delegable_tools)):
        extra = asked - parent.delegable_tools
        if extra:
            raise GrantRefused("tools_not_delegable",
                               f"{name} not in parent's delegable_tools: {', '.join(sorted(extra))}")
    if req.repository != parent.resources.get("repository"):
        raise GrantRefused("resource_escalation", "child must use the parent's repository")
    if parent.expires_at is not None and req.expires_at > parent.expires_at:
        raise GrantRefused("expiry_escalation", "child may not outlive its parent")
    return parent.human_id  # type: ignore[return-value]


# --- service ------------------------------------------------------------------

def load_chain(store: GrantWriter, parent_grant_id: str) -> Chain:
    """Walk from the parent up. Reads at most MAX_PARENT_DEPTH + 1 grants. Store errors propagate."""
    grants: list[Grant] = []
    seen: set[str] = set()
    gid: str | None = parent_grant_id
    while gid:
        if gid in seen:
            return Chain(tuple(grants), "cycle")
        if len(grants) > MAX_PARENT_DEPTH:
            return Chain(tuple(grants), "too_deep")
        seen.add(gid)
        g = store.get(gid)
        if g is None:
            return Chain(tuple(grants), "missing")
        grants.append(g)
        gid = g.parent_grant_id
    return Chain(tuple(grants))


def create_grant(req: GrantRequest, *, store: GrantWriter, human: HumanPrincipal | None = None,
                 delegator_agent_id: str | None = None, agents: frozenset[str] | None = None,
                 now: float | None = None) -> Grant:
    """Root grant (pass `human`) or child grant (pass `parent_grant_id` and `delegator_agent_id`).

    The caller must have verified `human` or `delegator_agent_id`; this function trusts them.
    """
    now = time.time() if now is None else now
    agents = registered_agents() if agents is None else agents
    chain = load_chain(store, req.parent_grant_id) if req.parent_grant_id else Chain()
    human_id = check_request(req, human=human, delegator_agent_id=delegator_agent_id,
                             chain=chain, agents=agents, now=now)
    grant = Grant(
        grant_id=new_grant_id(),
        agent_id=req.agent_id,
        workflow_id=req.workflow_id,
        human_id=human_id,
        status="active",
        expires_at=req.expires_at,
        parent_grant_id=req.parent_grant_id,
        tools=req.tools,
        delegable_tools=req.delegable_tools,
        resources={"repository": req.repository},
    )
    created_by = human.username if req.parent_grant_id is None else delegator_agent_id  # type: ignore[union-attr]
    store.put_new(grant, created_at=int(now), created_by=created_by)  # type: ignore[arg-type]
    return grant


def revoke_grant(grant_id: str, *, store: GrantWriter, human: HumanPrincipal | None,
                 now: float | None = None) -> RevokeResult:
    """Set status=revoked. Unknown grant raises GrantNotFound; already revoked is a no-op that says so."""
    now = time.time() if now is None else now
    username = getattr(human, "username", None)
    if not isinstance(username, str) or not username:
        raise GrantRefused("no_human", "revoking needs a signed-in human; run agentledger login")
    if not isinstance(grant_id, str) or not grant_id:
        raise GrantNotFound(str(grant_id))
    g = store.get(grant_id)
    if g is None:
        raise GrantNotFound(grant_id)
    if REVOKE_ANY_ROLE not in set(getattr(human, "groups", None) or ()) and g.human_id != username:
        raise GrantRefused("revoke_not_permitted",
                           f"{username} may revoke only their own grants unless in {REVOKE_ANY_ROLE}")
    if g.status == "revoked":
        return _already(grant_id)
    if store.mark_revoked(grant_id, revoked_at=int(now), revoked_by=username):
        return RevokeResult(grant_id, False,
                            f"revoked {grant_id}; the gateway denies it and its children at their next call")
    # The conditional update failed: re-read to say why instead of guessing.
    after = store.get(grant_id)
    if after is None:
        raise GrantNotFound(grant_id)
    if after.status == "revoked":
        return _already(grant_id)
    raise GrantStoreError(f"revoke of {grant_id} was refused by the store but the grant is {after.status}")


def _signed_in(human: HumanPrincipal | None, action: str) -> str:
    username = getattr(human, "username", None)
    if not isinstance(username, str) or not username:
        raise GrantRefused("no_human", f"{action} needs a signed-in human; run agentledger login")
    return username


def _sees_all(human: HumanPrincipal) -> bool:
    # GUESS: same rule as revoke: security-admin sees every grant, others only their own.
    return REVOKE_ANY_ROLE in set(getattr(human, "groups", None) or ())


def show_grant(grant_id: str, *, store: GrantReader, human: HumanPrincipal | None) -> Grant:
    """One grant by ID (consistent read). Another human's grant is refused unless security-admin."""
    username = _signed_in(human, "showing a grant")
    if not isinstance(grant_id, str) or not grant_id:
        raise GrantNotFound(str(grant_id))
    g = store.get(grant_id)
    if g is None:
        raise GrantNotFound(grant_id)
    if not _sees_all(human) and g.human_id != username:  # type: ignore[arg-type]
        raise GrantRefused("not_permitted", f"{grant_id} belongs to another human")
    return g


def list_grants(*, store: GrantReader, human: HumanPrincipal | None,
                workflow_id: str | None = None) -> list[Grant]:
    """Your grants (all grants for security-admin), optionally one workflow, sorted by expiry."""
    username = _signed_in(human, "listing grants")
    rows = store.by_workflow(workflow_id) if workflow_id else store.all()
    if not _sees_all(human):  # type: ignore[arg-type]
        rows = [g for g in rows if g.human_id == username]
    return sorted(rows, key=lambda g: (g.expires_at or 0, g.grant_id))


def _already(grant_id: str) -> RevokeResult:
    return RevokeResult(grant_id, True, f"{grant_id} was already revoked; nothing changed")
