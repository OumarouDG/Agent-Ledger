"""Offline tests for create_grant / revoke_grant: one pass and one refusal per delegation rule.

The store is an in-memory fake with the same conditional-write behaviour as DynamoGrantStore
(the DynamoDB calls themselves are covered in test_store.py). All names are fakes.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, replace

import pytest

from controlplane.grants.errors import GrantNotFound, GrantRefused
from controlplane.grants.service import (
    MAX_TTL_SECONDS, GrantRequest, create_grant, revoke_grant,
)
from gateway.authorization import MAX_PARENT_DEPTH, authorize
from gateway.grants import Grant, GrantStoreError

NOW = 1_800_000_000
HOUR = 3600
AGENTS = frozenset({"agent_lead", "agent_coder", "agent_tester"})


@dataclass(frozen=True)
class Human:
    username: str
    groups: tuple[str, ...]


ALICE = Human("alice", ("engineer",))
BOB = Human("bob", ("reviewer",))
DANA = Human("dana", ("security-admin",))
ERIN = Human("erin", ("engineer",))


class FakeStore:
    """Conditional writes like DynamoDB: put_new never overwrites, mark_revoked never creates."""

    def __init__(self):
        self.items: dict[str, dict] = {}
        self.writes = 0

    def get(self, grant_id):
        row = self.items.get(grant_id)
        return row["grant"] if row else None

    def put_new(self, grant, *, created_at, created_by):
        if grant.grant_id in self.items:
            raise GrantStoreError("exists")
        self.writes += 1
        self.items[grant.grant_id] = {"grant": grant, "created_at": created_at, "created_by": created_by}

    def mark_revoked(self, grant_id, *, revoked_at, revoked_by):
        row = self.items.get(grant_id)
        if row is None or row["grant"].status == "revoked":
            return False
        self.writes += 1
        row["grant"] = replace(row["grant"], status="revoked")
        row.update(revoked_at=revoked_at, revoked_by=revoked_by)
        return True

    def seed(self, grant: Grant) -> Grant:
        self.items[grant.grant_id] = {"grant": grant, "created_at": NOW, "created_by": "seed"}
        return grant


@pytest.fixture
def store():
    return FakeStore()


def root_req(**kw) -> GrantRequest:
    base = dict(agent_id="agent_lead", workflow_id="wf_t", tools=frozenset({"get_issue"}),
                delegable_tools=frozenset({"get_issue", "commit_file"}),
                expires_at=NOW + 2 * HOUR, repository="acme/demo")
    base.update(kw)
    return GrantRequest(**base)


def child_req(parent: Grant, **kw) -> GrantRequest:
    base = dict(agent_id="agent_coder", workflow_id=parent.workflow_id, tools=frozenset({"commit_file"}),
                expires_at=NOW + HOUR, repository="acme/demo", parent_grant_id=parent.grant_id)
    base.update(kw)
    return GrantRequest(**base)


def make_root(store, human=ALICE, **kw) -> Grant:
    return create_grant(root_req(**kw), store=store, human=human, agents=AGENTS, now=NOW)


def make_child(store, parent, delegator="agent_lead", **kw) -> Grant:
    return create_grant(child_req(parent, **kw), store=store, delegator_agent_id=delegator,
                        agents=AGENTS, now=NOW)


def refused(reason, fn, *a, **kw):
    with pytest.raises(GrantRefused) as e:
        fn(*a, **kw)
    assert e.value.reason == reason, e.value
    return e.value


def authz(store, grant, tool):
    return authorize(store, agent_id=grant.agent_id, grant_id=grant.grant_id,
                     workflow_id=grant.workflow_id, tool=tool, now=NOW)


# --- root grants ----------------------------------------------------------------

def test_root_grant_written_with_session_human(store):
    g = make_root(store)
    assert g.grant_id.startswith("gr_") and len(g.grant_id) == 3 + 16
    assert (g.human_id, g.status, g.parent_grant_id) == ("alice", "active", None)
    assert g.resources == {"repository": "acme/demo"}
    row = store.items[g.grant_id]
    assert row["grant"] == g and row["created_by"] == "alice" and row["created_at"] == NOW


def test_grant_ids_are_unique(store):
    assert len({make_root(store).grant_id for _ in range(50)}) == 50


def test_unknown_agent(store):
    refused("unknown_agent", make_root, store, agent_id="agent_nobody")
    assert store.writes == 0


@pytest.mark.parametrize("repo", ["", "acme", "acme/", "/demo", "acme/demo/extra", "acme demo/x",
                                  "https://github.com/acme/demo", None, "-acme/demo"])
def test_bad_repository(store, repo):
    refused("bad_repository", make_root, store, repository=repo)
    assert store.writes == 0


@pytest.mark.parametrize("repo", ["acme/demo", "Acme-Co/demo.repo_2", "a/b"])
def test_good_repository(store, repo):
    assert make_root(store, repository=repo).resources["repository"] == repo


@pytest.mark.parametrize("exp", [None, NOW, NOW - 1, NOW + MAX_TTL_SECONDS + 1,
                                 str(NOW + HOUR), True, float(NOW + HOUR)])
def test_bad_expiry(store, exp):
    refused("bad_expiry", make_root, store, expires_at=exp)
    assert store.writes == 0


def test_expiry_at_cap_allowed(store):
    assert make_root(store, expires_at=NOW + MAX_TTL_SECONDS).expires_at == NOW + MAX_TTL_SECONDS


def test_no_tools(store):
    refused("no_tools", make_root, store, tools=frozenset())
    assert store.writes == 0


@pytest.mark.parametrize("kw", [{"workflow_id": ""}, {"workflow_id": None},
                                {"tools": ["get_issue"]}, {"tools": frozenset({""})},
                                {"delegable_tools": {"get_issue"}}])
def test_bad_request_shape(store, kw):
    refused("bad_request", make_root, store, **kw)


@pytest.mark.parametrize("human", [None, Human("", ("engineer",))])
def test_root_needs_human(store, human):
    refused("no_human", make_root, store, human=human)
    assert store.writes == 0


def test_root_human_id_from_request_must_match_session(store):
    # Bad case: a request naming another human would make a grant on their behalf.
    refused("human_mismatch", make_root, store, human_id="mallory")
    assert store.writes == 0
    assert make_root(store, human_id="alice").human_id == "alice"


@pytest.mark.parametrize("human", [BOB, Human("carl", ())])
def test_role_not_permitted(store, human):
    refused("role_not_permitted", make_root, store, human=human)
    assert store.writes == 0


def test_security_admin_may_create_root(store):
    assert make_root(store, human=DANA).human_id == "dana"


# --- child grants ---------------------------------------------------------------

def test_child_inherits_human_and_is_attributed_to_delegator(store):
    root = make_root(store)
    child = make_child(store, root)
    assert (child.human_id, child.parent_grant_id, child.agent_id) == ("alice", root.grant_id, "agent_coder")
    assert store.items[child.grant_id]["created_by"] == "agent_lead"
    assert authz(store, child, "commit_file").allowed


@pytest.mark.parametrize("change", [
    {"status": "revoked"}, {"status": "quarantined"}, {"expires_at": NOW},
])
def test_parent_unusable(store, change):
    root = make_root(store)
    store.items[root.grant_id]["grant"] = replace(root, **change)
    refused("parent_unusable", make_child, store, root)
    assert store.writes == 1


def test_parent_missing(store):
    root = make_root(store)
    refused("parent_unusable", make_child, store, replace(root, grant_id="gr_ghost"))


def test_revoked_grandparent_makes_parent_unusable(store):
    root = make_root(store)
    mid = make_child(store, root, agent_id="agent_tester", tools=frozenset({"get_issue"}),
                     delegable_tools=frozenset({"commit_file"}))
    store.items[root.grant_id]["grant"] = replace(root, status="revoked")
    refused("parent_unusable", make_child, store, mid, delegator="agent_tester")


@pytest.mark.parametrize("delegator", ["agent_coder", None, ""])
def test_not_parent_holder(store, delegator):
    root = make_root(store)
    refused("not_parent_holder", make_child, store, root, delegator=delegator)
    assert store.writes == 1


def test_workflow_mismatch(store):
    root = make_root(store)
    refused("workflow_mismatch", make_child, store, root, workflow_id="wf_other")


def test_child_human_mismatch(store):
    root = make_root(store)
    refused("human_mismatch", make_child, store, root, human_id="mallory")
    assert make_child(store, root, human_id="alice").human_id == "alice"


@pytest.mark.parametrize("kw, named", [
    ({"tools": frozenset({"commit_file", "create_branch"})}, "create_branch"),
    ({"delegable_tools": frozenset({"llm_converse"})}, "llm_converse"),
])
def test_child_tools_outside_parent_delegable_refused_not_trimmed(store, kw, named):
    # Bad case: the child is written with the extra tool silently dropped.
    root = make_root(store)
    e = refused("tools_not_delegable", make_child, store, root, **kw)
    assert named in e.detail
    assert store.writes == 1  # only the root; no trimmed child was written


def test_parent_tools_not_delegable_unless_listed(store):
    # get_issue is in the root's tools AND delegable_tools; a root with tools only cannot hand it on.
    root = make_root(store, delegable_tools=frozenset())
    refused("tools_not_delegable", make_child, store, root, tools=frozenset({"get_issue"}))


def test_resource_escalation(store):
    root = make_root(store)
    refused("resource_escalation", make_child, store, root, repository="acme/other")


def test_expiry_escalation(store):
    root = make_root(store)
    refused("expiry_escalation", make_child, store, root, expires_at=root.expires_at + 1)
    assert make_child(store, root, expires_at=root.expires_at).expires_at == root.expires_at


def chain_of(store, n_ancestors: int) -> Grant:
    """Seed a straight chain; return the deepest grant, which has n_ancestors - 1 ancestors."""
    parent_id = None
    for i in range(n_ancestors):
        g = store.seed(Grant(grant_id=f"gr_c{i}", agent_id="agent_lead", workflow_id="wf_t",
                             human_id="alice", expires_at=NOW + 2 * HOUR, parent_grant_id=parent_id,
                             tools=frozenset({"get_issue"}), delegable_tools=frozenset({"commit_file"}),
                             resources={"repository": "acme/demo"}))
        parent_id = g.grant_id
    return g


def test_chain_depth_at_limit_allowed(store):
    leaf = chain_of(store, MAX_PARENT_DEPTH)  # child would have exactly MAX_PARENT_DEPTH ancestors
    child = make_child(store, leaf)
    assert authz(store, child, "commit_file").allowed


@pytest.mark.parametrize("n", [MAX_PARENT_DEPTH + 1, MAX_PARENT_DEPTH + 5])
def test_chain_too_deep(store, n):
    leaf = chain_of(store, n)
    refused("chain_too_deep", make_child, store, leaf)
    # The gateway would deny such a child anyway; refusing at create says why.


def test_chain_cycle(store):
    a = store.seed(Grant(grant_id="gr_a", agent_id="agent_lead", workflow_id="wf_t", human_id="alice",
                         expires_at=NOW + HOUR, parent_grant_id="gr_b",
                         delegable_tools=frozenset({"commit_file"}), resources={"repository": "acme/demo"}))
    store.seed(replace(a, grant_id="gr_b", parent_grant_id="gr_a"))
    refused("chain_too_deep", make_child, store, a)


def test_store_error_during_create_propagates_and_is_not_a_refusal():
    class Broken(FakeStore):
        def get(self, grant_id):
            raise GrantStoreError("unavailable")
    with pytest.raises(GrantStoreError):
        make_child(Broken(), make_root(FakeStore()))


# --- delegable_tools never means execute ------------------------------------------

def test_delegable_tools_alone_never_allow(store):
    root = make_root(store)  # tools={get_issue}, delegable={get_issue, commit_file}
    assert authz(store, root, "get_issue").allowed
    d = authz(store, root, "commit_file")
    assert not d.allowed and d.reason == "tool_not_permitted"
    child = make_child(store, root, tools=frozenset({"get_issue"}), delegable_tools=frozenset({"commit_file"}))
    d = authz(store, child, "commit_file")
    assert not d.allowed and d.reason == "tool_not_permitted"


# --- revoke -----------------------------------------------------------------------

def test_revoke_own_grant(store):
    g = make_root(store)
    r = revoke_grant(g.grant_id, store=store, human=ALICE, now=NOW + 5)
    assert not r.already_revoked and "revoked" in r.message
    row = store.items[g.grant_id]
    assert row["grant"].status == "revoked" and (row["revoked_by"], row["revoked_at"]) == ("alice", NOW + 5)
    assert authz(store, g, "get_issue").reason == "grant_revoked"


def test_revoke_twice_says_already_revoked(store):
    g = make_root(store)
    revoke_grant(g.grant_id, store=store, human=ALICE, now=NOW)
    writes = store.writes
    r = revoke_grant(g.grant_id, store=store, human=ALICE, now=NOW + 60)
    assert r.already_revoked and "already revoked" in r.message
    assert store.writes == writes and store.items[g.grant_id]["revoked_at"] == NOW  # untouched


@pytest.mark.parametrize("gid", ["gr_ghost", "gr_" + "x" * 16, ""])
def test_revoke_unknown_grant_is_an_error_not_success(store, gid):
    # Bad case: a mistyped ID reported as "revoked" while the real grant stays live.
    make_root(store)
    with pytest.raises(GrantNotFound):
        revoke_grant(gid, store=store, human=ALICE, now=NOW)
    assert store.writes == 1


def test_revoke_needs_human(store):
    g = make_root(store)
    refused("no_human", revoke_grant, g.grant_id, store=store, human=None)
    assert store.get(g.grant_id).status == "active"


def test_revoke_others_grant_refused(store):
    g = make_root(store)
    refused("revoke_not_permitted", revoke_grant, g.grant_id, store=store, human=ERIN, now=NOW)
    assert store.get(g.grant_id).status == "active"


def test_security_admin_revokes_any(store):
    g = make_root(store)
    assert not revoke_grant(g.grant_id, store=store, human=DANA, now=NOW).already_revoked
    assert store.items[g.grant_id]["revoked_by"] == "dana"


def test_revoked_root_kills_child_without_writing_child(store):
    root = make_root(store)
    child = make_child(store, root)
    revoke_grant(root.grant_id, store=store, human=ALICE, now=NOW)
    assert store.get(child.grant_id).status == "active"  # nothing cascaded by writing
    assert authz(store, child, "commit_file").reason == "parent_grant_revoked"


def test_revoke_race_already_revoked_elsewhere(store):
    g = make_root(store)

    class Racing(FakeStore):
        def mark_revoked(self, grant_id, **kw):
            self.items[grant_id]["grant"] = replace(self.items[grant_id]["grant"], status="revoked")
            return False
    racing = Racing()
    racing.items = store.items
    assert revoke_grant(g.grant_id, store=racing, human=ALICE, now=NOW).already_revoked


def test_revoke_race_grant_vanished(store):
    g = make_root(store)

    class Vanishing(FakeStore):
        def mark_revoked(self, grant_id, **kw):
            self.items.pop(grant_id)
            return False
    v = Vanishing()
    v.items = store.items
    with pytest.raises(GrantNotFound):
        revoke_grant(g.grant_id, store=v, human=ALICE, now=NOW)


def test_revoke_condition_failed_but_still_active_is_a_store_error(store):
    g = make_root(store)

    class Lying(FakeStore):
        def mark_revoked(self, grant_id, **kw):
            return False
    lying = Lying()
    lying.items = store.items
    with pytest.raises(GrantStoreError):
        revoke_grant(g.grant_id, store=lying, human=ALICE, now=NOW)


def test_request_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        root_req().tools = frozenset()  # type: ignore[misc]
