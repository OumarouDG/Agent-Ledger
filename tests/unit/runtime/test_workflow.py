"""start_workflow: grant shapes, delegator from Lead's verified token, cleanup on failure.

Offline: an in-memory grant store, local RSA tokens, and an in-process gateway for the
checks that the tree behaves as intended at call time.
"""

from __future__ import annotations

import dataclasses
import re
import time
from dataclasses import dataclass

import pytest

from controlplane.grants.errors import GrantRefused
from controlplane.grants.service import GrantRequest, revoke_grant
from controlplane.runtime import workflow as wfm
from controlplane.runtime.gateway_client import AgentSession, Denied, IdentityMismatch, ToolFailed
from tests.unit.runtime.conftest import CLIENT_IDS, FakeJwksVerifier, fake_mint, serve_gateway

AGENTS = frozenset({"agent_lead", "agent_coder", "agent_tester", "agent_rogue"})
REPO = "acme/demo"
NOW = time.time()


@dataclass(frozen=True)
class Human:
    username: str
    groups: tuple[str, ...] = ("engineer",)


ALICE = Human("alice")


class MemStore:
    """GrantWriter in memory. Records who created each grant."""

    def __init__(self):
        self.items: dict = {}
        self.created_by: dict[str, str] = {}

    def get(self, grant_id):
        return self.items.get(grant_id)

    def put_new(self, grant, *, created_at, created_by):
        assert grant.grant_id not in self.items
        self.items[grant.grant_id] = grant
        self.created_by[grant.grant_id] = created_by

    def mark_revoked(self, grant_id, *, revoked_at, revoked_by):
        g = self.items.get(grant_id)
        if g is None or g.status == "revoked":
            return False
        self.items[grant_id] = dataclasses.replace(g, status="revoked")
        return True


def opener(url="http://127.0.0.1:9/mcp", mint=None):
    """open_agent for tests: real AgentSession with a local key and fake mint."""
    def open_agent(agent_id, grant_id, workflow_id):
        return AgentSession(agent_id, grant_id, workflow_id, url, mint=mint or fake_mint(),
                            verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS)
    return open_agent


def start(store, human=ALICE, out=None, **kw):
    kw.setdefault("open_agent", opener())
    return wfm.start_workflow(human, 1, REPO, store=store, agents=AGENTS, now=NOW, out=out, **kw)


# --- grant shapes -------------------------------------------------------------------------

def test_tree_has_the_agreed_shapes():
    store = MemStore()
    flow = start(store, workflow_id="wf_unit01")
    root, coder, tester = flow.grants
    assert flow.workflow_id == "wf_unit01" and flow.human_id == "alice"

    assert (root.agent_id, root.parent_grant_id, root.human_id) == ("agent_lead", None, "alice")
    assert root.tools == {"get_issue", "llm_converse"}
    assert root.delegable_tools == {"get_issue", "create_branch", "commit_file",
                                    "open_pull_request", "llm_converse", "get_test_result",
                                    "get_pull_request"}
    assert root.resources == {"repository": REPO, "branch_prefix": "agentledger/wf_unit01/",
                              "models": ["us.amazon.nova-lite-v1:0"], "max_tokens": 300}

    assert (coder.agent_id, coder.parent_grant_id) == ("agent_coder", root.grant_id)
    assert coder.tools == {"get_issue", "create_branch", "commit_file", "open_pull_request",
                           "llm_converse"}
    assert coder.delegable_tools == frozenset()
    assert coder.resources == {"repository": REPO, "branch_prefix": "agentledger/wf_unit01/coder/",
                               "models": ["us.amazon.nova-lite-v1:0"], "max_tokens": 300}

    assert (tester.agent_id, tester.parent_grant_id) == ("agent_tester", root.grant_id)
    assert tester.tools == {"get_test_result", "get_pull_request"}
    assert tester.delegable_tools == frozenset()
    assert tester.resources == {"repository": REPO, "branch_prefix": "agentledger/wf_unit01/"}

    for g in flow.grants:
        assert (g.workflow_id, g.human_id, g.status) == ("wf_unit01", "alice", "active")
        assert g.expires_at == int(NOW) + 60 * 60
    assert set(store.items) == {root.grant_id, coder.grant_id, tester.grant_id}


def test_generated_workflow_ids_are_fresh_and_prefixes_follow_them():
    a, b = start(MemStore()), start(MemStore())
    assert re.fullmatch(r"wf_[0-9a-f]{8}", a.workflow_id) and a.workflow_id != b.workflow_id
    assert a.root.resources["branch_prefix"] == f"agentledger/{a.workflow_id}/"
    assert a.coder.resources["branch_prefix"] == f"agentledger/{a.workflow_id}/coder/"


# --- delegator comes from the verified token ----------------------------------------------

def test_children_are_created_by_leads_verified_identity():
    store = MemStore()
    flow = start(store)
    assert flow.lead.agent_id == "agent_lead" and flow.lead.grant_id == flow.root.grant_id
    assert store.created_by[flow.root.grant_id] == "alice"
    assert store.created_by[flow.coder.grant_id] == "agent_lead"
    assert store.created_by[flow.tester.grant_id] == "agent_lead"


def test_lead_token_that_verifies_as_another_agent_stops_the_run_and_revokes_root():
    store = MemStore()
    swapped = opener(mint=fake_mint({"agent_lead": "fakecoderclient"}))
    with pytest.raises(IdentityMismatch):
        start(store, open_agent=swapped)
    assert len(store.items) == 1, "no child may be written"
    (root,) = store.items.values()
    assert root.status == "revoked"


def _child_req(root, agent="agent_coder", tools=frozenset({"commit_file"})):
    return GrantRequest(agent_id=agent, workflow_id=root.workflow_id, tools=tools,
                        expires_at=root.expires_at, repository=REPO,
                        parent_grant_id=root.grant_id)


def test_delegate_from_a_non_holder_session_is_refused_not_parent_holder():
    store = MemStore()
    flow = start(store)
    coder = opener()("agent_coder", flow.coder.grant_id, flow.workflow_id)
    before = dict(store.items)
    with pytest.raises(GrantRefused) as e:
        wfm.delegate(coder, flow.root, _child_req(flow.root, "agent_rogue"), store=store,
                     agents=AGENTS, now=NOW)
    assert e.value.reason == "not_parent_holder"
    assert store.items == before


def test_delegate_refuses_a_plain_agent_name():
    store = MemStore()
    flow = start(store)
    before = dict(store.items)
    with pytest.raises(TypeError):
        wfm.delegate("agent_lead", flow.root, _child_req(flow.root), store=store, agents=AGENTS)
    assert store.items == before


def test_delegate_refuses_a_request_for_another_parent():
    store = MemStore()
    flow = start(store)
    req = dataclasses.replace(_child_req(flow.root), parent_grant_id=flow.coder.grant_id)
    with pytest.raises(wfm.WorkflowError):
        wfm.delegate(flow.lead, flow.root, req, store=store, agents=AGENTS)


# --- refused before anything is written ---------------------------------------------------

@pytest.mark.parametrize("human", [None, Human(""), object()])
def test_signed_out_is_refused_and_writes_nothing(human):
    store = MemStore()
    with pytest.raises(GrantRefused) as e:
        start(store, human=human)
    assert e.value.reason == "no_human" and store.items == {}


def test_human_without_a_root_role_is_refused():
    store = MemStore()
    with pytest.raises(GrantRefused) as e:
        start(store, human=Human("bob", ("viewer",)))
    assert e.value.reason == "role_not_permitted" and store.items == {}


@pytest.mark.parametrize("wf", ["wf_001", "", "wf_", "wf 1", "wf_../x", "WF_1", "x_1",
                                "wf_" + "a" * 41, 5])
def test_bad_or_reserved_workflow_ids_are_refused(wf):
    store = MemStore()
    with pytest.raises(wfm.WorkflowError):
        wfm.start_workflow(ALICE, 1, REPO, store=store, agents=AGENTS, out=None,
                           open_agent=opener(), workflow_id=wf)
    assert store.items == {}


@pytest.mark.parametrize("issue", [0, -1, True, "1", 1.0, None])
def test_bad_issue_numbers_are_refused(issue):
    store = MemStore()
    with pytest.raises(wfm.WorkflowError):
        wfm.start_workflow(ALICE, issue, REPO, store=store, agents=AGENTS, out=None,
                           open_agent=opener())
    assert store.items == {}


def test_failure_after_root_revokes_every_grant_written():
    store = MemStore()
    original = store.put_new

    def put_new(grant, **kw):  # the third write (Tester's grant) fails
        if grant.agent_id == "agent_tester":
            raise RuntimeError("store went away")
        original(grant, **kw)
    store.put_new = put_new

    with pytest.raises(RuntimeError):
        start(store)
    assert {g.agent_id for g in store.items.values()} == {"agent_lead", "agent_coder"}
    assert all(g.status == "revoked" for g in store.items.values())


# --- printout and revoke -----------------------------------------------------------------

def test_tree_printout_lists_every_grant_and_no_token():
    lines: list[str] = []
    flow = start(MemStore(), out=lines.append)
    (text,) = lines
    for g in flow.grants:
        assert g.grant_id in text and g.agent_id in text
    assert flow.workflow_id in text and "alice" in text
    assert flow.lead._AgentSession__token not in text
    assert "─" not in text and "└" not in text  # ASCII only for Windows consoles


def test_revoke_workflow_revokes_all_three():
    store = MemStore()
    flow = start(store)
    results = wfm.revoke_workflow(flow, store=store, human=ALICE)
    assert [r.already_revoked for r in results] == [False, False, False]
    assert all(store.get(g.grant_id).status == "revoked" for g in flow.grants)


# --- the tree at call time, through an in-process gateway --------------------------------

@pytest.fixture(scope="module")
def live_tree(tmp_path_factory):
    store = MemStore()
    with serve_gateway(store, tmp_path_factory.mktemp("rt-wf")) as url:
        flow = wfm.start_workflow(ALICE, 42, REPO, store=store, agents=AGENTS, out=None,
                                  open_agent=opener(url))
        open_agent = opener(url)
        yield {"flow": flow, "store": store,
               "coder": open_agent("agent_coder", flow.coder.grant_id, flow.workflow_id),
               "tester": open_agent("agent_tester", flow.tester.grant_id, flow.workflow_id)}


def test_lead_may_read_the_issue(live_tree):
    assert live_tree["flow"].lead.call("get_issue", issue_number=42)["number"] == 42


def test_lead_cannot_execute_what_it_may_only_delegate(live_tree):
    flow = live_tree["flow"]
    with pytest.raises(Denied) as e:
        flow.lead.call("create_branch", branch=f"agentledger/{flow.workflow_id}/coder/x")
    assert e.value.reason == "tool_not_permitted"


def test_coder_branch_inside_its_prefix_passes_the_guard(live_tree):
    flow = live_tree["flow"]
    # The test gateway has no GitHub App, so an allowed write fails at GitHub, not at the guard.
    with pytest.raises(ToolFailed, match="github is not configured"):
        live_tree["coder"].call("create_branch", branch=f"agentledger/{flow.workflow_id}/coder/issue-42")


def test_coder_branch_outside_its_prefix_is_denied(live_tree):
    flow = live_tree["flow"]
    with pytest.raises(Denied) as e:
        live_tree["coder"].call("create_branch", branch=f"agentledger/{flow.workflow_id}/other")
    assert e.value.reason == "branch_not_permitted"


def test_tester_cannot_read_issues(live_tree):
    with pytest.raises(Denied) as e:
        live_tree["tester"].call("get_issue", issue_number=42)
    assert e.value.reason == "tool_not_permitted"


def test_revoking_root_denies_the_children_next_call(live_tree):
    flow, store = live_tree["flow"], live_tree["store"]
    with pytest.raises(ToolFailed):  # allowed before the revoke (fails only at GitHub)
        live_tree["tester"].call("get_pull_request", number=1)
    revoke_grant(flow.root.grant_id, store=store, human=ALICE)
    calls = [("coder", "get_issue", {"issue_number": 42}),
             ("tester", "get_pull_request", {"number": 1})]
    for agent, tool, args in calls:
        with pytest.raises(Denied) as e:
            live_tree[agent].call(tool, **args)
        assert e.value.reason == "parent_grant_revoked", agent
    assert store.get(flow.coder.grant_id).status == "active"  # killed by the parent walk only
