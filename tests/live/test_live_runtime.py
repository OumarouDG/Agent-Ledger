"""Live runtime checks: real grants table, real agent tokens. Run with: pytest -q --live

Each test uses its own workflow ID `wf_live_<hex>` (never wf_001, Kiro's demo, or wf_002,
the runtime demo) and a fake human `livetest-<hex>` in group `engineer`, as in
test_live_grants.py: the grant service trusts the caller to have verified the human, so no
browser sign-in is needed. Agent tokens are real: each AgentSession mints through Cognito
and verifies against the pool's JWKS.

Gateway checks run only if the gateway URL accepts a TCP connection (the SSM tunnel); they
send only calls the gateway must deny, so nothing reaches GitHub, and each grant gets at
most one Sentinel violation (the lock needs three in a row).

Every grant is revoked at teardown, even when a test fails, then re-read to confirm.
"""

from __future__ import annotations

import secrets
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import boto3
import pytest

from controlplane.auth.config import load_config
from controlplane.grants.errors import GrantRefused
from controlplane.grants.service import GrantRequest, revoke_grant, show_grant
from controlplane.grants.store import TABLE_NAME, DynamoGrantStore
from controlplane.runtime import workflow as wfm
from controlplane.runtime.gateway_client import AgentSession, Denied, gateway_url

pytestmark = pytest.mark.live

REPO = "acme/livetest"
DEMO_WORKFLOWS = frozenset({"wf_001", "wf_002"})


@dataclass(frozen=True)
class Human:
    username: str
    groups: tuple[str, ...]


@pytest.fixture(scope="module")
def store() -> DynamoGrantStore:
    load_config.cache_clear()
    cfg = load_config()
    try:
        boto3.client("sts", region_name=cfg["region"]).get_caller_identity()
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"Can't reach AWS ({type(e).__name__}): paste fresh Workshop Studio credentials",
                    pytrace=False)
    return DynamoGrantStore(TABLE_NAME)


def live_workflow_id() -> str:
    wf = f"wf_live_{secrets.token_hex(4)}"
    assert wf.startswith("wf_live_") and wf not in DEMO_WORKFLOWS
    return wf


class Run:
    """One live workflow. Teardown revokes every grant it wrote."""

    def __init__(self, store: DynamoGrantStore):
        self.store = store
        self.human = Human(f"livetest-{secrets.token_hex(4)}", ("engineer",))
        self.workflow_id = live_workflow_id()
        self.flow: wfm.Workflow | None = None
        self.extra: list[str] = []

    def start(self) -> wfm.Workflow:
        self.flow = wfm.start_workflow(self.human, 1, REPO, store=self.store,
                                       workflow_id=self.workflow_id, out=print)
        return self.flow

    def cleanup(self) -> list[str]:
        ids = ([g.grant_id for g in self.flow.grants] if self.flow else []) + self.extra
        left = []
        for gid in ids:
            try:
                revoke_grant(gid, store=self.store, human=self.human)
                g = self.store.get(gid)
                if g is None or g.status != "revoked":
                    left.append(f"{gid} ({'missing' if g is None else g.status})")
            except Exception as e:  # noqa: BLE001 - keep revoking the rest
                left.append(f"{gid} ({type(e).__name__}: {e})")
        return left


@pytest.fixture
def run(store):
    r = Run(store)
    yield r
    left = r.cleanup()
    if left:
        pytest.fail(f"WARNING: grants not revoked at teardown, revoke by hand in {TABLE_NAME}: "
                    + ", ".join(left), pytrace=False)


def gateway_reachable() -> str | None:
    """None if the gateway URL accepts a TCP connection, else why not."""
    url = urlparse(gateway_url())
    try:
        with socket.create_connection((url.hostname, url.port or 80), timeout=2):
            return None
    except OSError as e:
        return f"gateway {gateway_url()} not reachable ({type(e).__name__}); open the tunnel"


# --- grant tree ---------------------------------------------------------------------

def test_tree_is_written_and_reads_back(run, store):
    flow = run.start()
    assert flow.workflow_id == run.workflow_id
    assert flow.lead.agent_id == "agent_lead"  # verified from a real Cognito token

    shown = {g.agent_id: show_grant(g.grant_id, store=store, human=run.human) for g in flow.grants}
    root, coder, tester = shown["agent_lead"], shown["agent_coder"], shown["agent_tester"]
    for g, wrote in zip((root, coder, tester), flow.grants):
        assert g == wrote, f"{g.grant_id} read back differently"
        assert (g.workflow_id, g.human_id, g.status) == (run.workflow_id, run.human.username, "active")

    assert root.parent_grant_id is None
    assert root.tools == wfm.LEAD_TOOLS and root.delegable_tools == wfm.LEAD_DELEGABLE
    assert root.resources["branch_prefix"] == f"agentledger/{run.workflow_id}/"
    assert root.resources["models"] == [wfm.MODEL] and int(root.resources["max_tokens"]) == 300

    assert coder.parent_grant_id == root.grant_id and coder.tools == wfm.CODER_TOOLS
    assert coder.delegable_tools == frozenset()
    assert coder.resources["branch_prefix"] == f"agentledger/{run.workflow_id}/coder/"

    assert tester.parent_grant_id == root.grant_id and tester.tools == wfm.TESTER_TOOLS
    assert tester.resources["branch_prefix"] == f"agentledger/{run.workflow_id}/"
    assert "models" not in tester.resources


def test_delegating_from_a_real_coder_token_is_refused(run, store):
    flow = run.start()
    coder = AgentSession("agent_coder", flow.coder.grant_id, flow.workflow_id)
    assert coder.agent_id == "agent_coder"
    req = GrantRequest(agent_id="agent_rogue", workflow_id=flow.workflow_id,
                       tools=frozenset({"get_issue"}), expires_at=flow.root.expires_at,
                       repository=REPO, parent_grant_id=flow.root.grant_id)
    with pytest.raises(GrantRefused) as e:
        grant = wfm.delegate(coder, flow.root, req, store=store)
        run.extra.append(grant.grant_id)  # only reached if the refusal failed; still revoked
    assert e.value.reason == "not_parent_holder"


# --- the tree at the real gateway (only through the tunnel) -------------------------------

def test_real_gateway_enforces_the_tree(run, store):
    why = gateway_reachable()
    if why:
        pytest.skip(why)
    flow = run.start()
    wf = flow.workflow_id

    with pytest.raises(Denied) as e:  # delegable only, never execute
        flow.lead.call("create_branch", branch=f"agentledger/{wf}/coder/x")
    assert e.value.reason == "tool_not_permitted"

    coder = AgentSession("agent_coder", flow.coder.grant_id, wf)
    with pytest.raises(Denied) as e:  # inside the root prefix but outside Coder's
        coder.call("create_branch", branch=f"agentledger/{wf}/other")
    assert e.value.reason == "branch_not_permitted"

    revoke_grant(flow.root.grant_id, store=store, human=run.human)
    tester = AgentSession("agent_tester", flow.tester.grant_id, wf)
    with pytest.raises(Denied) as e:
        tester.call("get_pull_request", number=1)
    assert e.value.reason == "parent_grant_revoked"
