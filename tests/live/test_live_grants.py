"""Live grant checks against the real DynamoDB table. Run with: pytest -q --live

Needs `python infra/grants_setup.py` to have run. Each test uses its own workflow ID
(`wf_live_<hex>`) and a fake human `livetest-<hex>` in group `engineer`; the grant service
trusts the caller to have verified the human, so no browser sign-in is needed.

Every grant a test creates is registered with the `ledger` fixture, which revokes it at
teardown even when the test fails, then re-reads it to confirm. Grants are never deleted
(the gateway's parent walk needs them), so revoked rows stay in the table.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

import boto3
import pytest

from controlplane.auth.config import load_config
from controlplane.grants.errors import GrantNotFound, GrantRefused
from controlplane.grants.service import GrantRequest, create_grant, registered_agents, revoke_grant
from controlplane.grants.store import TABLE_NAME, DynamoGrantStore
from gateway.authorization import authorize
from gateway.grants import Grant

pytestmark = pytest.mark.live

REPO = "acme/livetest"
TTL = 30 * 60
DENY_POLL_LIMIT_S = 10.0


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


class Ledger:
    """Creates grants for one test and remembers them so teardown can revoke every one."""

    def __init__(self, store: DynamoGrantStore):
        self.store = store
        tag = secrets.token_hex(4)
        self.human = Human(f"livetest-{tag}", ("engineer",))
        self.workflow_id = f"wf_live_{tag}"
        self.created: list[str] = []
        self.agents = registered_agents()

    def root(self, **kw) -> Grant:
        base = dict(agent_id="agent_lead", workflow_id=self.workflow_id,
                    tools=frozenset({"get_issue"}),
                    delegable_tools=frozenset({"get_issue", "commit_file"}),
                    expires_at=int(time.time()) + TTL, repository=REPO)
        base.update(kw)
        g = create_grant(GrantRequest(**base), store=self.store, human=self.human, agents=self.agents)
        self.created.append(g.grant_id)
        return g

    def child(self, parent: Grant, delegator: str = "agent_lead", **kw) -> Grant:
        base = dict(agent_id="agent_coder", workflow_id=parent.workflow_id,
                    tools=frozenset({"commit_file"}), expires_at=int(time.time()) + TTL - 60,
                    repository=REPO, parent_grant_id=parent.grant_id)
        base.update(kw)
        g = create_grant(GrantRequest(**base), store=self.store, delegator_agent_id=delegator,
                         agents=self.agents)
        self.created.append(g.grant_id)
        return g

    def revoke(self, grant_id: str):
        return revoke_grant(grant_id, store=self.store, human=self.human)

    def cleanup(self) -> list[str]:
        """Revoke everything created, newest first. Returns grant IDs that are not revoked after."""
        left = []
        for gid in reversed(self.created):
            try:
                self.revoke(gid)
                g = self.store.get(gid)
                if g is None or g.status != "revoked":
                    left.append(f"{gid} ({'missing' if g is None else g.status})")
            except Exception as e:  # noqa: BLE001 - keep revoking the rest, report every one left
                left.append(f"{gid} ({type(e).__name__}: {e})")
        return left


@pytest.fixture
def ledger(store):
    led = Ledger(store)
    yield led
    left = led.cleanup()
    if left:
        pytest.fail(f"WARNING: grants not revoked at teardown, revoke by hand in {TABLE_NAME}: "
                    + ", ".join(left), pytrace=False)


def decide(store, grant: Grant, tool: str = "get_issue"):
    return authorize(store, agent_id=grant.agent_id, grant_id=grant.grant_id,
                     workflow_id=grant.workflow_id, tool=tool)


# --- tests ------------------------------------------------------------------------

def test_root_grant_allows_get_issue(store, ledger):
    g = ledger.root()
    d = decide(store, g)
    assert d.allowed and d.reason == "allowed"
    assert d.grant.human_id == ledger.human.username and d.grant.resources == {"repository": REPO}
    assert decide(store, g, "commit_file").reason == "tool_not_permitted"  # delegable only


def test_revoke_denies_next_authorize_and_time_it(store, ledger, capsys):
    g = ledger.root()
    assert decide(store, g).allowed

    t0 = time.perf_counter()
    result = ledger.revoke(g.grant_id)
    t_revoked = time.perf_counter()
    assert not result.already_revoked

    attempts, reason = 0, None
    while time.perf_counter() - t_revoked < DENY_POLL_LIMIT_S:
        attempts += 1
        reason = decide(store, g).reason
        if reason == "grant_revoked":
            break
    t_denied = time.perf_counter()

    revoke_ms = (t_revoked - t0) * 1000
    to_deny_ms = (t_denied - t_revoked) * 1000
    with capsys.disabled():
        print(f"\n[revoke-to-deny] revoke_grant call {revoke_ms:.0f} ms; "
              f"revoke returned -> first grant_revoked denial {to_deny_ms:.0f} ms; "
              f"authorize attempts {attempts}; total {revoke_ms + to_deny_ms:.0f} ms")
    assert reason == "grant_revoked"
    assert attempts == 1, "a strongly consistent read should deny on the first call after revoke"
    assert ledger.revoke(g.grant_id).already_revoked


def test_revoked_root_denies_child(store, ledger):
    root = ledger.root()
    child = ledger.child(root)
    assert decide(store, child, "commit_file").allowed
    ledger.revoke(root.grant_id)
    assert decide(store, child, "commit_file").reason == "parent_grant_revoked"
    assert store.get(child.grant_id).status == "active"  # nothing cascaded by writing


def test_child_non_delegable_tool_refused_at_create(store, ledger):
    root = ledger.root()
    with pytest.raises(GrantRefused) as e:
        ledger.child(root, tools=frozenset({"commit_file", "create_branch"}))
    assert e.value.reason == "tools_not_delegable" and "create_branch" in e.value.detail
    assert ledger.created == [root.grant_id]  # no trimmed child was written


def test_child_from_non_holder_refused(store, ledger):
    # The root is held by agent_lead; agent_rogue tries to delegate from it.
    root = ledger.root()
    with pytest.raises(GrantRefused) as e:
        ledger.child(root, delegator="agent_rogue")
    assert e.value.reason == "not_parent_holder"
    assert ledger.created == [root.grant_id]


def test_revoke_unknown_id_errors_and_creates_no_row(store, ledger):
    # DynamoDB UpdateItem upserts without a condition; a mistyped ID must not become a junk row.
    ghost = f"gr_live_missing_{secrets.token_hex(6)}"
    with pytest.raises(GrantNotFound):
        ledger.revoke(ghost)
    assert store.mark_revoked(ghost, revoked_at=int(time.time()), revoked_by=ledger.human.username) is False
    assert store.get(ghost) is None


def test_missing_table_is_store_unavailable_not_unknown_grant(ledger):
    ghost = DynamoGrantStore(f"agentledger-grants-missing-{secrets.token_hex(4)}")
    d = authorize(ghost, agent_id="agent_lead", grant_id="gr_doesnotmatter",
                  workflow_id=ledger.workflow_id, tool="get_issue")
    assert not d.allowed and d.reason == "grant_store_unavailable"
