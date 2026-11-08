"""Rogue probe against an in-process gateway with the Sentinel on (threshold 3, as on EC2).

`agentledger probe` runs with a real CLI session check (locally signed ID token, in-memory
keyring) and an in-memory grant store. A live workflow is started first, as `agentledger run`
would, without running its agents.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import re

import pytest
import requests
from click.testing import CliRunner

from agentledger import commands, grant_commands, run_commands, storage
from agentledger.main import cli
from agentledger.storage import TokenStore
from controlplane.grants import service
from controlplane.runtime import probe as rogue
from controlplane.runtime import workflow as wfm
from tests.unit.cli.conftest import MemoryKeyring
from tests.unit.cli.test_session import CFG, id_token, save, verifier
from tests.unit.runtime.conftest import AGENTS, ALICE, MemStore, fake_mint, opener, serve_gateway
from tests.unit.runtime.test_agents import FakeGitHub, FakeLLM

WF = "wf_probe01"


@contextlib.contextmanager
def gateway_env(tmp_path, threshold=3):
    store, github = MemStore(), FakeGitHub()
    with serve_gateway(store, tmp_path, github_app=github, llm_client=FakeLLM(),
                       sentinel_threshold=threshold) as url:
        flow = wfm.start_workflow(ALICE, 1, "acme/demo", store=store, agents=AGENTS, out=None,
                                  open_agent=opener(url), workflow_id=WF)
        yield {"store": store, "github": github, "url": url, "flow": flow,
               "audit": tmp_path / "audit.jsonl"}


@pytest.fixture
def gw(tmp_path):
    with gateway_env(tmp_path) as e:
        yield e


def probe(e, **kw):
    lines: list[str] = []
    kw.setdefault("open_agent", opener(e["url"]))
    result = rogue.run_probe(ALICE, WF, store=e["store"], agents=AGENTS, out=lines.append, **kw)
    return result, lines


def decisions(e):
    rows = [json.loads(x) for x in e["audit"].read_text().splitlines()]
    return [(r["agent_id"], r["tool"], r["grant_id"], r["decision"], r["reason"])
            for r in rows if r.get("event") == "decision"]


def rogue_grants(e):
    return [g for g in e["store"].items.values() if g.agent_id == "agent_rogue"]


# --- every attack gets its reason ----------------------------------------------------

def test_every_attack_is_refused_with_its_reason(gw):
    result, lines = probe(gw)
    got = [(a.name.split(" ")[0], a.got, a.ok) for a in result.attempts]
    assert got == [("baseline:", "ALLOWED", True), ("1", "grant_agent_mismatch", True),
                   ("2", "missing_grant", True), ("3", "not_parent_holder", True),
                   ("4", "tool_not_permitted", True)]
    assert result.ok and result.lead_grant_id == gw["flow"].root.grant_id
    assert result.coder_grant_id == gw["flow"].coder.grant_id


def test_attacks_reach_the_gateway_as_rogue_and_delegation_makes_no_call(gw):
    result, _ = probe(gw)
    rid, cid = result.rogue_grant_id, gw["flow"].coder.grant_id
    assert decisions(gw)[-4:] == [
        ("agent_rogue", "get_issue", rid, "allow", "allowed"),
        ("agent_rogue", "get_issue", cid, "deny", "grant_agent_mismatch"),
        ("agent_rogue", "get_issue", None, "deny", "missing_grant"),
        ("agent_rogue", "create_branch", rid, "deny", "tool_not_permitted"),
    ]


def test_rogue_gets_its_own_narrow_root_grant_and_it_is_revoked_after(gw):
    result, lines = probe(gw)
    (g,) = rogue_grants(gw)
    assert g.grant_id == result.rogue_grant_id and g.parent_grant_id is None
    assert g.tools == {"get_issue"} and g.delegable_tools == frozenset()
    assert g.resources["branch_prefix"] == f"agentledger/{WF}/rogue/"
    assert g.human_id == "alice" and g.status == "revoked" and result.revoked
    assert f"revoked agent_rogue's grant {g.grant_id}" in lines[-1]
    assert len(gw["store"].items) == 4  # the run's three, plus Rogue's; no child was written


def test_probe_leaves_the_workflow_grants_active(gw):
    probe(gw)
    assert all(gw["store"].get(g.grant_id).status == "active" for g in gw["flow"].grants)


# --- Sentinel ------------------------------------------------------------------------

def test_until_locked_shows_an_allowed_tool_denied(gw):
    result, lines = probe(gw, until_locked=True)
    tail = [(a.got, a.ok) for a in result.attempts[-3:]]
    assert tail == [("tool_not_permitted", True), ("tool_not_permitted", True),
                    ("grant_quarantined", True)]
    assert result.ok


def test_lock_does_not_carry_over_between_probes(gw):
    first, _ = probe(gw, until_locked=True)
    second, _ = probe(gw, until_locked=True)
    assert first.ok and second.ok and first.rogue_grant_id != second.rogue_grant_id
    assert second.attempts[0].got == "ALLOWED"  # the new grant starts unlocked


def test_until_locked_without_a_sentinel_reports_allowed(tmp_path):
    with gateway_env(tmp_path, threshold=0) as e:
        result, lines = probe(e, until_locked=True)
    last = result.attempts[-1]
    assert (last.got, last.allowed, last.ok) == ("ALLOWED", True, False)
    assert not result.ok and "ALLOWED (unexpected)" in lines[-2]


# --- a probe that finds a hole fails ----------------------------------------------------

def test_coder_grant_held_by_another_agent_is_not_a_target(gw):
    # A tree whose Coder grant names agent_rogue as its holder has no Coder to attack.
    cid = gw["flow"].coder.grant_id
    gw["store"].items[cid] = dataclasses.replace(gw["store"].items[cid], agent_id="agent_rogue")
    with pytest.raises(rogue.ProbeError):  # and find_targets no longer sees an agent_coder child
        probe(gw)


def test_stolen_grant_accepted_is_reported_allowed(gw, monkeypatch):
    real = rogue._gateway_attempt

    def coder_grant_works(name, expected, s, tool, **args):
        if expected == "grant_agent_mismatch":  # the gateway let Rogue use Coder's grant
            return rogue.Attempt(name, expected, rogue.ALLOWED, True)
        return real(name, expected, s, tool, **args)
    monkeypatch.setattr(rogue, "_gateway_attempt", coder_grant_works)
    result, lines = probe(gw)
    assert not result.ok
    assert any("ALLOWED (unexpected)" in x and "Coder's grant" in x for x in lines)


def test_delegator_taken_from_a_string_is_caught(gw, monkeypatch):
    """Silent failure 4: if delegation trusted a name instead of the verified token, Rogue
    could write a child of Lead's grant. The probe must report it and revoke the child."""
    def trusting_delegate(session, parent, req, *, store, agents=None, now=None):
        return service.create_grant(req, store=store, delegator_agent_id=parent.agent_id,
                                    agents=agents, now=now)
    monkeypatch.setattr(rogue, "delegate", trusting_delegate)
    result, lines = probe(gw)
    attack3 = result.attempts[3]
    assert attack3.allowed and not attack3.ok and "written, revoked" in attack3.got
    children = [g for g in rogue_grants(gw) if g.parent_grant_id]
    assert len(children) == 1 and children[0].status == "revoked"


def test_wrong_reason_fails_the_probe(gw, monkeypatch):
    # If Rogue's grant had create_branch, "main" would be refused for the branch, not the tool.
    monkeypatch.setattr(rogue, "ROGUE_TOOLS", frozenset({"get_issue", "create_branch"}))
    result, lines = probe(gw)
    a4 = result.attempts[4]
    assert (a4.got, a4.ok) == ("branch_not_permitted", False)
    assert "WRONG REASON (expected tool_not_permitted)" in lines[-2]


def test_baseline_failure_fails_the_probe(gw):
    result, lines = probe(gw, issue=99)  # the fake GitHub has no issue 99
    assert not result.attempts[0].ok and not result.ok
    assert "BASELINE FAILED" in lines[2]


# --- cannot run --------------------------------------------------------------------

def test_no_active_workflow_is_a_probe_error(gw):
    service.revoke_grant(gw["flow"].root.grant_id, store=gw["store"], human=ALICE)
    with pytest.raises(rogue.ProbeError, match="no active Lead and Coder grants"):
        probe(gw)
    assert rogue_grants(gw) == []


def test_unreachable_gateway_still_revokes_rogues_grant(gw, dead_url):
    with pytest.raises(rogue.GatewayUnavailable):
        probe(gw, open_agent=opener(dead_url))
    (g,) = rogue_grants(gw)
    assert g.status == "revoked"


def test_newest_active_run_is_targeted(gw):
    newer = wfm.start_workflow(ALICE, 1, "acme/demo", store=gw["store"], agents=AGENTS, out=None,
                               open_agent=opener(gw["url"]), workflow_id=WF, now=None)
    store = gw["store"]
    for g in newer.grants:  # make the second run expire later than the first
        store.items[g.grant_id] = dataclasses.replace(g, expires_at=g.expires_at + 60)
    lead, coder = rogue.find_targets(store, ALICE, WF)
    assert (lead.grant_id, coder.grant_id) == (newer.root.grant_id, newer.coder.grant_id)


# --- the CLI ------------------------------------------------------------------------

@pytest.fixture
def cli_env(gw, monkeypatch):
    backend = MemoryKeyring()
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: backend)
    tokens = TokenStore(CFG["user_pool_id"])
    minted: list[str] = []
    base = fake_mint()

    def mint(agent_id):
        t = base(agent_id)
        minted.append(t.access_token)
        return t
    monkeypatch.setattr(commands, "_context", lambda: (CFG, tokens, verifier()))
    monkeypatch.setattr(grant_commands, "_store", lambda: gw["store"])
    monkeypatch.setattr(service, "registered_agents", lambda: AGENTS)
    monkeypatch.setattr(run_commands, "_open_agent", lambda: opener(gw["url"], mint=mint))

    def no_http(*a, **k):
        raise AssertionError("unexpected HTTP call")
    monkeypatch.setattr(requests, "post", no_http)
    return {**gw, "tokens": tokens, "minted": minted}


def sign_in(e):
    save(e["tokens"], id_token(), refresh=None)


def cli_probe(*args):
    return CliRunner().invoke(cli, ["probe", *args])


def test_cli_all_refused_exits_0(cli_env):
    sign_in(cli_env)
    res = cli_probe("--workflow", WF)
    assert res.exit_code == 0, res.output
    assert "4/4 refused with the expected reason; baseline ok" in res.output
    assert res.output.count(" OK") == 5


def test_cli_until_locked_exits_0(cli_env):
    sign_in(cli_env)
    res = cli_probe("--workflow", WF, "--until-locked")
    assert res.exit_code == 0, res.output
    assert "grant_quarantined" in res.output and "7/7 refused" in res.output


def test_cli_allowed_attack_exits_1(cli_env, monkeypatch):
    sign_in(cli_env)
    monkeypatch.setattr(rogue, "delegate", lambda s, parent, req, **kw: service.create_grant(
        req, store=kw["store"], delegator_agent_id=parent.agent_id, agents=kw.get("agents")))
    res = cli_probe("--workflow", WF)
    assert res.exit_code == 1, res.output
    assert "ALLOWED (unexpected)" in res.output and "3/4 refused" in res.output


def test_cli_unreachable_exits_2(cli_env, monkeypatch, dead_url):
    sign_in(cli_env)
    monkeypatch.setattr(run_commands, "_open_agent", lambda: opener(dead_url))
    res = cli_probe("--workflow", WF)
    assert res.exit_code == 2 and "can't reach the gateway" in res.output
    assert all(g.status == "revoked" for g in rogue_grants(cli_env))


def test_cli_no_live_workflow_exits_1(cli_env):
    sign_in(cli_env)
    res = cli_probe("--workflow", "wf_nothing")
    assert res.exit_code == 1 and "no active Lead and Coder grants in wf_nothing" in res.output


def test_cli_signed_out_exits_1_and_writes_nothing(cli_env):
    res = cli_probe("--workflow", WF)
    assert res.exit_code == 1 and "agentledger login" in res.output
    assert rogue_grants(cli_env) == []


@pytest.mark.parametrize("wf", ["wf_001", "bad id"])
def test_cli_bad_workflow_is_a_usage_error(cli_env, wf):
    sign_in(cli_env)
    res = cli_probe("--workflow", wf)
    assert res.exit_code == 2 and rogue_grants(cli_env) == []


def test_cli_output_never_contains_a_token(cli_env):
    sign_in(cli_env)
    res = cli_probe("--workflow", WF, "--until-locked")
    assert res.exit_code == 0 and len(cli_env["minted"]) == 3
    for tok in cli_env["minted"]:
        assert tok not in res.output
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.", res.output)
