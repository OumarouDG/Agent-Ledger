"""RT-6: guards for runtime failures that looked like success. Offline.

Each section names the bad case. These tests were written before the fixes and run against
the RT-5 code first, to show the bad case. Token values are generated here.
"""

from __future__ import annotations

import pytest

from agentledger import run_commands
from controlplane.grants import service
from controlplane.runtime import agents as ag
from controlplane.runtime import gateway_client as gc
from controlplane.runtime.gateway_client import AgentSession
from tests.unit.runtime.conftest import ALICE, CLIENT_IDS, FakeJwksVerifier, fake_mint, opener
from tests.unit.runtime.test_run_command import (  # noqa: F401 - the env fixture
    decisions, env, root_id, run, sign_in)

# Looked up this way so the file also runs against the code before the fix.
GatewayConfigError = getattr(gc, "GatewayConfigError", gc.GatewayError)

# --- 5. Grants stayed active after a run that did not finish -----------------------------
# Bad case: a denial, Ctrl+C, an unreachable gateway or a crash ended the run, and all three
# grants stayed active for up to 60 minutes with nobody watching. A normal run (tests passed
# or not) still leaves them active on purpose: the probe and a human reviewer use them.


def _states(env):
    return {g.agent_id: g.status for g in env["store"].items.values()}


def test_denied_run_revokes_the_root(env):
    sign_in(env)
    env["github"].on_pr = lambda: service.revoke_grant(  # someone revokes the Tester's grant
        next(g.grant_id for g in env["store"].items.values() if g.agent_id == "agent_tester"),
        store=env["store"], human=ALICE)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 1, res.output
    assert _states(env)["agent_lead"] == "revoked"
    assert f"revoked root {root_id(env)} because the run did not finish" in res.output
    assert "root revoked: the gateway denies all three grants" in res.output


def test_unreachable_gateway_revokes_the_root(env, monkeypatch, dead_url):
    sign_in(env)
    real = run_commands._open_agent()

    def open_agent(agent_id, grant_id, workflow_id):  # Lead works, Coder's gateway is gone
        if agent_id == "agent_coder":
            return opener(dead_url)(agent_id, grant_id, workflow_id)
        return real(agent_id, grant_id, workflow_id)
    monkeypatch.setattr(run_commands, "_open_agent", lambda: open_agent)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 2, res.output
    assert _states(env)["agent_lead"] == "revoked"


def test_ctrl_c_mid_run_revokes_the_root(env, monkeypatch):
    sign_in(env)
    # Ctrl+C while Coder's create_branch is in flight (not at a --step prompt).
    monkeypatch.setattr(ag.AgentSession, "call", _interrupt_on("create_branch"))
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 1, res.output
    assert _states(env)["agent_lead"] == "revoked"


def _interrupt_on(tool):
    real = AgentSession.call

    def call(self, name, **args):
        if name == tool:
            raise KeyboardInterrupt
        return real(self, name, **args)
    return call


def test_crash_mid_run_revokes_the_root_and_still_raises(env, monkeypatch):
    sign_in(env)

    def crash(*a, **k):
        raise RuntimeError("bug in the runtime")
    monkeypatch.setattr(ag, "tester_step", crash)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code != 0
    assert isinstance(res.exception, RuntimeError)  # not hidden
    assert _states(env)["agent_lead"] == "revoked"


def test_already_revoked_root_is_reported_not_an_error(env, monkeypatch):
    sign_in(env)
    prompts = {"n": 0}

    def wait(prompt):  # the --step demo: a second terminal revokes the root
        prompts["n"] += 1
        if prompts["n"] == 4:
            service.revoke_grant(root_id(env), store=env["store"], human=ALICE)
        return ""
    monkeypatch.setattr(run_commands, "_wait", wait)
    res = run("--issue", "1", "--repo", "acme/demo", "--step")
    assert res.exit_code == 1, res.output
    assert f"root {root_id(env)} was already revoked" in res.output


@pytest.mark.parametrize("runs_passed", [True, False])
def test_finished_runs_leave_grants_active(env, runs_passed):
    from tests.unit.runtime.test_agents import run_found
    sign_in(env)
    if not runs_passed:
        env["github"].runs = lambda sha, n: run_found(sha, conclusion="failure")
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == (0 if runs_passed else 3), res.output
    assert set(_states(env).values()) == {"active"}
    assert "because the run did not finish" not in res.output


# --- 7. Agent token sent in clear to any host ------------------------------------------
# Bad case: AGENTLEDGER_GATEWAY_URL=http://<any host>/mcp (a typo, a stale value, a hostile
# shell profile) made every agent send its bearer token over plain HTTP to that host. The
# tunnel is loopback; anything else must be https.


@pytest.mark.parametrize("url", [
    "http://example.com/mcp", "http://10.0.0.5:8000/mcp", "http://127.0.0.1.evil.test/mcp",
    "http://localhost.evil.test/mcp", "ftp://127.0.0.1/mcp", "127.0.0.1:18000/mcp",
    "https:///mcp",
])
def test_cleartext_or_odd_gateway_url_is_refused_before_minting(url):
    minted = []

    def mint(agent_id):
        minted.append(agent_id)
        return fake_mint()(agent_id)
    with pytest.raises(GatewayConfigError):
        AgentSession("agent_lead", "g", "wf_x", url, mint=mint, verifier=FakeJwksVerifier(),
                     client_ids=CLIENT_IDS)
    assert minted == []  # no token was even created


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:18000/mcp", "http://localhost:18001/mcp", "http://[::1]:18000/mcp",
    "https://gateway.example.com/mcp",
])
def test_loopback_http_and_any_https_are_allowed(url):
    s = AgentSession("agent_lead", "g", "wf_x", url, mint=fake_mint(),
                     verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS)
    assert s.url == url


def test_bad_gateway_url_from_env_is_refused(monkeypatch):
    monkeypatch.setenv("AGENTLEDGER_GATEWAY_URL", "http://gw.example.com/mcp")
    with pytest.raises(GatewayConfigError, match="plain http"):
        AgentSession("agent_lead", "g", "wf_x", mint=fake_mint(), verifier=FakeJwksVerifier(),
                     client_ids=CLIENT_IDS)


# --- 8. "Tests passed" when the PR head is not the tested commit -----------------------------
# Bad case: Tester read a passing run for the commit Coder made, but the PR's head had moved
# (someone pushed to the branch). The report noted it, yet the summary said "tests passed"
# and the run exited 0, so a script would treat an untested PR as tested.


def test_pr_head_not_the_tested_commit_is_not_passed(env, monkeypatch):
    sign_in(env)
    real = env["github"].get_pull_request

    def moved(repo, number, prefix):
        pr = real(repo, number, prefix)
        return {**pr, "head_sha": "f" * 40}
    monkeypatch.setattr(env["github"], "get_pull_request", moved)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 3, res.output
    assert "tests    passed" not in res.output
    assert "tests    PR head ffffffffffff is not the tested commit" in res.output
