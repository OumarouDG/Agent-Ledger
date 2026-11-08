"""`agentledger run` offline: real CLI session check (locally signed ID token, in-memory
keyring), in-memory grants, in-process gateway with fake GitHub and fake model."""

from __future__ import annotations

import json
import re

import pytest
import requests
from click.testing import CliRunner

from agentledger import commands, grant_commands, run_commands, storage
from agentledger.main import cli
from agentledger.storage import TokenStore
from controlplane.grants import service
from controlplane.runtime import agents as ag
from controlplane.runtime.agents import CallTiming
from gateway.github import GitHubError
from tests.unit.cli.conftest import MemoryKeyring
from tests.unit.cli.test_session import CFG, id_token, save, verifier
from tests.unit.runtime.conftest import AGENTS, ALICE, MemStore, fake_mint, opener, serve_gateway
from tests.unit.runtime.test_agents import FakeGitHub, FakeLLM, not_found, run_found

CALLS_ON_HAPPY_PATH = 10  # 2 Lead, 4 Coder, 3 test-result checks, 1 get_pull_request


@pytest.fixture
def env(monkeypatch, tmp_path):
    backend = MemoryKeyring()
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: backend)
    tokens = TokenStore(CFG["user_pool_id"])
    store, github, llm = MemStore(), FakeGitHub(), FakeLLM()
    minted: list[str] = []
    base_mint = fake_mint()

    def mint(agent_id):
        tok = base_mint(agent_id)
        minted.append(tok.access_token)
        return tok

    monkeypatch.setattr(commands, "_context", lambda: (CFG, tokens, verifier()))
    monkeypatch.setattr(grant_commands, "_store", lambda: store)
    monkeypatch.setattr(service, "registered_agents", lambda: AGENTS)
    monkeypatch.setattr(run_commands, "_sleep", lambda s: None)

    def no_http(*a, **k):
        raise AssertionError("unexpected HTTP call")
    monkeypatch.setattr(requests, "post", no_http)

    with serve_gateway(store, tmp_path, github_app=github, llm_client=llm) as url:
        monkeypatch.setattr(run_commands, "_open_agent", lambda: opener(url, mint=mint))
        yield {"tokens": tokens, "store": store, "github": github, "llm": llm, "url": url,
               "minted": minted, "audit": tmp_path / "audit.jsonl"}


def sign_in(env, groups=("engineer",)):
    save(env["tokens"], id_token(**{"cognito:groups": list(groups)}), refresh=None)


def run(*args, input=None):
    return CliRunner().invoke(cli, ["run", *args], input=input)


def decisions(env):
    if not env["audit"].exists():
        return []
    rows = [json.loads(x) for x in env["audit"].read_text().splitlines()]
    return [(r["agent_id"], r["tool"], r["decision"], r["reason"]) for r in rows
            if r.get("event") == "decision"]


def root_id(env):
    (root,) = [g for g in env["store"].items.values() if g.parent_grant_id is None]
    return root.grant_id


# --- exit codes ----------------------------------------------------------------------

def test_tests_passed_exits_0_with_summary(env):
    sign_in(env)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 0, res.output
    out = res.output
    assert "https://github.com/acme/demo/pull/7" in out
    assert "tests    passed" in out
    assert run_commands.HONEST_LINE in out and "exit 0" in out
    assert re.search(r"agent_coder\s+create_branch\s+gr_\S+\s+\d+ ms\s+allowed\s+branch agentledger/", out)
    assert re.search(r"latency: 10 calls, median \d+ ms, p95 \d+ ms", out)
    for g in env["store"].items.values():
        assert g.grant_id in out


@pytest.mark.parametrize("runs, verdict", [
    (lambda sha, n: run_found(sha, conclusion="failure"), "FAILED: failure"),
    (lambda sha, n: not_found(sha), "no test run found after 18 checks"),
    (lambda sha, n: run_found(sha, status="in_progress", conclusion=None), "not finished (in_progress)"),
])
def test_tests_not_passed_exits_3(env, runs, verdict):
    sign_in(env)
    env["github"].runs = runs
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 3, res.output
    assert f"tests    {verdict}" in res.output and "tests    passed" not in res.output


def test_denial_exits_1_and_says_who_what_why(env, monkeypatch):
    sign_in(env)
    real_create = service.create_grant

    def no_branch_for_coder(req, **kw):  # Coder's grant is written without create_branch
        if req.agent_id == "agent_coder":
            req = type(req)(**{**req.__dict__, "tools": req.tools - {"create_branch"}})
        return real_create(req, **kw)
    monkeypatch.setattr("controlplane.runtime.workflow.create_grant", no_branch_for_coder)
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 1, res.output
    assert "agent_coder was denied create_branch on grant gr_" in res.output
    assert "tool_not_permitted" in res.output and env["github"].branches == {}
    assert "exit 1" in res.output


def test_tool_failure_exits_1(env):
    sign_in(env)
    def exists(*a):
        raise GitHubError("branch already exists")
    env["github"].create_branch = exists
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 1 and "branch already exists" in res.output


def test_unreachable_gateway_exits_2(env, monkeypatch, dead_url):
    sign_in(env)
    monkeypatch.setattr(run_commands, "_open_agent", lambda: opener(dead_url))
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 2, res.output
    assert "can't reach the gateway" in res.output and "exit 2" in res.output


def test_signed_out_exits_1_and_writes_nothing(env):
    res = run("--issue", "1")
    assert res.exit_code == 1 and "agentledger login" in res.output
    assert env["store"].items == {} and decisions(env) == []


def test_human_without_root_role_exits_1(env):
    sign_in(env, groups=("viewer",))
    res = run("--issue", "1", "--repo", "acme/demo")
    assert res.exit_code == 1 and "role_not_permitted" in res.output
    assert env["store"].items == {}


@pytest.mark.parametrize("args", [["--issue", "1", "--workflow", "wf_001"],
                                  ["--issue", "0"], ["--issue", "1", "--workflow", "bad id"]])
def test_bad_arguments_are_usage_errors_before_anything_is_written(env, args):
    sign_in(env)
    res = run(*args)
    assert res.exit_code == 2 and "Usage" in res.output
    assert env["store"].items == {}


def test_workflow_flag_is_used_and_wf_002_reruns_get_new_branches(env):
    sign_in(env)
    outs = []
    for _ in range(2):
        env["github"].test_calls = 0
        res = run("--issue", "1", "--repo", "acme/demo", "--workflow", "wf_002")
        assert res.exit_code == 0, res.output
        outs.append(res.output)
    branches = [re.search(r"branch   (\S+)", o).group(1) for o in outs]
    assert branches[0] != branches[1]
    assert all(b.startswith("agentledger/wf_002/coder/issue-1-") for b in branches)


# --- --step --------------------------------------------------------------------------

def test_step_waits_before_every_call(env, monkeypatch):
    sign_in(env)
    seen_before_each_prompt: list[int] = []

    def wait(prompt):
        seen_before_each_prompt.append(len(decisions(env)))
        return ""
    monkeypatch.setattr(run_commands, "_wait", wait)
    res = run("--issue", "1", "--repo", "acme/demo", "--step")
    assert res.exit_code == 0, res.output
    # One prompt per call, and the gateway had seen exactly i calls at prompt i.
    assert seen_before_each_prompt == list(range(CALLS_ON_HAPPY_PATH))
    assert res.output.count("[step] next:") == CALLS_ON_HAPPY_PATH
    assert f"agentledger grant revoke {root_id(env)}" in res.output


def test_step_revoke_between_steps_denies_the_next_call(env, monkeypatch):
    sign_in(env)
    prompts = {"n": 0}

    def wait(prompt):  # before Coder's create_branch, a second terminal revokes the root
        prompts["n"] += 1
        if prompts["n"] == 4:
            service.revoke_grant(root_id(env), store=env["store"], human=ALICE)
        return ""
    monkeypatch.setattr(run_commands, "_wait", wait)
    res = run("--issue", "1", "--repo", "acme/demo", "--step")
    assert res.exit_code == 1, res.output
    assert decisions(env)[-1] == ("agent_coder", "create_branch", "deny", "parent_grant_revoked")
    assert "agent_coder was denied create_branch" in res.output
    assert "DENIED: parent_grant_revoked" in res.output
    assert env["github"].branches == {}


def test_step_with_closed_input_stops_before_sending(env):
    sign_in(env)
    res = run("--issue", "1", "--repo", "acme/demo", "--step", input="\n\n")  # then EOF
    assert res.exit_code == 1, res.output
    assert "stopped at --step before agent_coder sent llm_converse" in res.output
    assert [d[1] for d in decisions(env)] == ["get_issue", "llm_converse"]


def test_step_ctrl_c_stops_before_sending(env, monkeypatch):
    sign_in(env)

    def wait(prompt):
        raise KeyboardInterrupt
    monkeypatch.setattr(run_commands, "_wait", wait)
    res = run("--issue", "1", "--repo", "acme/demo", "--step")
    assert res.exit_code == 1 and decisions(env) == []
    assert "stopped at --step before agent_lead sent get_issue" in res.output


# --- no tokens in output -------------------------------------------------------------

@pytest.mark.parametrize("extra", [[], ["--step"]])
def test_output_never_contains_a_token(env, monkeypatch, extra):
    sign_in(env)
    monkeypatch.setattr(run_commands, "_wait", lambda p: "")
    res = run("--issue", "1", "--repo", "acme/demo", *extra)
    assert res.exit_code == 0, res.output
    assert len(env["minted"]) == 3  # Lead, Coder and Tester each minted their own
    for tok in env["minted"]:
        assert tok not in res.output
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.", res.output)


# --- latency summary -----------------------------------------------------------------

def test_latency_summary_numbers():
    t = [CallTiming("a", "get_issue", ms, "allowed") for ms in (100, 200, 300, 400)] + \
        [CallTiming("a", "llm_converse", 1000, "allowed")]
    lines = ag.latency_summary(t)
    assert lines[0] == "latency: 5 calls, median 300 ms, p95 1000 ms, min 100 ms, max 1000 ms"
    assert lines[1].split() == ["get_issue", "n=4", "median", "250", "ms", "max", "400", "ms"]
    assert ag.latency_summary([]) == ["latency: no gateway calls"]


def test_describe_args_never_shows_prompts_or_file_bodies():
    assert ag.describe_args("llm_converse", {"messages": [{"role": "user", "content": "SECRET PLAN"}]}) \
        == "ask the model (11 chars of prompt)"
    s = ag.describe_args("commit_file", {"branch": "b", "path": "p.py", "content": "BODY", "message": "m"})
    assert "BODY" not in s and "4 bytes" in s
