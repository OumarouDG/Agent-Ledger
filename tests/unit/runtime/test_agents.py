"""Lead, Coder and Tester through an in-process gateway with a fake GitHub App and fake model.

The fake GitHub keeps branches, files and pull requests in memory and serves scripted test
runs. The fake model answers by system prompt. Sleeps are recorded, not slept.
"""

from __future__ import annotations

import dataclasses
import json
import re
import secrets

import pytest

from controlplane.runtime import agents as ag
from controlplane.runtime import workflow as wfm
from controlplane.runtime.agents import CoderOutputRejected, RunStopped, CiOutcome
from gateway.github import GitHubError
from tests.unit.runtime.conftest import (
    AGENTS, ALICE, MemStore, fake_mint, opener, serve_gateway)

REPO = "acme/demo"
GOOD_FILE = 'def greet(name):\n    return f"Hello, {name}!"\n'
GOOD_REPLY = f"PATH: greeting.py\n```python\n{GOOD_FILE}```\n"


def run_found(sha, status="completed", conclusion="success"):
    return {"repository": REPO, "sha": sha, "found": True, "run_id": 99, "run_attempt": 1,
            "workflow": "tests", "status": status, "conclusion": conclusion,
            "passed": status == "completed" and conclusion == "success",
            "branch": "x", "url": "https://github.com/acme/demo/actions/runs/99"}


def not_found(sha):
    return {"repository": REPO, "sha": sha, "found": False, "status": "none",
            "conclusion": None, "passed": False}


class FakeGitHub:
    """Duck-typed gateway.github.GitHubApp. `runs` maps a call number to a test-run reply."""

    def __init__(self):
        self.branches: dict[str, str] = {}
        self.files: dict[tuple[str, str], str] = {}
        self.prs: dict[int, dict] = {}
        self.runs = lambda sha, n: run_found(sha) if n >= 3 else not_found(sha)
        self.test_calls = 0
        self.on_pr = None

    def get_issue(self, repo, number):
        if number != 1:
            raise GitHubError("issue not found")
        return {"repository": repo, "number": 1, "title": "Add a greeting function",
                "state": "open", "body": "Add greet(name) that returns a greeting.",
                "labels": [], "url": f"https://github.com/{repo}/issues/1"}

    def create_branch(self, repo, branch, base):
        if branch in self.branches:
            raise GitHubError("branch already exists")
        self.branches[branch] = "b" * 40
        return {"repository": repo, "branch": branch, "base": base, "sha": "b" * 40}

    def commit_file(self, repo, branch, path, content, message):
        sha = secrets.token_hex(20)
        self.files[(branch, path)] = content
        self.branches[branch] = sha
        return {"repository": repo, "branch": branch, "path": path, "commit_sha": sha, "url": ""}

    def open_pull_request(self, repo, head, base, title, body):
        n = len(self.prs) + 7
        self.prs[n] = {"head": head, "head_sha": self.branches[head], "title": title, "body": body}
        if self.on_pr:
            self.on_pr()
        return {"repository": repo, "number": n, "url": f"https://github.com/{repo}/pull/{n}",
                "head_branch": head, "head_sha": self.branches[head], "base": base,
                "state": "open", "merged": False}

    def get_test_result(self, repo, sha, branch_prefix):
        self.test_calls += 1
        return self.runs(sha, self.test_calls)

    def get_pull_request(self, repo, number, branch_prefix):
        pr = self.prs.get(number)
        if pr is None or not pr["head"].startswith(branch_prefix):
            raise GitHubError("pull request not found")
        return {"repository": repo, "number": number, "title": pr["title"], "state": "open",
                "merged": False, "merged_by": None, "merge_commit_sha": None,
                "head_branch": pr["head"], "head_sha": pr["head_sha"], "base": "main",
                "approved_by": [], "url": f"https://github.com/{repo}/pull/{number}"}


class FakeLLM:
    """Duck-typed gateway.llm.BedrockLLM. Records each call's system prompt and cap."""

    def __init__(self, coder_reply=GOOD_REPLY, coder_stop="end_turn"):
        self.coder_reply, self.coder_stop = coder_reply, coder_stop
        self.calls: list[dict] = []

    def converse(self, model, messages, system, max_tokens):
        self.calls.append({"model": model, "system": system, "max_tokens": max_tokens})
        if system == ag.CODER_SYSTEM:
            return {"model": model, "text": self.coder_reply, "stop_reason": self.coder_stop,
                    "input_tokens": 50, "output_tokens": 40}
        return {"model": model, "text": "1. Add greeting.py\n2. Open a PR", "stop_reason": "end_turn",
                "input_tokens": 30, "output_tokens": 12}


@pytest.fixture
def env(tmp_path):
    """A fresh gateway, store, GitHub and model per test, and a started workflow."""
    store, github, llm = MemStore(), FakeGitHub(), FakeLLM()
    with serve_gateway(store, tmp_path, github_app=github, llm_client=llm) as url:
        flow = wfm.start_workflow(ALICE, 1, REPO, store=store, agents=AGENTS, out=None,
                                  open_agent=opener(url))
        yield {"url": url, "store": store, "github": github, "llm": llm, "flow": flow,
               "audit": tmp_path / "audit.jsonl", "sleeps": []}


def go(env, **kw):
    lines: list[str] = []
    kw.setdefault("open_agent", opener(env["url"]))
    kw.setdefault("sleep", env["sleeps"].append)
    try:
        return ag.run_agents(env["flow"], out=lines.append, **kw), lines
    finally:
        env["lines"] = lines


def decisions(env):
    rows = [json.loads(x) for x in env["audit"].read_text().splitlines()]
    return [(r["agent_id"], r["tool"], r["decision"]) for r in rows if r.get("event") == "decision"]


# --- happy path ----------------------------------------------------------------------

def test_happy_path_opens_a_pr_and_reports_the_test_run(env):
    result, lines = go(env)
    flow, gh = env["flow"], env["github"]
    assert result.pr_number == 7 and result.pr_url.endswith("/pull/7")
    assert re.fullmatch(rf"agentledger/{flow.workflow_id}/coder/issue-1-[0-9a-f]{{6}}", result.branch)
    assert result.branch == flow.branch
    assert gh.files == {(flow.branch, "greeting.py"): GOOD_FILE}
    assert re.fullmatch(r"[0-9a-f]{40}", result.commit_sha)
    assert result.test == CiOutcome("passed", "success", "completed",
                                      "https://github.com/acme/demo/actions/runs/99", 3)
    assert env["sleeps"] == [10, 10, 10]
    assert "tests passed" in result.report and "PR #7 is open, not merged" in result.report
    assert "Scripted orchestration" in gh.prs[7]["body"]
    assert flow.coder.grant_id in gh.prs[7]["body"]


def test_each_call_runs_as_its_own_agent(env):
    go(env)
    assert decisions(env) == [
        ("agent_lead", "get_issue", "allow"),
        ("agent_lead", "llm_converse", "allow"),
        ("agent_coder", "llm_converse", "allow"),
        ("agent_coder", "create_branch", "allow"),
        ("agent_coder", "commit_file", "allow"),
        ("agent_coder", "open_pull_request", "allow"),
        ("agent_tester", "get_test_result", "allow"),
        ("agent_tester", "get_test_result", "allow"),
        ("agent_tester", "get_test_result", "allow"),
        ("agent_tester", "get_pull_request", "allow"),
    ]


def test_model_calls_use_the_granted_model_and_cap(env):
    go(env)
    assert [(c["model"], c["max_tokens"]) for c in env["llm"].calls] == \
        [(wfm.MODEL, 300), (wfm.MODEL, 300)]


def test_output_never_contains_a_token(env):
    result, lines = go(env)
    text = "\n".join(lines) + result.report
    for s in (env["flow"].lead,):
        assert s._AgentSession__token not in text
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.", text)


# --- denials stop the run ------------------------------------------------------------

def test_revoke_mid_run_stops_tester_with_the_reason(env):
    store, flow = env["store"], env["flow"]
    env["github"].on_pr = lambda: wfm.revoke_grant(flow.root.grant_id, store=store, human=ALICE)
    with pytest.raises(RunStopped) as e:
        go(env)
    assert (e.value.exit_code, e.value.agent, e.value.tool, e.value.reason) == \
        (1, "agent_tester", "get_test_result", "parent_grant_revoked")
    assert "agent_tester was denied get_test_result" in str(e.value)
    assert env["lines"][-1].endswith("DENIED: parent_grant_revoked")
    assert env["github"].test_calls == 0


def test_coder_denied_create_branch_writes_nothing(env):
    store, flow = env["store"], env["flow"]
    g = store.items[flow.coder.grant_id]
    store.items[g.grant_id] = dataclasses.replace(g, tools=g.tools - {"create_branch"})
    with pytest.raises(RunStopped) as e:
        go(env)
    assert (e.value.exit_code, e.value.agent, e.value.reason) == (1, "agent_coder", "tool_not_permitted")
    assert env["github"].branches == {} and env["github"].files == {}
    assert ("agent_coder", "commit_file", "allow") not in decisions(env)


def test_unreachable_gateway_for_coder_exits_2(env, dead_url):
    lead_url = env["url"]

    def open_agent(agent_id, grant_id, workflow_id):
        return opener(dead_url if agent_id == "agent_coder" else lead_url)(agent_id, grant_id, workflow_id)
    with pytest.raises(RunStopped) as e:
        go(env, open_agent=open_agent)
    assert e.value.exit_code == 2 and e.value.agent == "agent_coder"


def test_tool_failure_stops_the_run(env):
    env["github"].branches[env["flow"].branch] = "x" * 40  # already exists
    with pytest.raises(RunStopped) as e:
        go(env)
    assert e.value.exit_code == 1 and "branch already exists" in str(e.value)
    assert env["github"].files == {}


def test_coder_token_for_another_agent_stops_the_run(env):
    swapped = opener(env["url"], mint=fake_mint({"agent_coder": "faketesterclient",
                                                  "agent_lead": "fakeleadclient"}))
    with pytest.raises(RunStopped) as e:
        go(env, open_agent=swapped)
    assert e.value.exit_code == 1 and "verifies as agent_tester" in str(e.value)
    assert env["github"].branches == {}


# --- the test result is never invented -----------------------------------------------

def test_found_false_until_timeout_is_no_test_run_not_passed(env):
    env["github"].runs = lambda sha, n: not_found(sha)
    result, _ = go(env)
    assert result.test.verdict == "no test run" and not result.test.passed
    assert result.test.attempts == 18 and env["github"].test_calls == 18
    assert sum(env["sleeps"]) == 180
    assert "no test run found" in result.report and "passed" not in result.report
    assert result.pr_number == 7  # the PR is still reported


def test_run_still_in_progress_at_timeout_is_not_finished(env):
    env["github"].runs = lambda sha, n: run_found(sha, status="in_progress", conclusion=None)
    result, _ = go(env, poll_timeout_s=30)
    assert result.test.verdict == "not finished" and not result.test.passed
    assert "not finished (in_progress)" in result.report


def test_failed_run_is_reported_failed(env):
    env["github"].runs = lambda sha, n: run_found(sha, conclusion="failure")
    result, _ = go(env)
    assert result.test.verdict == "failed" and result.test.conclusion == "failure"
    assert "tests FAILED" in result.report


@pytest.mark.parametrize("reply, verdict", [
    ({"found": True, "sha": "a" * 40, "status": "completed", "conclusion": "success", "passed": False}, "failed"),
    ({"found": True, "sha": "a" * 40, "status": "completed", "conclusion": None, "passed": True}, "failed"),
    ({"found": True, "sha": "b" * 40, "status": "completed", "conclusion": "success", "passed": True}, None),
    ({"found": False, "sha": "a" * 40}, None),
    ({"found": True, "sha": "a" * 40, "status": "queued"}, None),
    ("denied: x", None),
    (None, None),
])
def test_outcome_is_passed_only_for_completed_success_on_this_sha(reply, verdict):
    got = ag._outcome(reply, "a" * 40, 1)
    assert (got.verdict if got else None) == verdict


# --- model output is content only ----------------------------------------------------

def test_model_output_is_committed_verbatim_and_never_run(env, tmp_path):
    marker = tmp_path / "executed.txt"
    payload = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
    env["llm"].coder_reply = f"PATH: payload.py\n```python\n{payload}```"
    go(env)
    assert env["github"].files == {(env["flow"].branch, "payload.py"): payload}
    assert not marker.exists()


@pytest.mark.parametrize("reply, why", [
    ("no format at all", "format"),
    ("PATH: greeting.py\nno fence", "format"),
    ("```python\nx = 1\n```", "format"),
    ("PATH: greeting.py\n```\n   \n```", "empty"),
    ("PATH: .github/workflows/ci.yml\n```\non: push\n```", "hidden"),
    ("PATH: tests/test_greeting.py\n```\nassert True\n```", "test file"),
    ("PATH: test_greeting.py\n```\nassert True\n```", "test file"),
    ("PATH: conftest.py\n```\nx = 1\n```", "test file"),
    ("PATH: ../outside.py\n```\nx = 1\n```", "hidden"),
    ("PATH: src/../../outside.py\n```\nx = 1\n```", "hidden"),
    ("PATH: greet ing.py\n```\nx = 1\n```", "format"),
    ("PATH: greet$ing.py\n```\nx = 1\n```", "plain"),
    ("PATH: /etc/passwd\n```\nx\n```", "plain"),
    ("PATH: a//b.py\n```\nx\n```", "hidden"),
])
def test_unusable_model_output_stops_before_any_write(env, reply, why):
    env["llm"].coder_reply = reply
    with pytest.raises(RunStopped) as e:
        go(env)
    assert e.value.exit_code == 1 and why in str(e.value)
    assert env["github"].branches == {} and env["github"].files == {}


def test_reply_cut_off_at_max_tokens_is_refused(env):
    env["llm"].coder_stop = "max_tokens"
    with pytest.raises(RunStopped) as e:
        go(env)
    assert "cut off" in str(e.value) and env["github"].files == {}


def test_parse_accepts_backticked_path_and_adds_final_newline():
    path, content = ag.parse_coder_reply(
        {"text": "Here you go.\nPATH: `src/greeting.py`\n```py\nx = 1```", "stop_reason": "end_turn"})
    assert (path, content) == ("src/greeting.py", "x = 1\n")


@pytest.mark.parametrize("reply", [None, {}, {"text": 5}, "PATH: a.py"])
def test_parse_refuses_malformed_replies(reply):
    with pytest.raises(CoderOutputRejected):
        ag.parse_coder_reply(reply)


# --- rehearsals ----------------------------------------------------------------------

def test_wf_002_can_run_twice_with_separate_branches(env):
    store, url = env["store"], env["url"]
    branches = []
    for _ in range(2):
        flow = wfm.start_workflow(ALICE, 1, REPO, store=store, agents=AGENTS, out=None,
                                  open_agent=opener(url), workflow_id="wf_002")
        result = ag.run_agents(flow, open_agent=opener(url), out=None, sleep=lambda s: None)
        branches.append(result.branch)
        env["github"].test_calls = 0
    assert branches[0] != branches[1]
    assert all(b.startswith("agentledger/wf_002/coder/issue-1-") for b in branches)
    assert len(env["github"].prs) == 2
