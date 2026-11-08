"""get_test_result, open_pull_request, get_pull_request: adapter rules and grant-scoped access.
Offline: a fake GitHub that answers like the Actions and Pulls APIs."""

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import github
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make
from tests.gateway.test_github import PEM, Resp

SHA = "a" * 40
OTHER = "b" * 40
PREFIX = "agentledger/wf1/"


def run(sha=SHA, branch="agentledger/wf1/feat", status="completed", conclusion="success",
        rid=100, created="2026-11-08T01:00:00Z", attempt=1):
    return {"id": rid, "head_sha": sha, "head_branch": branch, "status": status,
            "conclusion": conclusion, "name": "tests", "run_attempt": attempt,
            "created_at": created, "html_url": f"https://x/runs/{rid}"}


PR = {"number": 7, "title": "Add greet", "state": "closed", "merged": True,
      "merged_by": {"login": "OumarouDG"}, "merge_commit_sha": "c" * 40,
      "head": {"ref": "agentledger/wf1/feat", "sha": SHA}, "base": {"ref": "main"},
      "html_url": "https://x/pull/7"}


class FakeCI:
    def __init__(self, runs=None, pr=None, reviews=None, runs_status=200, pr_status=200,
                 reviews_status=200, create_status=201):
        self.runs, self.pr, self.reviews = runs or [], pr or PR, reviews or []
        self.runs_status, self.pr_status = runs_status, pr_status
        self.reviews_status, self.create_status = reviews_status, create_status
        self.calls = []

    def post(self, url, headers, timeout, json=None):
        self.calls.append(("POST", url, json))
        if url.endswith("/access_tokens"):
            return Resp(201, {"token": "ghs_x"})
        return Resp(self.create_status, {"number": 9, "html_url": "https://x/pull/9",
                                         "head": {"sha": SHA}, "state": "open"})

    def get(self, url, headers, timeout, params=None):
        self.calls.append(("GET", url, params))
        if url.endswith("/actions/runs"):
            return Resp(self.runs_status, {"workflow_runs": self.runs})
        if url.endswith("/reviews"):
            return Resp(self.reviews_status, self.reviews)
        return Resp(self.pr_status, self.pr)


def gh(http):
    return github.GitHubApp("1", "2", lambda: PEM, http=http)


# --- get_test_result -----------------------------------------------------------------

def test_passing_run_for_the_exact_commit():
    out = gh(FakeCI(runs=[run()])).get_test_result("o/r", SHA, PREFIX)
    assert out["found"] and out["passed"] and out["conclusion"] == "success"
    assert out["run_id"] == 100 and out["sha"] == SHA


def test_failing_and_unfinished_runs_are_not_passed():
    failed = gh(FakeCI(runs=[run(conclusion="failure")])).get_test_result("o/r", SHA, PREFIX)
    assert failed["found"] and not failed["passed"] and failed["conclusion"] == "failure"
    running = gh(FakeCI(runs=[run(status="in_progress", conclusion=None)])).get_test_result(
        "o/r", SHA, PREFIX)
    assert running["found"] and not running["passed"] and running["status"] == "in_progress"


def test_runs_for_another_commit_or_branch_are_ignored():
    http = FakeCI(runs=[run(sha=OTHER), run(branch="main"), run(branch="other/x")])
    out = gh(http).get_test_result("o/r", SHA, PREFIX)
    assert out["found"] is False and out["passed"] is False and out["conclusion"] is None


def test_the_latest_run_wins():
    http = FakeCI(runs=[run(rid=1, conclusion="failure", created="2026-11-08T01:00:00Z"),
                        run(rid=2, conclusion="success", created="2026-11-08T02:00:00Z")])
    out = gh(http).get_test_result("o/r", SHA, PREFIX)
    assert out["run_id"] == 2 and out["passed"]


@pytest.mark.parametrize("sha", ["", "abc", "A" * 40, "a" * 39, "a" * 41, "g" * 40, None, 5])
def test_bad_sha_is_rejected_before_any_request(sha):
    http = FakeCI()
    with pytest.raises(github.GitHubError):
        gh(http).get_test_result("o/r", sha, PREFIX)
    assert not http.calls


def test_missing_actions_permission_is_a_clean_error():
    with pytest.raises(github.GitHubError, match="HTTP 403"):
        gh(FakeCI(runs_status=403)).get_test_result("o/r", SHA, PREFIX)


# --- open_pull_request ---------------------------------------------------------------

def test_open_pull_request_sends_the_right_payload():
    http = FakeCI()
    out = gh(http).open_pull_request("o/r", "agentledger/wf1/feat", "main", "Add greet", "body")
    post = [c for c in http.calls if c[0] == "POST" and c[1].endswith("/pulls")][0]
    assert post[2] == {"title": "Add greet", "head": "agentledger/wf1/feat", "base": "main",
                       "body": "body"}
    assert out["number"] == 9 and out["merged"] is False and out["head_sha"] == SHA


def test_existing_pull_request_is_a_clean_error():
    with pytest.raises(github.GitHubError, match="not created"):
        gh(FakeCI(create_status=422)).open_pull_request("o/r", "agentledger/wf1/f", "main", "t", "")


@pytest.mark.parametrize("kw", [{"head": "../x"}, {"base": "a b"}, {"title": ""},
                                {"title": "t" * (github.MAX_TITLE_CHARS + 1)},
                                {"body": "b" * (github.MAX_BODY_CHARS + 1)}, {"body": None}])
def test_open_pull_request_rejects_bad_input_before_any_write(kw):
    http = FakeCI()
    args = dict(repo="o/r", head="agentledger/wf1/f", base="main", title="t", body="")
    args.update(kw)
    with pytest.raises(github.GitHubError):
        gh(http).open_pull_request(**args)
    assert not [c for c in http.calls if c[0] == "POST" and not c[1].endswith("/access_tokens")]


# --- get_pull_request ----------------------------------------------------------------

def test_merged_pull_request_reports_who_merged_it():
    out = gh(FakeCI()).get_pull_request("o/r", 7, PREFIX)
    assert out["merged"] and out["merged_by"] == "OumarouDG" and out["merge_commit_sha"] == "c" * 40


def test_open_pull_request_is_not_merged():
    pr = {**PR, "state": "open", "merged": False, "merged_by": None, "merge_commit_sha": "zzz"}
    out = gh(FakeCI(pr=pr)).get_pull_request("o/r", 7, PREFIX)
    assert out["merged"] is False and out["merged_by"] is None and out["merge_commit_sha"] is None


def test_only_approvals_of_the_current_head_commit_count():
    reviews = [{"state": "APPROVED", "commit_id": SHA, "user": {"login": "bob"}},
               {"state": "APPROVED", "commit_id": OTHER, "user": {"login": "old"}},
               {"state": "CHANGES_REQUESTED", "commit_id": SHA, "user": {"login": "dana"}}]
    assert gh(FakeCI(reviews=reviews)).get_pull_request("o/r", 7, PREFIX)["approved_by"] == ["bob"]


def test_review_lookup_failure_is_unknown_not_empty():
    assert gh(FakeCI(reviews_status=403)).get_pull_request("o/r", 7, PREFIX)["approved_by"] is None


def test_pull_request_from_outside_the_prefix_looks_like_it_does_not_exist():
    pr = {**PR, "head": {"ref": "someone/else", "sha": SHA}}
    with pytest.raises(github.GitHubError, match="not found"):
        gh(FakeCI(pr=pr)).get_pull_request("o/r", 7, PREFIX)


@pytest.mark.parametrize("number", [0, -1, "7", None, True])
def test_bad_pull_request_number_rejected(number):
    http = FakeCI()
    with pytest.raises(github.GitHubError):
        gh(http).get_pull_request("o/r", number, PREFIX)
    assert not http.calls


# --- through the gateway --------------------------------------------------------------

def grant(**kw):
    base = {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["get_test_result", "open_pull_request", "get_pull_request"],
            "expires_at": int(time.time()) + 3600,
            "resources": {"repository": "o/r", "branch_prefix": PREFIX}}
    base.update(kw)
    return base


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("evgw")
    gfile, afile = d / "g.json", d / "a.jsonl"
    noprefix = grant()
    noprefix["resources"] = {"repository": "o/r"}
    gfile.write_text(json.dumps({"grants": {
        "ok": grant(), "noprefix": noprefix,
        "readonly": grant(tools=["get_issue"])}}))
    http = FakeCI(runs=[run(rid=5)])
    application = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS, grants=JsonFileGrantStore(gfile),
        audit_path=afile, github_app=gh(http)).http_app()
    srv = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield {"url": f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp",
           "afile": afile, "http": http}
    srv.should_exit = True
    t.join(timeout=10)


def call(env, grant_id, tool, args):
    async def go():
        tr = StreamableHttpTransport(
            env["url"], headers={"X-Grant-Id": grant_id, "X-Workflow-Id": "wf1"},
            auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool(tool, args, raise_on_error=False)
    return asyncio.run(go())


def lines(env):
    return [json.loads(x) for x in env["afile"].read_text().splitlines()]


def test_test_result_outcome_links_the_run_to_the_exact_sha(env):
    env["http"].runs = [run(rid=5)]
    r = call(env, "ok", "get_test_result", {"sha": SHA})
    assert not r.is_error and r.data["passed"] is True
    out = lines(env)[-1]
    assert out["artifact"] == {"kind": "test_run", "repository": "o/r", "sha": SHA, "run_id": 5,
                               "status": "completed", "conclusion": "success",
                               "url": "https://x/runs/5"}
    assert out["evidence"] == "external" and out["status"] == "succeeded"


def test_a_failed_test_is_reported_as_failed_not_hidden(env):
    env["http"].runs = [run(rid=6, conclusion="failure")]
    r = call(env, "ok", "get_test_result", {"sha": SHA})
    assert not r.is_error and r.data["passed"] is False
    assert lines(env)[-1]["artifact"]["conclusion"] == "failure"


def test_no_run_yet_records_no_artifact_and_no_external_evidence(env):
    env["http"].runs = []
    r = call(env, "ok", "get_test_result", {"sha": SHA})
    assert not r.is_error and r.data["found"] is False
    out = lines(env)[-1]
    assert "artifact" not in out and out["evidence"] == "none"


def test_tools_need_a_branch_prefix_in_the_grant(env):
    for tool, args in (("get_test_result", {"sha": SHA}), ("get_pull_request", {"number": 7})):
        r = call(env, "noprefix", tool, args)
        assert r.is_error and "resource_not_in_grant" in r.content[0].text


def test_pull_request_branch_must_be_under_the_prefix(env):
    r = call(env, "ok", "open_pull_request", {"branch": "main", "title": "t"})
    assert r.is_error and "branch_not_permitted" in r.content[0].text
    ok = call(env, "ok", "open_pull_request", {"branch": "agentledger/wf1/feat", "title": "Add"})
    assert not ok.is_error and ok.data["number"] == 9
    out = lines(env)[-1]
    assert out["artifact"]["kind"] == "pull_request" and out["artifact"]["merged"] is False


def test_acceptance_is_read_from_github_not_from_the_agent(env):
    r = call(env, "ok", "get_pull_request", {"number": 7})
    assert not r.is_error and r.data["merged"] is True
    art = lines(env)[-1]["artifact"]
    assert art["merged"] is True and art["merged_by"] == "OumarouDG" and art["sha"] == SHA


def test_tool_not_in_grant_is_denied(env):
    r = call(env, "readonly", "get_test_result", {"sha": SHA})
    assert r.is_error and "tool_not_permitted" in r.content[0].text
