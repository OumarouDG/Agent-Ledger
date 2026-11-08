"""Outcome events: an allowed call is not a successful call. Offline, fake GitHub."""

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make
from tests.gateway.test_github import Resp
from tests.gateway.test_write_tools import Fake, app, grant


class Boom(Fake):
    """A GitHub client that blows up with a message that must never reach an agent or the log."""

    def put(self, url, headers, timeout, json=None):
        raise RuntimeError("secret ghs_LEAKED token in message")


def start(tmp_path, http):
    gfile, afile = tmp_path / "g.json", tmp_path / "a.jsonl"
    gfile.write_text(json.dumps({"grants": {"ok": grant()}}))
    application = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS, grants=JsonFileGrantStore(gfile),
        audit_path=afile, github_app=app(http)).http_app()
    srv = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    url = f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp"
    return srv, t, url, afile


@pytest.fixture()
def gateway(tmp_path):
    http = Fake()
    srv, t, url, afile = start(tmp_path, http)
    yield {"url": url, "afile": afile, "http": http}
    srv.should_exit = True
    t.join(timeout=10)


def call(url, tool, args, grant_id="ok"):
    async def go():
        tr = StreamableHttpTransport(
            url, headers={"X-Grant-Id": grant_id, "X-Workflow-Id": "wf1"}, auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool(tool, args, raise_on_error=False)
    return asyncio.run(go())


def lines(afile):
    return [json.loads(x) for x in afile.read_text().splitlines()]


COMMIT = {"branch": "agentledger/wf1/feat", "path": "src/g.py",
          "content": "def greet(n): return n", "message": "add"}


def test_success_writes_a_correlated_outcome_with_the_commit_sha(gateway):
    r = call(gateway["url"], "commit_file", COMMIT)
    assert not r.is_error
    decision, outcome = lines(gateway["afile"])[-2:]
    assert decision["event"] == "decision" and decision["decision"] == "allow"
    assert outcome["event"] == "outcome" and outcome["status"] == "succeeded"
    assert outcome["activity_id"] == decision["activity_id"]
    assert outcome["artifact"] == {"kind": "git_commit", "repository": "o/r",
                                   "branch": "agentledger/wf1/feat", "path": "src/g.py",
                                   "sha": "newsha"}
    assert outcome["source"] == "github_api" and outcome["evidence"] == "external"
    assert isinstance(outcome["elapsed_ms"], int)
    assert outcome["human_id"] == "alice" and outcome["grant_id"] == "ok"


def test_failed_github_call_is_recorded_as_failed_with_no_artifact(tmp_path):
    http = Fake(put_status=500)
    srv, t, url, afile = start(tmp_path, http)
    try:
        r = call(url, "commit_file", COMMIT)
    finally:
        srv.should_exit = True
        t.join(timeout=10)
    assert r.is_error and "HTTP 500" in r.content[0].text
    decision, outcome = lines(afile)[-2:]
    assert decision["decision"] == "allow"  # it was authorized...
    assert outcome["status"] == "failed" and "HTTP 500" in outcome["error"]  # ...and failed
    assert "artifact" not in outcome and "evidence" not in outcome


def run_once(tmp_path, http, args=COMMIT):
    srv, t, url, afile = start(tmp_path, http)
    try:
        return call(url, "commit_file", args), afile
    finally:
        srv.should_exit = True
        t.join(timeout=10)


def test_network_style_failure_never_leaks_the_exception_message(tmp_path):
    r, afile = run_once(tmp_path, Boom())
    assert r.is_error and "LEAKED" not in r.content[0].text
    text = afile.read_text()
    assert "LEAKED" not in text and "ghs_" not in text
    outcome = lines(afile)[-1]
    assert outcome["status"] == "failed" and outcome["error"] == "github request failed: RuntimeError"


class Malformed(Fake):
    """GitHub answers 201 but without the commit: an unexpected shape, not an HTTP error."""

    def put(self, url, headers, timeout, json=None):
        return Resp(201, {})


def test_unexpected_shape_becomes_internal_error_and_a_failed_outcome(tmp_path):
    r, afile = run_once(tmp_path, Malformed())
    assert r.is_error and r.content[0].text.endswith("internal error")
    outcome = lines(afile)[-1]
    assert outcome["status"] == "failed" and outcome["error"] == "KeyError"
    assert "commit" not in r.content[0].text

def test_denied_calls_have_no_outcome_line(gateway):
    call(gateway["url"], "commit_file", {**COMMIT, "branch": "main"})
    last = lines(gateway["afile"])[-1]
    assert last["event"] == "decision" and last["decision"] == "deny"


def test_each_call_gets_its_own_activity_id_so_retries_do_not_merge(gateway):
    call(gateway["url"], "commit_file", COMMIT)
    call(gateway["url"], "commit_file", COMMIT)
    outcomes = [e for e in lines(gateway["afile"]) if e["event"] == "outcome"]
    assert len(outcomes) == 2 and outcomes[0]["activity_id"] != outcomes[1]["activity_id"]
    ids = [e["event_id"] for e in lines(gateway["afile"])]
    assert len(ids) == len(set(ids))


def test_branch_outcome_artifact(gateway):
    call(gateway["url"], "create_branch", {"branch": "agentledger/wf1/feat"})
    outcome = lines(gateway["afile"])[-1]
    assert outcome["artifact"] == {"kind": "git_branch", "repository": "o/r",
                                   "branch": "agentledger/wf1/feat", "sha": "basesha"}


def test_file_content_never_reaches_the_audit(gateway):
    call(gateway["url"], "commit_file", COMMIT)
    assert "def greet" not in gateway["afile"].read_text()


def test_ping_and_whoami_are_audited_without_a_grant(gateway):
    async def go():
        async with Client(gateway["url"], auth=BearerAuth(make())) as c:
            await c.call_tool("agentledger_ping")
            await c.call_tool("agentledger_whoami")
    asyncio.run(go())
    a, b = lines(gateway["afile"])[-2:]
    assert (a["tool"], b["tool"]) == ("agentledger_ping", "agentledger_whoami")
    for e in (a, b):
        assert e["event"] == "identity" and e["decision"] == "allow"
        assert e["agent_id"] == "coder-agent" and e["grant_id"] is None
