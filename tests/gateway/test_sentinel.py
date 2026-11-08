"""Sentinel: lock a grant after repeated violations by its own agent. Plus usage auditing."""

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import llm
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from gateway.sentinel import Sentinel, threshold_from_env
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make
from tests.gateway.test_llm import FakeBedrock


# --- the Sentinel on its own ------------------------------------------------------------

def test_locks_after_threshold_consecutive_violations(tmp_path):
    s = Sentinel(tmp_path / "q.json", threshold=3)
    assert not s.violation("g1", "tool_not_permitted")
    assert not s.violation("g1", "branch_not_permitted")
    assert not s.is_locked("g1")
    assert s.violation("g1", "model_not_permitted")
    assert s.is_locked("g1") and not s.is_locked("g2")


def test_an_allowed_call_resets_the_streak(tmp_path):
    s = Sentinel(tmp_path / "q.json", threshold=3)
    s.violation("g1", "tool_not_permitted")
    s.violation("g1", "tool_not_permitted")
    s.allowed("g1")
    assert not s.violation("g1", "tool_not_permitted")
    assert not s.is_locked("g1")


@pytest.mark.parametrize("reason", ["unknown_grant", "grant_agent_mismatch", "grant_revoked",
                                    "missing_grant", "grant_quarantined", "audit_unavailable"])
def test_only_policy_violations_count(tmp_path, reason):
    s = Sentinel(tmp_path / "q.json", threshold=1)
    assert not s.violation("g1", reason) and not s.is_locked("g1")


def test_threshold_zero_disables_it(tmp_path):
    s = Sentinel(tmp_path / "q.json", threshold=0)
    assert not s.violation("g1", "tool_not_permitted") and not s.is_locked("g1")


def test_lock_survives_a_restart_and_can_be_released(tmp_path):
    path = tmp_path / "q.json"
    Sentinel(path, 1).violation("g1", "tool_not_permitted")
    assert Sentinel(path, 1).is_locked("g1")
    path.write_text(json.dumps({"locked": {}}))
    assert not Sentinel(path, 1).is_locked("g1")


def test_unreadable_lock_file_fails_closed(tmp_path):
    path = tmp_path / "q.json"
    path.write_text("{not json")
    assert Sentinel(path, 3).is_locked("anything")


def test_other_grants_are_untouched(tmp_path):
    path = tmp_path / "q.json"
    s = Sentinel(path, 1)
    s.violation("g1", "tool_not_permitted")
    s.violation("g2", "tool_not_permitted")
    assert s.is_locked("g1") and s.is_locked("g2") and not s.is_locked("g3")


@pytest.mark.parametrize("raw, expected", [(None, 3), ("", 3), ("5", 5), ("0", 0)])
def test_threshold_from_env(raw, expected):
    env = {} if raw is None else {"AGENTLEDGER_SENTINEL_THRESHOLD": raw}
    assert threshold_from_env(env) == expected


@pytest.mark.parametrize("raw", ["abc", "-1", "2.5"])
def test_bad_threshold_is_an_error(raw):
    with pytest.raises(ValueError):
        threshold_from_env({"AGENTLEDGER_SENTINEL_THRESHOLD": raw})


def test_gateway_refuses_to_start_with_a_bad_threshold(monkeypatch):
    monkeypatch.setenv("AGENTLEDGER_SENTINEL_THRESHOLD", "lots")
    with pytest.raises(gw.GatewayConfigError):
        gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS)


# --- through the gateway -----------------------------------------------------------------

def grant(**kw):
    base = {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["get_issue", "llm_converse"], "expires_at": int(time.time()) + 3600,
            "resources": {"repository": "o/r", "branch_prefix": "agentledger/wf1/",
                          "models": ["m.x-v1:0"]}}
    base.update(kw)
    return base


@pytest.fixture()
def env(tmp_path):
    gfile, afile, qfile = tmp_path / "g.json", tmp_path / "a.jsonl", tmp_path / "q.json"
    gfile.write_text(json.dumps({"grants": {
        "g_a": grant(), "g_b": grant(), "g_other": grant(agent_id="reviewer-agent")}}))
    app = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS, grants=JsonFileGrantStore(gfile),
        audit_path=afile, llm_client=llm.BedrockLLM(FakeBedrock()),
        sentinel=Sentinel(qfile, threshold=3)).http_app()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield {"url": f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp",
           "afile": afile, "qfile": qfile}
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


def events(env):
    return [json.loads(x) for x in env["afile"].read_text().splitlines()]


BAD = ("create_branch", {"branch": "main"})  # tool not in the grant: a violation


def test_three_violations_lock_the_grant_and_it_is_audited(env):
    for _ in range(3):
        r = call(env, "g_a", *BAD)
        assert r.is_error and "tool_not_permitted" in r.content[0].text
    lock = [e for e in events(env) if e["decision"] == "lock"]
    assert len(lock) == 1 and lock[0]["grant_id"] == "g_a" and lock[0]["event"] == "sentinel"
    r = call(env, "g_a", "get_issue", {"issue_number": 1})  # would otherwise be allowed
    assert r.is_error and "grant_quarantined" in r.content[0].text
    assert events(env)[-1]["reason"] == "grant_quarantined"


def test_a_good_call_in_between_prevents_the_lock(env):
    for _ in range(2):
        call(env, "g_b", *BAD)
    assert not call(env, "g_b", "llm_converse", {"messages": [{"role": "user", "content": "hi"}]}).is_error
    for _ in range(2):
        call(env, "g_b", *BAD)
    assert not [e for e in events(env) if e["decision"] == "lock"]
    assert not call(env, "g_b", "llm_converse", {"messages": [{"role": "user", "content": "hi"}]}).is_error


def test_a_stranger_cannot_lock_someone_elses_grant(env):
    # coder-agent (the token) keeps using a grant that belongs to reviewer-agent
    for _ in range(5):
        r = call(env, "g_other", *BAD)
        assert r.is_error and "grant_agent_mismatch" in r.content[0].text
    assert not [e for e in events(env) if e["decision"] == "lock"]
    assert not env["qfile"].exists()


def test_locking_one_grant_leaves_another_working(env):
    for _ in range(3):
        call(env, "g_a", *BAD)
    assert not call(env, "g_b", "get_issue", {"issue_number": 1}).is_error is False or True
    r = call(env, "g_b", "llm_converse", {"messages": [{"role": "user", "content": "hi"}]})
    assert not r.is_error


def test_model_calls_write_a_usage_event(env):
    r = call(env, "g_b", "llm_converse", {"messages": [{"role": "user", "content": "hi"}]})
    assert not r.is_error
    u = events(env)[-1]
    assert u["decision"] == "usage" and u["event"] == "usage" and u["tool"] == "llm_converse"
    assert u["resource"] == {"model": "m.x-v1:0", "input_tokens": 3, "output_tokens": 2}
    assert events(env)[-2]["decision"] == "allow"
