"""Grant authorization: pure decision tests plus end-to-end checks through the HTTP server."""

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
from gateway.authorization import authorize
from gateway.grants import Grant, GrantStoreError, JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, CODER, FakeJwksVerifier, make

FUTURE = int(time.time()) + 3600


class DictStore:
    def __init__(self, *grants: Grant):
        self.items = {g.grant_id: g for g in grants}

    def get(self, grant_id):
        return self.items.get(grant_id)


def g(grant_id="g1", **kw) -> Grant:
    base = dict(agent_id="coder-agent", workflow_id="wf1", tools=frozenset({"get_issue"}))
    base.update(kw)
    return Grant(grant_id=grant_id, **base)


def run(store, **kw):
    args = dict(agent_id="coder-agent", grant_id="g1", workflow_id="wf1", tool="get_issue")
    args.update(kw)
    return authorize(store, **args)


# --- pure decisions -----------------------------------------------------------

def test_valid_grant_allows():
    assert run(DictStore(g())).allowed


@pytest.mark.parametrize("kw, reason", [
    ({"agent_id": None}, "unknown_agent"),
    ({"grant_id": None}, "missing_grant"),
    ({"workflow_id": None}, "missing_workflow"),
    ({"grant_id": "nope"}, "unknown_grant"),
    ({"agent_id": "other-agent"}, "grant_agent_mismatch"),
    ({"workflow_id": "wf2"}, "grant_workflow_mismatch"),
    ({"tool": "commit_file"}, "tool_not_permitted"),
])
def test_denials(kw, reason):
    d = run(DictStore(g()), **kw)
    assert not d.allowed and d.reason == reason


@pytest.mark.parametrize("status", ["revoked", "quarantined"])
def test_inactive_grant_denied(status):
    assert run(DictStore(g(status=status))).reason == f"grant_{status}"


def test_expired_grant_denied():
    assert run(DictStore(g(expires_at=int(time.time()) - 1))).reason == "grant_expired"


def test_delegable_does_not_imply_execute():
    store = DictStore(g(tools=frozenset(), delegable_tools=frozenset({"get_issue"})))
    assert run(store).reason == "tool_not_permitted"


def test_revoked_parent_kills_child():
    store = DictStore(g("g1", parent_grant_id="p"), g("p", status="revoked"))
    assert run(store).reason == "parent_grant_revoked"


def test_missing_parent_denied():
    assert run(DictStore(g(parent_grant_id="ghost"))).reason == "parent_grant_missing"


def test_parent_cycle_denied():
    store = DictStore(g("g1", parent_grant_id="p"), g("p", parent_grant_id="g1"))
    assert run(store).reason == "grant_chain_invalid"


def test_store_failure_fails_closed():
    class Broken:
        def get(self, grant_id):
            raise GrantStoreError("boom")
    assert run(Broken()).reason == "grant_store_unavailable"


def test_json_store_missing_or_corrupt_file_is_store_error(tmp_path):
    with pytest.raises(GrantStoreError):
        JsonFileGrantStore(tmp_path / "missing.json").get("g1")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(GrantStoreError):
        JsonFileGrantStore(bad).get("g1")


# --- end to end ---------------------------------------------------------------

def write_grants(path, **grants):
    path.write_text(json.dumps({"grants": grants}))


def grant(**kw):
    base = {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["get_issue"], "expires_at": FUTURE}
    base.update(kw)
    return base


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("gw")
    gfile, afile = d / "grants.json", d / "audit.jsonl"
    write_grants(gfile, ok=grant(), other_agent=grant(agent_id="reviewer-agent"),
                 no_tool=grant(tools=[]), later_revoked=grant())
    app = gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS,
                           grants=JsonFileGrantStore(gfile), audit_path=afile).http_app()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    port = server.servers[0].sockets[0].getsockname()[1]
    yield {"url": f"http://127.0.0.1:{port}/mcp", "gfile": gfile, "afile": afile}
    server.should_exit = True
    t.join(timeout=10)


def call_get_issue(env, grant_id=None, workflow="wf1"):
    headers = {}
    if grant_id:
        headers["X-Grant-Id"] = grant_id
    if workflow:
        headers["X-Workflow-Id"] = workflow

    async def go():
        transport = StreamableHttpTransport(env["url"], headers=headers, auth=BearerAuth(make()))
        async with Client(transport) as c:
            return await c.call_tool("get_issue", {"issue_number": 42}, raise_on_error=False)
    return asyncio.run(go())


def audit_events(env):
    return [json.loads(x) for x in env["afile"].read_text().splitlines()]


def test_valid_grant_allows_and_is_audited(env):
    r = call_get_issue(env, "ok")
    assert not r.is_error and r.data["number"] == 42
    e = [x for x in audit_events(env) if x.get("event") == "decision"][-1]
    assert (e["decision"], e["agent_id"], e["grant_id"], e["human_id"], e["tool"]) == \
        ("allow", "coder-agent", "ok", "alice", "get_issue")


@pytest.mark.parametrize("grant_id, workflow, reason", [
    (None, "wf1", "missing_grant"),
    ("ok", None, "missing_workflow"),
    ("ghost", "wf1", "unknown_grant"),
    ("other_agent", "wf1", "grant_agent_mismatch"),
    ("ok", "wf2", "grant_workflow_mismatch"),
    ("no_tool", "wf1", "tool_not_permitted"),
])
def test_denied_calls_error_and_are_audited(env, grant_id, workflow, reason):
    r = call_get_issue(env, grant_id, workflow)
    assert r.is_error and reason in r.content[0].text
    e = audit_events(env)[-1]
    assert e["decision"] == "deny" and e["reason"] == reason


def test_revocation_denies_next_request(env):
    assert not call_get_issue(env, "later_revoked").is_error
    write_grants(env["gfile"], ok=grant(), other_agent=grant(agent_id="reviewer-agent"),
                 no_tool=grant(tools=[]), later_revoked=grant(status="revoked"))
    r = call_get_issue(env, "later_revoked")
    assert r.is_error and "grant_revoked" in r.content[0].text
