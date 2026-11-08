"""Audit fails closed: if the event cannot be written, the call is denied."""

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import audit
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make


def test_record_raises_when_path_is_unwritable(tmp_path):
    with pytest.raises(audit.AuditError):
        audit.record(tmp_path, tool="x")  # a directory cannot be opened for append


def test_record_raises_when_a_field_is_not_json(tmp_path):
    with pytest.raises(audit.AuditError):
        audit.record(tmp_path / "a.jsonl", tool=object())


def test_record_writes_a_line(tmp_path):
    p = tmp_path / "a.jsonl"
    audit.record(p, tool="x", decision="allow")
    assert json.loads(p.read_text())["tool"] == "x"


@pytest.fixture(scope="module")
def url(tmp_path_factory):
    d = tmp_path_factory.mktemp("auditgw")
    gfile = d / "grants.json"
    gfile.write_text(json.dumps({"grants": {"ok": {
        "agent_id": "coder-agent", "workflow_id": "wf1", "tools": ["get_issue"],
        "expires_at": int(time.time()) + 3600}}}))
    app = gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS,
                           grants=JsonFileGrantStore(gfile),
                           audit_path=d / "no-such-dir" / "audit.jsonl").http_app()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp"
    srv.should_exit = True
    t.join(timeout=10)


def test_valid_grant_is_denied_when_audit_cannot_be_written(url):
    async def go():
        tr = StreamableHttpTransport(url, headers={"X-Grant-Id": "ok", "X-Workflow-Id": "wf1"},
                                     auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool("get_issue", {"issue_number": 42}, raise_on_error=False)
    r = asyncio.run(go())
    assert r.is_error and "audit_unavailable" in r.content[0].text
