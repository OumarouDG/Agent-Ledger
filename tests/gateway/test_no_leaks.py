"""Nothing secret may reach the audit file: tokens, keys, file contents, prompts, error details.

Drives every kind of event (success, denial, GitHub failure, crash, model call) with distinctive
fake secrets in the inputs, then scans the whole audit text."""

import asyncio
import json
import time

import pytest
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import llm
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make
from tests.gateway.test_llm import FakeBedrock
from tests.gateway.test_outcomes import Boom, start
from tests.gateway.test_write_tools import Fake, grant

FORBIDDEN = ["eyJ", "Bearer ", "-----BEGIN", "ghs_", "AKIA", "SECRET_FILE_BODY",
             "SECRET_PROMPT_TEXT", "SECRET_SYSTEM_TEXT", "password", "client_secret"]


def call_all(url, token):
    """One of everything an agent can do, including calls that must be refused."""
    async def go():
        tr = StreamableHttpTransport(
            url, headers={"X-Grant-Id": "ok", "X-Workflow-Id": "wf1"}, auth=BearerAuth(token))
        async with Client(tr) as c:
            await c.call_tool("agentledger_whoami", raise_on_error=False)
            await c.call_tool("create_branch", {"branch": "agentledger/wf1/feat"}, raise_on_error=False)
            await c.call_tool("commit_file", {
                "branch": "agentledger/wf1/feat", "path": "a.py",
                "content": "SECRET_FILE_BODY", "message": "m"}, raise_on_error=False)
            await c.call_tool("commit_file", {
                "branch": "main", "path": "a.py", "content": "SECRET_FILE_BODY",
                "message": "m"}, raise_on_error=False)
            await c.call_tool("llm_converse", {
                "messages": [{"role": "user", "content": "SECRET_PROMPT_TEXT"}],
                "system": "SECRET_SYSTEM_TEXT"}, raise_on_error=False)
            await c.call_tool("llm_converse", {
                "messages": [{"role": "user", "content": "SECRET_PROMPT_TEXT"}],
                "model": "not.allowed-v1:0"}, raise_on_error=False)
    asyncio.run(go())


def grants_with_models(tmp_path):
    g = grant()
    g["tools"] = ["create_branch", "commit_file", "llm_converse"]
    g["resources"]["models"] = ["m.x-v1:0"]
    (tmp_path / "g.json").write_text(json.dumps({"grants": {"ok": g}}))


@pytest.mark.parametrize("http", [Fake(), Boom()], ids=["github-ok", "github-crashes"])
def test_audit_text_never_contains_secrets_or_request_content(tmp_path, http):
    grants_with_models(tmp_path)
    afile = tmp_path / "a.jsonl"
    token = make()
    from tests.gateway.test_write_tools import app
    import threading
    import uvicorn
    application = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS,
        grants=JsonFileGrantStore(tmp_path / "g.json"), audit_path=afile, github_app=app(http),
        llm_client=llm.BedrockLLM(FakeBedrock())).http_app()
    srv = uvicorn.Server(uvicorn.Config(application, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    try:
        call_all(f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp", token)
    finally:
        srv.should_exit = True
        t.join(timeout=10)

    text = afile.read_text()
    assert text.count("\n") >= 8, "the scan needs real events to mean anything"
    assert token not in text
    for needle in FORBIDDEN:
        assert needle not in text, f"audit contains {needle!r}"
    # every line is valid JSON with the fields consumers rely on
    for line in text.splitlines():
        e = json.loads(line)
        assert e["event_id"].startswith("evt_") and "tool" in e and "decision" in e
