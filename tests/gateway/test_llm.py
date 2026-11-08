"""llm_converse: request validation, grant-scoped models and limits. Offline, fake Bedrock."""

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
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make

USER = [{"role": "user", "content": "hi"}]


class FakeBedrock:
    def __init__(self, error=None, response=None):
        self.calls, self.error = [], error
        self.response = response or {
            "output": {"message": {"content": [{"text": "hello "}, {"text": "there"}]}},
            "usage": {"inputTokens": 3, "outputTokens": 2}, "stopReason": "end_turn"}

    def converse(self, **kw):
        self.calls.append(kw)
        if self.error:
            raise self.error
        return self.response


class ClientError(Exception):
    response = {"Error": {"Code": "AccessDeniedException"}}


# --- validation -------------------------------------------------------------------

@pytest.mark.parametrize("messages", [
    None, [], "hi", [{"role": "system", "content": "x"}],
    [{"role": "user", "content": ""}], [{"role": "user", "content": "  "}],
    [{"role": "user", "content": 5}], [{"role": "user"}],
    [{"role": "user", "content": "x", "extra": 1}],
    [{"role": "assistant", "content": "x"}],
    [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}],
    [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}],
    [{"role": "user", "content": "x" * (llm.MAX_MESSAGE_CHARS + 1)}],
    [{"role": "user" if i % 2 == 0 else "assistant", "content": "x"}
     for i in range(llm.MAX_MESSAGES + 1)],
])
def test_bad_messages_rejected(messages):
    with pytest.raises(llm.LLMError):
        llm.validate_messages(messages)


def test_good_messages_become_converse_format():
    out = llm.validate_messages([{"role": "user", "content": "a"},
                                 {"role": "assistant", "content": "b"},
                                 {"role": "user", "content": "c"}])
    assert out[0] == {"role": "user", "content": [{"text": "a"}]} and len(out) == 3


@pytest.mark.parametrize("limit, expected", [
    (None, 1024), (0, 1024), (-5, 1024), ("500", 1024), (True, 1024),
    (300, 300), (999_999, llm.HARD_MAX_TOKENS)])
def test_max_tokens_never_exceeds_the_hard_cap(limit, expected):
    assert llm.effective_max_tokens(limit) == expected


def test_converse_joins_text_and_reports_usage():
    out = llm.BedrockLLM(FakeBedrock()).converse("m.x-v1:0", USER, None, 50)
    assert out == {"model": "m.x-v1:0", "text": "hello there", "stop_reason": "end_turn",
                   "input_tokens": 3, "output_tokens": 2}


def test_converse_sends_system_and_token_cap():
    fake = FakeBedrock()
    llm.BedrockLLM(fake).converse("m.x-v1:0", USER, "be brief", 77)
    kw = fake.calls[0]
    assert kw["system"] == [{"text": "be brief"}] and kw["inferenceConfig"] == {"maxTokens": 77}


@pytest.mark.parametrize("model", ["", "bad model", "a;b", "x" * 201, None, 5])
def test_bad_model_id_rejected_before_any_call(model):
    fake = FakeBedrock()
    with pytest.raises(llm.LLMError):
        llm.BedrockLLM(fake).converse(model, USER, None, 10)
    assert not fake.calls


def test_aws_errors_become_safe_messages():
    with pytest.raises(llm.LLMError, match="AccessDeniedException"):
        llm.BedrockLLM(FakeBedrock(error=ClientError("secret detail"))).converse(
            "m.x-v1:0", USER, None, 10)


def test_unexpected_response_is_an_error():
    with pytest.raises(llm.LLMError, match="unexpected"):
        llm.BedrockLLM(FakeBedrock(response={"nope": 1})).converse("m.x-v1:0", USER, None, 10)


# --- through the gateway ------------------------------------------------------------

def grant(**res):
    resources = {"models": ["allowed.model-v1:0", "other.model-v1:0"], "max_tokens": 200}
    resources.update(res)
    return {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["llm_converse"], "resources": resources,
            "expires_at": int(time.time()) + 3600}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("llmgw")
    gfile, afile = d / "g.json", d / "a.jsonl"
    gfile.write_text(json.dumps({"grants": {
        "ok": grant(), "nomodels": grant(models=None), "nolimit": grant(max_tokens=None),
        "notool": {**grant(), "tools": ["get_issue"]}}}))
    fake = FakeBedrock()
    app = gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS,
                           grants=JsonFileGrantStore(gfile), audit_path=afile,
                           llm_client=llm.BedrockLLM(fake)).http_app()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield {"url": f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp",
           "afile": afile, "fake": fake}
    srv.should_exit = True
    t.join(timeout=10)


def call(env, grant_id, **args):
    args.setdefault("messages", USER)

    async def go():
        tr = StreamableHttpTransport(
            env["url"], headers={"X-Grant-Id": grant_id, "X-Workflow-Id": "wf1"},
            auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool("llm_converse", args, raise_on_error=False)
    return asyncio.run(go())


def last_audit(env):
    return json.loads(env["afile"].read_text().splitlines()[-1])


def test_default_model_is_the_first_one_in_the_grant(env):
    r = call(env, "ok")
    assert not r.is_error and r.data["text"] == "hello there"
    kw = env["fake"].calls[-1]
    assert kw["modelId"] == "allowed.model-v1:0" and kw["inferenceConfig"]["maxTokens"] == 200
    lines = [json.loads(x) for x in env["afile"].read_text().splitlines()]
    allow, usage = lines[-2], lines[-1]  # the decision, then the usage record after the call
    assert allow["decision"] == "allow" and allow["resource"]["model"] == "allowed.model-v1:0"
    assert usage["decision"] == "usage" and usage["resource"]["output_tokens"] == 2


def test_second_listed_model_can_be_chosen(env):
    assert not call(env, "ok", model="other.model-v1:0").is_error
    assert env["fake"].calls[-1]["modelId"] == "other.model-v1:0"


def test_unlisted_model_is_denied_before_bedrock(env):
    before = len(env["fake"].calls)
    r = call(env, "ok", model="anthropic.claude-opus-5")
    assert r.is_error and "model_not_permitted" in r.content[0].text
    assert len(env["fake"].calls) == before
    e = last_audit(env)
    assert e["decision"] == "deny" and e["resource"]["model"] == "anthropic.claude-opus-5"


def test_grant_without_models_cannot_call_a_model(env):
    before = len(env["fake"].calls)
    r = call(env, "nomodels")
    assert r.is_error and "model_not_permitted" in r.content[0].text
    assert len(env["fake"].calls) == before


def test_missing_limit_uses_the_default_cap(env):
    call(env, "nolimit")
    assert env["fake"].calls[-1]["inferenceConfig"]["maxTokens"] == llm.DEFAULT_MAX_TOKENS


def test_tool_not_in_grant_is_denied(env):
    r = call(env, "notool")
    assert r.is_error and "tool_not_permitted" in r.content[0].text


def test_bad_messages_are_a_clean_error_after_the_grant_check(env):
    r = call(env, "ok", messages=[{"role": "system", "content": "x"}])
    assert r.is_error and "role must be" in r.content[0].text
