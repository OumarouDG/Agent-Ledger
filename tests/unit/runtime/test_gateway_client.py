"""AgentSession against an in-process gateway: identity, allowed calls, denials, failures."""

from __future__ import annotations

import time

import pytest

from controlplane.auth.jwt_verify import AuthError
from controlplane.runtime import gateway_client as gc
from controlplane.runtime.gateway_client import (
    AgentSession, Denied, GatewayRejected, GatewayUnavailable, IdentityMismatch, ToolFailed)
from tests.unit.runtime.conftest import CLIENT_IDS, WF, FakeJwksVerifier, fake_mint


def session(url, agent="agent_lead", grant="g_lead", workflow=WF, **kw) -> AgentSession:
    kw.setdefault("mint", fake_mint())
    kw.setdefault("client_ids", CLIENT_IDS)
    return AgentSession(agent, grant, workflow, url, verifier=FakeJwksVerifier(), **kw)


# --- identity -------------------------------------------------------------------

def test_whoami_returns_the_verified_agent(gateway):
    s = session(gateway["url"])
    assert s.agent_id == "agent_lead"
    info = s.whoami()
    assert info["agent_id"] == "agent_lead" and info["client_id"] == "fakeleadclient"


def test_token_for_another_agent_is_refused_at_open(gateway):
    # The mint hands back Coder's token when asked for Lead's: the session must not open.
    swapped = fake_mint({"agent_lead": "fakecoderclient"})
    with pytest.raises(IdentityMismatch, match="verifies as agent_coder"):
        session(gateway["url"], mint=swapped)


def test_token_for_unknown_client_is_refused_at_open(gateway):
    with pytest.raises(AuthError) as e:
        session(gateway["url"], mint=fake_mint({"agent_lead": "strangerclient"}))
    assert e.value.reason == "unknown_client"


def test_expired_token_is_refused_at_open(gateway):
    with pytest.raises(AuthError) as e:
        session(gateway["url"], mint=fake_mint(exp=int(time.time()) - 3600))
    assert e.value.reason == "token_expired"


def test_token_without_tools_scope_is_refused_at_open(gateway):
    with pytest.raises(AuthError) as e:
        session(gateway["url"], mint=fake_mint(scope="agentledger/other"))
    assert e.value.reason == "missing_scope"


@pytest.mark.parametrize("agent", ["", "   ", None])
def test_empty_agent_id_is_refused(gateway, agent):
    with pytest.raises(ValueError):
        session(gateway["url"], agent=agent)


def test_gateway_that_rejects_the_token_raises(gateway):
    # Our side trusts this client; the gateway does not, so it answers 401 before any tool.
    ids = {**CLIENT_IDS, "fakerogueclient": "agent_rogue"}
    s = session(gateway["url"], agent="agent_rogue", client_ids=ids,
                mint=fake_mint({"agent_rogue": "fakerogueclient"}))
    with pytest.raises(GatewayRejected):
        s.call("agentledger_whoami")


# --- allowed and denied calls ---------------------------------------------------------

def test_allowed_get_issue_returns_the_issue(gateway):
    assert session(gateway["url"]).call("get_issue", issue_number=42)["number"] == 42


def test_revoked_grant_raises_denied(gateway):
    s = session(gateway["url"], grant="g_revoke_me")
    assert s.call("get_issue", issue_number=42)["number"] == 42
    gateway["store"].revoke("g_revoke_me")
    with pytest.raises(Denied) as e:
        s.call("get_issue", issue_number=42)
    assert (e.value.reason, e.value.tool, e.value.agent_id, e.value.grant_id) == \
        ("grant_revoked", "get_issue", "agent_lead", "g_revoke_me")


def test_tool_outside_grant_raises_denied(gateway):
    with pytest.raises(Denied) as e:
        session(gateway["url"]).call("create_branch", branch=f"agentledger/{WF}/x")
    assert e.value.reason == "tool_not_permitted"


@pytest.mark.parametrize("grant, workflow, reason", [
    (None, WF, "missing_grant"),
    ("g_lead", None, "missing_workflow"),
    ("g_ghost", WF, "unknown_grant"),
    ("g_lead", "wf_other", "grant_workflow_mismatch"),
])
def test_missing_or_wrong_headers_raise_denied(gateway, grant, workflow, reason):
    with pytest.raises(Denied) as e:
        session(gateway["url"], grant=grant, workflow=workflow).call("get_issue", issue_number=42)
    assert e.value.reason == reason


def test_another_agents_grant_raises_denied(gateway):
    s = session(gateway["url"], agent="agent_coder", grant="g_lead")
    with pytest.raises(Denied) as e:
        s.call("get_issue", issue_number=42)
    assert e.value.reason == "grant_agent_mismatch"


def test_denial_text_never_comes_back_as_a_result(gateway):
    """Silent-failure pair, part 1: the raw MCP result for a denial is an error result whose
    text is 'denied: ...'. A client that read .content without checking is_error would
    hand that text on as if it were the tool's output."""
    import asyncio
    s = session(gateway["url"])
    raw = asyncio.run(s._call_async("create_branch", {"branch": f"agentledger/{WF}/x"}))
    assert raw.is_error and raw.content[0].text == "denied: tool_not_permitted"


def test_denial_raises_instead_of_returning(gateway):
    """Silent-failure pair, part 2: call() raises on that same denial, so nothing is returned."""
    returned = "not set"
    with pytest.raises(Denied):
        returned = session(gateway["url"]).call("create_branch", branch=f"agentledger/{WF}/x")
    assert returned == "not set"


def test_tool_failure_raises_tool_failed_not_a_result(gateway):
    # Allowed by the grant, but the mock gateway only knows issue #42.
    with pytest.raises(ToolFailed, match="issue not found"):
        session(gateway["url"]).call("get_issue", issue_number=7)


# --- unreachable gateway -----------------------------------------------------------------

def test_unreachable_url_raises_gateway_unavailable(gateway, dead_url):
    s = session(dead_url)
    with pytest.raises(GatewayUnavailable, match="tunnel"):
        s.call("agentledger_whoami")


def test_gateway_unavailable_is_not_denied(gateway, dead_url):
    with pytest.raises(GatewayUnavailable) as e:
        session(dead_url).call("get_issue", issue_number=42)
    assert not isinstance(e.value, Denied)


# --- the token never shows ---------------------------------------------------------------

def _token_of(s: AgentSession) -> str:
    return s._AgentSession__token


def test_repr_and_str_never_show_the_token(gateway):
    s = session(gateway["url"])
    tok = _token_of(s)
    assert tok and tok not in repr(s) and tok not in str(s)
    assert "agent_lead" in repr(s)


def test_errors_never_contain_the_token(gateway, dead_url):
    for s, call in [
        (session(dead_url), lambda s: s.call("agentledger_whoami")),
        (session(gateway["url"]), lambda s: s.call("create_branch", branch="main")),
        (session(gateway["url"]), lambda s: s.call("get_issue", issue_number=7)),
    ]:
        with pytest.raises(gc.GatewayError) as e:
            call(s)
        assert _token_of(s) not in str(e.value) and _token_of(s) not in repr(e.value)
        assert e.value.__cause__ is None or _token_of(s) not in str(e.value.__cause__)


def test_scrub_removes_the_token():
    assert gc._scrub("Bearer abc.def.ghi failed", "abc.def.ghi") == "Bearer [redacted] failed"


# --- URL selection -----------------------------------------------------------------------

@pytest.mark.parametrize("env, expected", [
    ({}, "http://127.0.0.1:18000/mcp"),
    ({"AGENTLEDGER_GATEWAY_URL": "  "}, "http://127.0.0.1:18000/mcp"),
    ({"AGENTLEDGER_GATEWAY_URL": "http://127.0.0.1:18001/mcp"}, "http://127.0.0.1:18001/mcp"),
])
def test_gateway_url_from_env(env, expected):
    assert gc.gateway_url(env) == expected
