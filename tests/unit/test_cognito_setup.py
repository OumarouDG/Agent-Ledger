"""Offline tests for infra/cognito_setup.py: fallbacks are reported loudly at the end of the run.

Importing the module creates boto3 clients but makes no AWS call.
"""

from __future__ import annotations

import infra.cognito_setup as setup

GOOD = {"client_id": "c1", "scopes": [], "secret_ref": "secretsmanager:agentledger/agents/a", "token_mode": "get_client_token"}


def test_no_warning_when_nothing_fell_back(capsys):
    agents = {"agent_lead": dict(GOOD), "agent_coder": dict(GOOD)}
    assert setup.report_fallbacks(agents) == []
    assert "WARNING" not in capsys.readouterr().out


def test_oauth2_token_fallback_is_reported_loudly(capsys):
    # Bad case: the only sign of the fallback was one indented line in the middle of the run.
    agents = {"agent_lead": dict(GOOD), "agent_coder": dict(GOOD, token_mode="oauth2_token")}
    lines = setup.report_fallbacks(agents)
    out = capsys.readouterr().out
    assert any("agent_coder" in line and "oauth2_token" in line for line in lines)
    assert not any("agent_lead" in line for line in lines)
    assert out.count("WARNING") >= 1 and "agent_coder" in out


def test_local_secret_fallback_is_reported_loudly(capsys):
    # Bad case: Secrets Manager was denied and secrets went to a local file with one indented line.
    agents = {"agent_tester": dict(GOOD, secret_ref="local:agent_tester")}
    lines = setup.report_fallbacks(agents)
    out = capsys.readouterr().out
    assert any("agent_tester" in line and "agent-secrets.local.json" in line for line in lines)
    assert "WARNING" in out


def test_both_fallbacks_for_one_agent_both_reported(capsys):
    agents = {"agent_rogue": dict(GOOD, token_mode="oauth2_token", secret_ref="local:agent_rogue")}
    assert len(setup.report_fallbacks(agents)) == 2
