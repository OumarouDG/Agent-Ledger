"""`agentledger grant ...` offline: real session verification (locally signed JWTs, in-memory
keyring), in-memory grant store, no network. Token values are fakes."""

from __future__ import annotations

import pytest
import requests
from click.testing import CliRunner

from agentledger import commands, grant_commands, storage
from agentledger.main import cli
from agentledger.storage import TokenStore
from controlplane.grants import service
from gateway.grants import GrantStoreError
from tests.unit.cli.conftest import MemoryKeyring
from tests.unit.cli.test_session import CFG, expired_id_token, id_token, save, verifier
from tests.unit.grants.test_service import FakeStore

AGENTS = frozenset({"agent_lead", "agent_coder", "agent_tester"})


class ListStore(FakeStore):
    def __init__(self):
        super().__init__()
        self.broken = False

    def get(self, grant_id):
        if self.broken:
            raise GrantStoreError("grant store unavailable (ResourceNotFoundException): "
                                  "table missing: run `python infra/grants_setup.py`")
        return super().get(grant_id)

    def by_workflow(self, workflow_id):
        return [r["grant"] for r in self.items.values() if r["grant"].workflow_id == workflow_id]

    def all(self):
        return [r["grant"] for r in self.items.values()]


@pytest.fixture
def env(monkeypatch):
    backend = MemoryKeyring()
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: backend)
    tokens = TokenStore(CFG["user_pool_id"])
    grants = ListStore()
    monkeypatch.setattr(commands, "_context", lambda: (CFG, tokens, verifier()))
    monkeypatch.setattr(grant_commands, "_store", lambda: grants)
    monkeypatch.setattr(service, "registered_agents", lambda: AGENTS)

    def no_http(*a, **k):
        raise AssertionError("unexpected HTTP call")
    monkeypatch.setattr(requests, "post", no_http)
    return {"tokens": tokens, "grants": grants}


def sign_in(env, user="alice", groups=("engineer",)):
    tok = id_token(**{"cognito:username": user, "cognito:groups": list(groups)})
    save(env["tokens"], tok, refresh=None)
    return tok


def run(*args):
    return CliRunner().invoke(cli, ["grant", *args])


CREATE = ["create", "--agent", "agent_coder", "--workflow", "wf_demo", "--tools", "get_issue",
          "--repo", "acme/demo", "--ttl", "60m"]


def created_id(env):
    assert len(env["grants"].items) == 1
    return next(iter(env["grants"].items))


# --- signed out / expired -------------------------------------------------------

@pytest.mark.parametrize("args", [CREATE, ["revoke", "gr_x"], ["show", "gr_x"], ["list"]])
def test_signed_out_refused(env, args):
    res = run(*args)
    assert res.exit_code == 1, res.output
    assert "run agentledger login" in res.output
    assert env["grants"].writes == 0


def test_expired_session_refused(env):
    save(env["tokens"], expired_id_token(), refresh=None)
    res = run(*CREATE)
    assert res.exit_code == 1 and "run agentledger login" in res.output
    assert env["grants"].writes == 0


# --- create ---------------------------------------------------------------------

def test_create_as_alice(env):
    tok = sign_in(env)
    res = run("create", "--agent", "agent_lead", "--workflow", "wf_demo",
              "--tools", "get_issue,commit_file", "--tools", "create_branch",
              "--delegable", "commit_file", "--repo", "acme/demo", "--ttl", "2h")
    assert res.exit_code == 0, res.output
    g = env["grants"].get(created_id(env))
    assert g.human_id == "alice" and g.agent_id == "agent_lead" and g.status == "active"
    assert g.tools == frozenset({"get_issue", "commit_file", "create_branch"})
    assert g.delegable_tools == frozenset({"commit_file"})
    assert f"Created grant {g.grant_id} for agent_lead on behalf of alice" in res.output
    assert "status:          active" in res.output
    assert tok not in res.output and "fake-access" not in res.output


def test_human_id_comes_from_session(env):
    sign_in(env, "dana", ("security-admin",))
    assert run(*CREATE).exit_code == 0
    assert env["grants"].get(created_id(env)).human_id == "dana"


@pytest.mark.parametrize("flag", ["--human", "--human-id", "--human_id", "--user"])
def test_no_flag_can_set_human_id(env, flag):
    # Bad case: a flag naming another human would create a grant on their behalf.
    sign_in(env)
    res = run(*CREATE, flag, "mallory")
    assert res.exit_code == 2 and "No such option" in res.output
    assert env["grants"].writes == 0


def test_reviewer_refused(env):
    sign_in(env, "bob", ("reviewer",))
    res = run(*CREATE)
    assert res.exit_code == 1
    assert "Refused: role_not_permitted" in res.output and "bob" in res.output
    assert env["grants"].writes == 0


@pytest.mark.parametrize("swap, reason", [
    (("--agent", "agent_nobody"), "unknown_agent"),
    (("--repo", "acme"), "bad_repository"),
    (("--ttl", "5h"), "bad_expiry"),
])
def test_refusal_reasons_printed(env, swap, reason):
    sign_in(env)
    args = list(CREATE)
    args[args.index(swap[0]) + 1] = swap[1]
    res = run(*args)
    assert res.exit_code == 1 and f"Refused: {reason}" in res.output
    assert env["grants"].writes == 0


def test_empty_tools_refused(env):
    sign_in(env)
    args = list(CREATE)
    args[args.index("--tools") + 1] = " , "
    res = run(*args)
    assert res.exit_code == 1 and "Refused: no_tools" in res.output


@pytest.mark.parametrize("ttl", ["60", "1d", "-5m", "0m", "abc", "1.5h"])
def test_bad_ttl_is_usage_error(env, ttl):
    sign_in(env)
    args = list(CREATE)
    args[args.index("--ttl") + 1] = ttl
    res = run(*args)
    assert res.exit_code == 2 and "--ttl" in res.output
    assert env["grants"].writes == 0


@pytest.mark.parametrize("ttl, seconds", [("30s", 30), ("45m", 2700), ("4h", 14400)])
def test_parse_ttl(ttl, seconds):
    assert grant_commands.parse_ttl(ttl) == seconds


def test_store_error_exits_1_with_cause(env):
    sign_in(env)
    env["grants"].broken = True
    res = run("show", "gr_x")
    assert res.exit_code == 1 and "ResourceNotFoundException" in res.output
    assert "Traceback" not in res.output


# --- revoke / show / list ---------------------------------------------------------

def test_create_show_revoke_show(env):
    sign_in(env)
    run(*CREATE)
    gid = created_id(env)
    assert "status:          active" in run("show", gid).output
    res = run("revoke", gid)
    assert res.exit_code == 0 and f"revoked {gid}" in res.output
    assert "status:          revoked" in run("show", gid).output
    again = run("revoke", gid)
    assert again.exit_code == 0 and "already revoked" in again.output


@pytest.mark.parametrize("cmd", ["revoke", "show"])
def test_unknown_grant_exits_nonzero(env, cmd):
    # Bad case: a mistyped ID reported as revoked while the real grant stays live.
    sign_in(env)
    run(*CREATE)
    res = run(cmd, "gr_typo")
    assert res.exit_code == 1 and "no grant 'gr_typo'" in res.output
    assert env["grants"].get(created_id(env)).status == "active"


def test_other_engineer_cannot_revoke_or_show(env):
    sign_in(env)
    run(*CREATE)
    gid = created_id(env)
    sign_in(env, "erin", ("engineer",))
    res = run("revoke", gid)
    assert res.exit_code == 1 and "Refused: revoke_not_permitted" in res.output
    assert env["grants"].get(gid).status == "active"
    res = run("show", gid)
    assert res.exit_code == 1 and "Refused: not_permitted" in res.output


def test_security_admin_can_show_and_revoke_any(env):
    sign_in(env)
    run(*CREATE)
    gid = created_id(env)
    sign_in(env, "dana", ("security-admin",))
    assert run("show", gid).exit_code == 0
    assert run("revoke", gid).exit_code == 0
    assert env["grants"].get(gid).status == "revoked"


def test_list_shows_own_grants_and_filters_by_workflow(env):
    sign_in(env)
    run(*CREATE)
    a = created_id(env)
    sign_in(env, "erin", ("engineer",))
    run("create", "--agent", "agent_tester", "--workflow", "wf_other", "--tools", "get_issue",
        "--repo", "acme/demo")
    e = next(g for g in env["grants"].items if g != a)

    out = run("list").output
    assert e in out and a not in out
    sign_in(env, "dana", ("security-admin",))
    out = run("list").output
    assert e in out and a in out
    out = run("list", "--workflow", "wf_demo").output
    assert a in out and e not in out and "can lag a revoke" in out
    res = run("list", "--workflow", "wf_none")
    assert res.exit_code == 0 and "No grants in wf_none." in res.output


def test_grant_help_needs_no_config(monkeypatch):
    monkeypatch.setattr(commands, "_context", lambda: (_ for _ in ()).throw(AssertionError("loaded")))
    res = CliRunner().invoke(cli, ["grant", "--help"])
    assert res.exit_code == 0
    for sub in ("create", "revoke", "list", "show"):
        assert sub in res.output
