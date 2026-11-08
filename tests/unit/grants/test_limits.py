"""Grant limits the gateway's tools read: branch_prefix, base_branch, models, max_tokens.

Rules: a bad value is refused, never trimmed; a child may not widen its parent. The last tests
run a stored grant through the gateway's own checks to show the two halves agree."""

from __future__ import annotations

from decimal import Decimal

import pytest
from click.testing import CliRunner

from agentledger import grant_commands
from agentledger.main import cli
from controlplane.grants.service import MAX_MODELS, GrantRequest, create_grant
from gateway.llm import DEFAULT_MAX_TOKENS, HARD_MAX_TOKENS, effective_max_tokens
from tests.unit.grants.test_grant_commands import CREATE, env, run, sign_in  # noqa: F401
from tests.unit.grants.test_service import (
    AGENTS, ALICE, NOW, FakeStore, child_req, make_child, make_root, refused, root_req,
)

MODEL = "us.amazon.nova-lite-v1:0"
OTHER = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
LIMITS = dict(branch_prefix="agentledger/wf_t/", models=frozenset({MODEL, OTHER}), max_tokens=500,
              base_branch="main", delegable_tools=frozenset({"commit_file", "llm_converse"}))


@pytest.fixture
def store():
    return FakeStore()


def test_limits_are_stored_in_resources_and_nothing_extra(store):
    g = make_root(store, **LIMITS)
    assert g.resources == {"repository": "acme/demo", "branch_prefix": "agentledger/wf_t/",
                           "base_branch": "main", "models": sorted([MODEL, OTHER]),
                           "max_tokens": 500}


def test_a_grant_without_limits_stores_only_the_repository(store):
    assert make_root(store).resources == {"repository": "acme/demo"}


@pytest.mark.parametrize("prefix", ["", "agentledger", "agentledger/wf", "/x/", "a//b/", "a/../b/",
                                    "./", "a/./b/", "a b/", "a;b/", "x.lock/", 5])
def test_bad_branch_prefix_is_refused(store, prefix):
    refused("bad_branch_prefix", make_root, store, branch_prefix=prefix)
    assert store.writes == 0


@pytest.mark.parametrize("base", ["", "a b", "../x", "a//b", "x.lock", "a" * 101, 5])
def test_bad_base_branch_is_refused(store, base):
    refused("bad_base_branch", make_root, store, base_branch=base)


@pytest.mark.parametrize("models", [frozenset({""}), frozenset({"a b"}), frozenset({"a;b"}),
                                    frozenset({f"m{i}" for i in range(MAX_MODELS + 1)}),
                                    {"not-a-frozenset"}, frozenset({5})])
def test_bad_models_are_refused(store, models):
    refused("bad_models", make_root, store, models=models)


@pytest.mark.parametrize("tokens", [0, -1, HARD_MAX_TOKENS + 1, 2.5, "500", True])
def test_bad_max_tokens_is_refused(store, tokens):
    refused("bad_max_tokens", make_root, store, max_tokens=tokens)


def test_the_hard_cap_itself_is_allowed(store):
    assert make_root(store, max_tokens=HARD_MAX_TOKENS).resources["max_tokens"] == HARD_MAX_TOKENS


# --- children may not widen the parent ----------------------------------------------------

def test_child_inside_every_limit_is_allowed(store):
    parent = make_root(store, **LIMITS)
    child = make_child(store, parent, branch_prefix="agentledger/wf_t/coder/",
                       models=frozenset({MODEL}), max_tokens=100, base_branch="main")
    assert child.resources["branch_prefix"] == "agentledger/wf_t/coder/"
    assert child.resources["models"] == [MODEL] and child.resources["max_tokens"] == 100


def test_child_may_omit_limits_which_only_narrows_it(store):
    parent = make_root(store, **LIMITS)
    assert make_child(store, parent).resources == {"repository": "acme/demo"}


@pytest.mark.parametrize("kw", [
    {"branch_prefix": "other/"},                     # outside the parent's prefix
    {"branch_prefix": "agentledger/"},               # wider than the parent's prefix
    {"models": frozenset({"anthropic.claude-opus-5"})},   # a model the parent does not have
    {"models": frozenset({MODEL, "anthropic.claude-opus-5"})},
    {"max_tokens": 501},                             # above the parent's cap
    {"base_branch": "release"},                      # a different base
])
def test_child_asking_for_more_is_refused_not_trimmed(store, kw):
    parent = make_root(store, **LIMITS)
    before = store.writes
    refused("resource_escalation", make_child, store, parent, **kw)
    assert store.writes == before


def test_child_cannot_add_limits_the_parent_does_not_have(store):
    parent = make_root(store)  # no prefix, no models
    refused("resource_escalation", make_child, store, parent, branch_prefix="agentledger/wf_t/")
    refused("resource_escalation", make_child, store, parent, models=frozenset({MODEL}))
    refused("resource_escalation", make_child, store, parent, base_branch="main")


def test_parent_without_a_token_cap_means_the_gateway_default(store):
    parent = make_root(store)
    make_child(store, parent, max_tokens=DEFAULT_MAX_TOKENS)  # equal is fine
    refused("resource_escalation", make_child, store, parent, max_tokens=DEFAULT_MAX_TOKENS + 1)


def test_child_prefix_must_not_just_share_a_text_start(store):
    parent = make_root(store, **{**LIMITS, "branch_prefix": "agentledger/wf_t/"})
    refused("resource_escalation", make_child, store, parent, branch_prefix="agentledger/wf_tx/")


# --- the stored grant and the gateway agree -------------------------------------------------

def test_decimal_numbers_from_dynamodb_still_cap_replies(store):
    g = make_root(store, **LIMITS)
    from_dynamo = Decimal(str(g.resources["max_tokens"]))  # what the deserializer returns
    assert effective_max_tokens(from_dynamo) == 500


def test_gateway_check_for_branches_uses_the_stored_prefix(store):
    from gateway.github import valid_branch

    g = make_root(store, **LIMITS)
    prefix = g.resources["branch_prefix"]
    assert valid_branch(prefix + "feat") and ("agentledger/wf_t/feat").startswith(prefix)
    assert not "main".startswith(prefix)


# --- the CLI -------------------------------------------------------------------------------

def test_cli_creates_a_grant_with_every_limit(env):
    sign_in(env)
    r = run(*CREATE, "--tools", "create_branch,llm_converse", "--branch-prefix", "agentledger/wf_demo/",
            "--model", MODEL, "--model", OTHER, "--max-tokens", "300", "--base-branch", "main")
    assert r.exit_code == 0, r.output
    g = next(iter(env["grants"].items.values()))["grant"]
    assert g.resources["branch_prefix"] == "agentledger/wf_demo/"
    assert g.resources["models"] == sorted([MODEL, OTHER]) and g.resources["max_tokens"] == 300
    assert "branch_prefix:" in r.output and "max_tokens:" in r.output and MODEL in r.output


def test_cli_without_limits_still_works_and_shows_defaults(env):
    sign_in(env)
    r = run(*CREATE)
    assert r.exit_code == 0, r.output
    assert "(none)" in r.output and "default" in r.output


def test_cli_refuses_a_bad_prefix_and_writes_nothing(env):
    sign_in(env)
    r = run(*CREATE, "--branch-prefix", "agentledger")
    assert r.exit_code == 1 and "bad_branch_prefix" in r.output
    assert not env["grants"].items


def test_cli_refuses_too_many_tokens(env):
    sign_in(env)
    r = run(*CREATE, "--max-tokens", str(HARD_MAX_TOKENS + 1))
    assert r.exit_code == 1 and "bad_max_tokens" in r.output
