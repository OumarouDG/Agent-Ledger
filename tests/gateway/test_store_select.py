"""Grant store selection: explicit, and never a silent fallback."""

import sys
import types

import pytest

from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from gateway.store_select import GrantStoreConfigError, build_grant_store
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier


class FakeStore:
    def get(self, grant_id):
        return None


def fake_module(monkeypatch, **attrs):
    mod = types.ModuleType("controlplane.grants")
    for k, v in attrs.items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, "controlplane.grants", mod)


def test_default_and_json_use_the_file_store(tmp_path):
    for env in ({}, {"AGENTLEDGER_GRANT_STORE": "json"}, {"AGENTLEDGER_GRANT_STORE": " JSON "}):
        assert isinstance(build_grant_store(env), JsonFileGrantStore)


def test_json_store_uses_the_configured_file(tmp_path):
    f = tmp_path / "g.json"
    f.write_text('{"grants": {}}')
    store = build_grant_store({"AGENTLEDGER_GRANTS_FILE": str(f)})
    assert store.get("nope") is None


def test_dynamodb_uses_store_from_env(monkeypatch):
    fake_module(monkeypatch, store_from_env=lambda: FakeStore())
    assert isinstance(build_grant_store({"AGENTLEDGER_GRANT_STORE": "dynamodb"}), FakeStore)


def test_dynamodb_module_missing_does_not_fall_back(monkeypatch):
    monkeypatch.setitem(sys.modules, "controlplane.grants", None)  # import raises
    with pytest.raises(GrantStoreConfigError, match="failed to load"):
        build_grant_store({"AGENTLEDGER_GRANT_STORE": "dynamodb"})


def test_dynamodb_store_error_does_not_fall_back(monkeypatch):
    def boom():
        raise RuntimeError("no table")
    fake_module(monkeypatch, store_from_env=boom)
    with pytest.raises(GrantStoreConfigError, match="no table"):
        build_grant_store({"AGENTLEDGER_GRANT_STORE": "dynamodb"})


def test_store_without_get_is_refused(monkeypatch):
    fake_module(monkeypatch, store_from_env=lambda: object())
    with pytest.raises(GrantStoreConfigError, match="get"):
        build_grant_store({"AGENTLEDGER_GRANT_STORE": "dynamodb"})


def test_unknown_mode_is_refused():
    with pytest.raises(GrantStoreConfigError, match="unknown"):
        build_grant_store({"AGENTLEDGER_GRANT_STORE": "redis"})


def test_gateway_refuses_to_start_when_the_store_cannot_load(monkeypatch):
    monkeypatch.setenv("AGENTLEDGER_GRANT_STORE", "dynamodb")
    monkeypatch.setitem(sys.modules, "controlplane.grants", None)
    with pytest.raises(gw.GatewayConfigError, match="failed to load"):
        gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS)
