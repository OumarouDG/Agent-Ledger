"""Offline tests for loading shared/cognito.json."""

import json
from pathlib import Path

import pytest

from controlplane.auth import config
from controlplane.auth.config import load_config


@pytest.fixture(autouse=True)
def fresh_cache():
    load_config.cache_clear()
    yield
    load_config.cache_clear()


def test_missing_file_names_setup_script(tmp_path, monkeypatch):
    missing = tmp_path / "nope" / "cognito.json"
    monkeypatch.setenv("AGENTLEDGER_COGNITO_CONFIG", str(missing))
    with pytest.raises(FileNotFoundError) as e:
        load_config()
    msg = str(e.value)
    assert str(missing) in msg
    assert "infra/cognito_setup.py" in msg


def test_missing_default_file_names_setup_script(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTLEDGER_COGNITO_CONFIG", raising=False)
    monkeypatch.setattr(config, "DEFAULT_PATH", tmp_path / "shared" / "cognito.json")
    with pytest.raises(FileNotFoundError) as e:
        load_config()
    assert "infra/cognito_setup.py" in str(e.value)


def test_env_override_is_used(tmp_path, monkeypatch):
    p = tmp_path / "custom.json"
    p.write_text(json.dumps({"region": "us-east-1", "issuer": "https://example.test/pool"}))
    monkeypatch.setenv("AGENTLEDGER_COGNITO_CONFIG", str(p))
    # Default path must not be consulted when the override is set.
    monkeypatch.setattr(config, "DEFAULT_PATH", tmp_path / "default-does-not-exist.json")
    cfg = load_config()
    assert cfg["issuer"] == "https://example.test/pool"


def test_explicit_path_beats_env(tmp_path, monkeypatch):
    env_file = tmp_path / "env.json"
    env_file.write_text(json.dumps({"source": "env"}))
    arg_file = tmp_path / "arg.json"
    arg_file.write_text(json.dumps({"source": "arg"}))
    monkeypatch.setenv("AGENTLEDGER_COGNITO_CONFIG", str(env_file))
    assert load_config(str(arg_file))["source"] == "arg"


def test_default_path_points_at_shared_cognito_json():
    assert config.DEFAULT_PATH == Path(config.ROOT) / "shared" / "cognito.json"
