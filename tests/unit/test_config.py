"""Offline tests for loading shared/cognito.json, and a check that it holds no secrets."""

import json
import re
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


# --- shared/cognito.json must hold no secrets --------------------------------

# Keys that look secret-ish by name but hold only references or modes.
ALLOWED_KEYS = {"secret_ref", "token_mode"}
SECRET_KEY = re.compile(r"secret|password|passwd|token|private|credential|api[_-]?key", re.I)
SECRET_VALUE_PATTERNS = {
    "jwt": re.compile(r"eyJ[\w-]+\.[\w-]+\."),
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    "pem_block": re.compile(r"-----BEGIN [A-Z ]+-----"),
    "demo_password": re.compile(r"\bAl[A-Za-z0-9]{14}9!"),  # infra/cognito_setup.py make_password()
}
# Cognito client secrets are ~51 chars; client IDs are 26. Anything this long that isn't a URL is suspect.
LONG_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")
SECRET_REF = re.compile(r"^(secretsmanager|local):[\w/+=.@-]+$")


def find_secrets(node, path: str = "$") -> list[str]:
    """Return a list of 'path: reason' for anything in a parsed config that looks like a secret."""
    hits: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}"
            if k not in ALLOWED_KEYS and SECRET_KEY.search(k):
                hits.append(f"{p}: key name looks secret")
            if k == "secret_ref" and not (isinstance(v, str) and SECRET_REF.match(v)):
                hits.append(f"{p}: secret_ref is not a secretsmanager:/local: reference")
            hits += find_secrets(v, p)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += find_secrets(v, f"{path}[{i}]")
    elif isinstance(node, str):
        for name, pat in SECRET_VALUE_PATTERNS.items():
            if pat.search(node):
                hits.append(f"{path}: value matches {name}")
        if LONG_OPAQUE.match(node):
            hits.append(f"{path}: long opaque value")
    return hits


def test_shared_cognito_json_has_no_secrets():
    if not config.DEFAULT_PATH.exists():
        pytest.skip("shared/cognito.json not generated yet: run python infra/cognito_setup.py")
    cfg = json.loads(config.DEFAULT_PATH.read_text(encoding="utf-8"))
    assert cfg["agents"], "no agents in shared/cognito.json"
    assert find_secrets(cfg) == []


def test_find_secrets_passes_a_clean_config():
    clean = {
        "issuer": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST",
        "cli": {"client_id": "abcdefghijklmnopqrstuvwxyz"},
        "agents": {"agent_coder": {"client_id": "abcdefghijklmnopqrstuvwxyz",
                                   "secret_ref": "secretsmanager:agentledger/agents/agent_coder",
                                   "token_mode": "get_client_token",
                                   "scopes": ["agentledger/tools"]}},
    }
    assert find_secrets(clean) == []


# Each fake must be caught, so the real-file check above can't pass by being blind.
@pytest.mark.parametrize("bad, expect", [
    ({"agents": {"a": {"client_secret": "x"}}}, "key name looks secret"),
    ({"users": {"alice": {"password": "x"}}}, "key name looks secret"),
    ({"access_token": "x"}, "key name looks secret"),
    ({"note": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"}, "jwt"),
    ({"note": "ASIA" + "A" * 16}, "aws_access_key_id"),
    ({"note": "-----BEGIN PRIVATE KEY-----"}, "pem_block"),
    ({"note": "Al" + "x" * 14 + "9!"}, "demo_password"),
    ({"agents": {"a": {"client_id": "a" * 51}}}, "long opaque value"),
    ({"agents": {"a": {"secret_ref": "fake-raw-secret-in-the-ref-field"}}}, "not a secretsmanager:/local: reference"),
    ({"agents": {"a": {"secret_ref": None}}}, "not a secretsmanager:/local: reference"),
    ({"list": [{"nested": ["ok", "eyJa.eyJb.c"]}]}, "jwt"),
])
def test_find_secrets_catches_fakes(bad, expect):
    hits = find_secrets(bad)
    assert any(expect in h for h in hits), hits
