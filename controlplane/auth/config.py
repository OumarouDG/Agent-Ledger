"""Load the shared IdP config written by infra/cognito_setup.py."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = ROOT / "shared" / "cognito.json"
ENV_VAR = "AGENTLEDGER_COGNITO_CONFIG"


def config_path(path: str | None = None) -> Path:
    """Explicit path, else AGENTLEDGER_COGNITO_CONFIG (if non-empty), else shared/cognito.json."""
    return Path(path or os.environ.get(ENV_VAR) or DEFAULT_PATH).resolve()


def load_config(path: str | None = None) -> dict:
    # The path is resolved on every call, so a changed env var is seen; each file is read once.
    return _load(str(config_path(path)))


@lru_cache(maxsize=8)
def _load(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"{p} not found. Run `python infra/cognito_setup.py` first.")
    return json.loads(p.read_text(encoding="utf-8"))


load_config.cache_clear = _load.cache_clear  # type: ignore[attr-defined]
