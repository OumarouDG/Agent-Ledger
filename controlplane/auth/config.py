"""Load the shared IdP config written by infra/cognito_setup.py."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = ROOT / "shared" / "cognito.json"


@lru_cache(maxsize=1)
def load_config(path: str | None = None) -> dict:
    p = Path(path or os.environ.get("AGENTLEDGER_COGNITO_CONFIG", DEFAULT_PATH))
    if not p.exists():
        raise FileNotFoundError(f"{p} not found. Run `python infra/cognito_setup.py` first.")
    return json.loads(p.read_text())
