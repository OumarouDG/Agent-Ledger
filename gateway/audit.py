"""Local audit trail for gateway decisions (JSON lines).

Placeholder until the Ledger schema is agreed; keep fields minimal and never log tokens.
Denials are recorded too. A write failure is logged, not raised.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("agentledger.gateway.audit")
_lock = threading.Lock()


def default_path() -> Path:
    return Path(os.environ.get("AGENTLEDGER_AUDIT_FILE", "gateway-audit.jsonl"))


def record(path: Path, **fields: Any) -> dict:
    event = {"ts": int(time.time()), **fields}
    try:
        with _lock, path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
    except OSError as e:
        log.error("audit write failed: %s", type(e).__name__)
    return event
