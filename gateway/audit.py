"""Local audit trail for gateway decisions (JSON lines).

Placeholder until the Ledger schema is agreed; keep fields minimal and never log tokens.
Denials are recorded too. If an event cannot be written, ecord raises AuditError\nand the gateway denies the call: no action is allowed without a record.
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


class AuditError(RuntimeError):
    """The audit event could not be written."""


def default_path() -> Path:
    return Path(os.environ.get("AGENTLEDGER_AUDIT_FILE", "gateway-audit.jsonl"))


def record(path: Path, **fields: Any) -> dict:
    event = {"ts": int(time.time()), **fields}
    try:
        with _lock, path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
    except (OSError, TypeError, ValueError) as e:  # unwritable path, or a field that is not JSON
        log.error("audit write failed: %s", type(e).__name__)
        raise AuditError("audit unavailable") from e
    return event
