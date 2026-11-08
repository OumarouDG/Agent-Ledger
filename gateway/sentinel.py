"""Sentinel: lock a grant after repeated policy violations by the agent that holds it.

A violation is a denial where the verified agent IS the grant's agent but asked for
something the grant does not allow (a tool, a branch, a model, a missing resource).
Denials caused by a stranger (wrong agent, unknown grant) never count, so nobody can lock
another agent's grant by guessing its id.

The count is consecutive: any allowed call resets it. Counts live in memory; the lock
itself is written to a file so it survives a restart. Remove a grant's entry from the
file (or delete the file) to release it, no restart needed.

This is a gateway-local lock. Joshua's grant store has a `quarantined` status; once it
can be written, the lock should move there.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

log = logging.getLogger("agentledger.gateway.sentinel")

VIOLATION_REASONS = frozenset({
    "tool_not_permitted", "branch_not_permitted", "model_not_permitted",
    "resource_not_in_grant",
})
DEFAULT_THRESHOLD = 3


def threshold_from_env(env) -> int:
    """AGENTLEDGER_SENTINEL_THRESHOLD: denials in a row before a lock. 0 turns it off."""
    raw = env.get("AGENTLEDGER_SENTINEL_THRESHOLD")
    if raw is None or raw.strip() == "":
        return DEFAULT_THRESHOLD
    try:
        n = int(raw)
    except ValueError:
        raise ValueError("AGENTLEDGER_SENTINEL_THRESHOLD must be a whole number") from None
    if n < 0:
        raise ValueError("AGENTLEDGER_SENTINEL_THRESHOLD cannot be negative")
    return n


def default_lock_path() -> Path:
    return Path(os.environ.get("AGENTLEDGER_SENTINEL_FILE", "gateway-quarantine.json"))


class Sentinel:
    def __init__(self, lock_path: Path, threshold: int = DEFAULT_THRESHOLD):
        self._path = Path(lock_path)
        self.threshold = threshold
        self._counts: dict[str, int] = {}
        self._mem_locked: set[str] = set()  # locks that could not be written to the file
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.threshold > 0

    def is_locked(self, grant_id: str | None) -> bool:
        """True when the grant is locked. An unreadable lock file locks everything (fail closed)."""
        if not grant_id or not self.enabled:
            return False
        if grant_id in self._mem_locked:
            return True
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return grant_id in data["locked"]
        except FileNotFoundError:
            return False
        except (OSError, ValueError, KeyError, TypeError):
            log.error("sentinel lock file unreadable; treating grants as locked")
            return True

    def allowed(self, grant_id: str | None) -> None:
        """An allowed call ends the streak."""
        if grant_id and self.enabled:
            with self._lock:
                self._counts.pop(grant_id, None)

    def violation(self, grant_id: str, reason: str) -> bool:
        """Record a violation. Returns True when this one tripped the lock."""
        if not self.enabled or reason not in VIOLATION_REASONS:
            return False
        with self._lock:
            n = self._counts.get(grant_id, 0) + 1
            if n < self.threshold:
                self._counts[grant_id] = n
                return False
            self._counts.pop(grant_id, None)
        self._write_lock(grant_id, reason)
        return True

    def _write_lock(self, grant_id: str, reason: str) -> None:
        with self._lock:
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                locked = data["locked"]
                if not isinstance(locked, dict):
                    raise ValueError
            except FileNotFoundError:
                locked = {}
            except (OSError, ValueError, KeyError, TypeError):
                locked = {}  # replaced below; it was already treated as locked
            locked[grant_id] = {"since": int(time.time()), "reason": reason}
            try:
                self._path.write_text(json.dumps({"locked": locked}, sort_keys=True),
                                      encoding="utf-8")
            except OSError as e:
                self._mem_locked.add(grant_id)  # still locked until restart
                log.error("sentinel could not write the lock file: %s", type(e).__name__)
