"""Grant lookup for the gateway.

`GrantStore` is the seam for Joshua's grant service, which does not exist yet. Until it
does, `JsonFileGrantStore` serves grants from a local file for development and tests.
It is NOT the authoritative store: swap it for the real service, keep the interface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class Grant:
    grant_id: str
    agent_id: str
    workflow_id: str
    human_id: str | None = None
    status: str = "active"  # active | revoked | quarantined
    expires_at: int | None = None  # unix seconds; None = no expiry
    parent_grant_id: str | None = None
    tools: frozenset[str] = frozenset()  # tools the agent may EXECUTE
    delegable_tools: frozenset[str] = frozenset()  # tools it may hand on; never implies execute
    resources: dict[str, Any] = field(default_factory=dict)


class GrantStore(Protocol):
    def get(self, grant_id: str) -> Grant | None: ...


class GrantStoreError(RuntimeError):
    """The store could not be read. Callers must treat this as a denial."""


class JsonFileGrantStore:
    """Dev store. Re-reads the file on every lookup so a revoke applies to the next request."""

    def __init__(self, path: str | Path):
        self._path = Path(path)

    def get(self, grant_id: str) -> Grant | None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            raw = data["grants"].get(grant_id)
            if raw is None:
                return None
            return Grant(
                grant_id=grant_id,
                agent_id=raw["agent_id"],
                workflow_id=raw["workflow_id"],
                human_id=raw.get("human_id"),
                status=raw.get("status", "active"),
                expires_at=raw.get("expires_at"),
                parent_grant_id=raw.get("parent_grant_id"),
                tools=frozenset(raw.get("tools", [])),
                delegable_tools=frozenset(raw.get("delegable_tools", [])),
                resources=dict(raw.get("resources", {})),
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            raise GrantStoreError(f"grant store unreadable: {type(e).__name__}") from e
