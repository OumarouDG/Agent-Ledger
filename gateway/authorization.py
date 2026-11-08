"""Grant authorization: decides whether a verified agent may run a tool under a grant."""

from __future__ import annotations

import time
from dataclasses import dataclass

from .grants import Grant, GrantStore, GrantStoreError

MAX_PARENT_DEPTH = 10


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    grant: Grant | None = None


def _deny(reason: str, grant: Grant | None = None) -> Decision:
    return Decision(False, reason, grant)


def _usable(grant: Grant, now: float) -> str | None:
    """Return a denial reason if this grant cannot be used, else None."""
    if grant.status != "active":
        return f"grant_{grant.status}"
    if grant.expires_at is not None and grant.expires_at <= now:
        return "grant_expired"
    return None


def authorize(store: GrantStore, *, agent_id: str | None, grant_id: str | None,
              workflow_id: str | None, tool: str, now: float | None = None) -> Decision:
    """Fail closed: any missing input, store error or doubt is a denial."""
    now = time.time() if now is None else now
    if not agent_id:
        return _deny("unknown_agent")
    if not grant_id:
        return _deny("missing_grant")
    if not workflow_id:
        return _deny("missing_workflow")
    try:
        grant = store.get(grant_id)
        if grant is None:
            return _deny("unknown_grant")
        if grant.agent_id != agent_id:
            return _deny("grant_agent_mismatch", grant)
        if grant.workflow_id != workflow_id:
            return _deny("grant_workflow_mismatch", grant)
        if (why := _usable(grant, now)):
            return _deny(why, grant)

        # A revoked, expired or inactive ancestor kills every descendant.
        seen, parent_id, depth = {grant.grant_id}, grant.parent_grant_id, 0
        while parent_id:
            depth += 1
            if parent_id in seen or depth > MAX_PARENT_DEPTH:
                return _deny("grant_chain_invalid", grant)
            seen.add(parent_id)
            parent = store.get(parent_id)
            if parent is None:
                return _deny("parent_grant_missing", grant)
            if (why := _usable(parent, now)):
                return _deny(f"parent_{why}", grant)
            parent_id = parent.parent_grant_id
    except GrantStoreError:
        return _deny("grant_store_unavailable")
    except Exception:  # an adapter bug must still be a denial, and still get audited
        return _deny("grant_store_unavailable")

    if tool not in grant.tools:
        return _deny("tool_not_permitted", grant)
    return Decision(True, "allowed", grant)
