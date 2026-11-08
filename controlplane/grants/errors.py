"""Errors raised by the grant service. Messages are safe to print: no tokens, no secrets."""

from __future__ import annotations

from gateway.grants import GrantStoreError

__all__ = ["GrantError", "GrantNotFound", "GrantRefused", "GrantStoreError"]


class GrantError(Exception):
    """Base for grant service errors that are the caller's fault, not the store's."""


class GrantRefused(GrantError):
    """A create or revoke request broke a rule. `reason` is a stable code; nothing was written."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class GrantNotFound(GrantError):
    """No grant with this ID. Revoking an unknown or mistyped ID is an error, not a success."""

    def __init__(self, grant_id: str):
        self.grant_id = grant_id
        super().__init__(f"no grant {grant_id!r}; check the ID with `agentledger grant list`")
