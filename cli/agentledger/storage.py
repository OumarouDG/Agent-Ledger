"""Store CLI tokens in the OS credential store via `keyring`. Never writes a token file.

Layout under service `agentledger`, keyed by Cognito user pool ID:

    <pool_id>            manifest: {"v": 1, "chunks": n, "sha256": <hex of payload>}
    <pool_id>#0 .. #n-1  the JSON token bundle, split into chunks

Windows Credential Manager caps one entry at 2560 bytes (CRED_MAX_CREDENTIAL_BLOB_SIZE),
and keyring stores the value as UTF-16, so one entry holds at most 1280 characters.
A Cognito ID token alone can pass that, hence the split.

Chunks are written before the manifest, so an interrupted save is caught on load by
the hash check instead of returning a half-written bundle.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE = "agentledger"
CHUNK_CHARS = 1000  # under the 1280-character Windows limit, with margin
MAX_CHUNKS = 64  # 64,000 characters; a Cognito bundle is a few KB
FORMAT_VERSION = 1
TOKEN_KEYS = ("id_token", "access_token", "refresh_token")
RELOGIN = "run agentledger login"


class StorageError(Exception):
    """Credential store unusable or stored sign-in unreadable. Message is safe to print."""


class StoredSessionCorrupt(StorageError):
    pass


class TokenStore:
    def __init__(self, pool_id: str, backend: Any = None, service: str = SERVICE):
        if not isinstance(pool_id, str) or not pool_id.strip():
            raise ValueError("TokenStore needs a user pool ID. Check user_pool_id in shared/cognito.json.")
        self.pool_id = pool_id
        self.service = service
        self._backend = backend

    @classmethod
    def for_config(cls, cfg: dict, backend: Any = None) -> "TokenStore":
        return cls(cfg.get("user_pool_id", ""), backend=backend)

    @property
    def backend(self) -> Any:
        return self._backend if self._backend is not None else keyring.get_keyring()

    def _chunk_key(self, i: int) -> str:
        return f"{self.pool_id}#{i}"

    # --- save -------------------------------------------------------------

    def save(self, tokens: dict) -> None:
        """Store id, access and (if present) refresh token. Other fields are dropped."""
        bundle = {k: tokens[k] for k in TOKEN_KEYS if tokens.get(k)}
        for k in ("id_token", "access_token"):
            if not isinstance(bundle.get(k), str):
                raise StorageError(f"Refusing to store a sign-in without {k}; {RELOGIN}.")
        payload = json.dumps(bundle, separators=(",", ":"), sort_keys=True)
        chunks = [payload[i:i + CHUNK_CHARS] for i in range(0, len(payload), CHUNK_CHARS)]
        if len(chunks) > MAX_CHUNKS:
            raise StorageError(f"Token bundle is {len(payload)} characters, over the "
                               f"{MAX_CHUNKS * CHUNK_CHARS} limit; not stored.")
        old_count = self._manifest_count()
        manifest = json.dumps({"v": FORMAT_VERSION, "chunks": len(chunks),
                               "sha256": hashlib.sha256(payload.encode()).hexdigest()})
        try:
            for i, chunk in enumerate(chunks):
                self.backend.set_password(self.service, self._chunk_key(i), chunk)
            self.backend.set_password(self.service, self.pool_id, manifest)
        except KeyringError as e:
            raise StorageError(f"Can't write to the OS credential store ({type(e).__name__}). "
                               "Check that Windows Credential Manager / Keychain is available.") from None
        for i in range(len(chunks), old_count):
            self._delete_quietly(self._chunk_key(i))

    # --- load -------------------------------------------------------------

    def load(self) -> dict | None:
        """Return the token bundle, None if nothing is stored, or raise StoredSessionCorrupt."""
        raw = self._get(self.pool_id)
        if raw is None:
            return None
        manifest = self._parse_manifest(raw)
        parts = []
        for i in range(manifest["chunks"]):
            part = self._get(self._chunk_key(i))
            if part is None:
                raise StoredSessionCorrupt(f"Stored sign-in is incomplete (part {i} missing); {RELOGIN}.")
            parts.append(part)
        payload = "".join(parts)
        if hashlib.sha256(payload.encode()).hexdigest() != manifest["sha256"]:
            raise StoredSessionCorrupt(f"Stored sign-in failed its integrity check; {RELOGIN}.")
        try:
            bundle = json.loads(payload)
        except ValueError:
            raise StoredSessionCorrupt(f"Stored sign-in is unreadable; {RELOGIN}.") from None
        if not isinstance(bundle, dict) or not all(isinstance(bundle.get(k), str)
                                                   for k in ("id_token", "access_token")):
            raise StoredSessionCorrupt(f"Stored sign-in is missing tokens; {RELOGIN}.")
        return bundle

    def _parse_manifest(self, raw: str) -> dict:
        try:
            m = json.loads(raw)
        except ValueError:
            m = None
        if (not isinstance(m, dict) or m.get("v") != FORMAT_VERSION
                or not isinstance(m.get("chunks"), int) or isinstance(m.get("chunks"), bool)
                or not 1 <= m["chunks"] <= MAX_CHUNKS or not isinstance(m.get("sha256"), str)):
            raise StoredSessionCorrupt(f"Stored sign-in is unreadable; {RELOGIN}.")
        return m

    def _manifest_count(self) -> int:
        try:
            return self._parse_manifest(self._get(self.pool_id) or "")["chunks"]
        except StorageError:
            return 0

    def _get(self, key: str) -> str | None:
        try:
            return self.backend.get_password(self.service, key)
        except KeyringError as e:
            raise StorageError(f"Can't read the OS credential store ({type(e).__name__}). "
                               "Check that Windows Credential Manager / Keychain is available.") from None

    # --- delete -----------------------------------------------------------

    def delete(self) -> int:
        """Delete the manifest and every possible chunk, so a corrupt manifest or an
        interrupted save leaves nothing behind. Returns the number of entries deleted."""
        deleted = sum(self._delete_quietly(self._chunk_key(i)) for i in range(MAX_CHUNKS))
        return deleted + self._delete_quietly(self.pool_id)

    def _delete_quietly(self, key: str) -> int:
        try:
            self.backend.delete_password(self.service, key)
            return 1
        except PasswordDeleteError:
            return 0
