"""CLI-1: token storage in the OS credential store (in-memory keyring here). Offline."""

from __future__ import annotations

import builtins
import io
import json
import os

import pytest

from agentledger.storage import (CHUNK_CHARS, SERVICE, StorageError, StoredSessionCorrupt,
                                 TokenStore)

from .conftest import CFG, FAKE_TOKENS

POOL = CFG["user_pool_id"]
WINDOWS_ENTRY_CHARS = 1280  # 2560-byte blob limit, UTF-16


def stored_tokens() -> dict:
    return {k: FAKE_TOKENS[k] for k in ("id_token", "access_token", "refresh_token")}


def big_tokens(n: int = 4096) -> dict:
    return {"id_token": "I" * n, "access_token": "A" * 1200, "refresh_token": "R" * 1800}


# --- happy path -------------------------------------------------------------

def test_round_trip(mem):
    store = TokenStore(POOL)
    store.save(FAKE_TOKENS)
    assert store.load() == stored_tokens()  # expires_in / token_type are not stored


def test_round_trip_without_refresh_token(mem):
    store = TokenStore(POOL)
    store.save({"id_token": "fake-id", "access_token": "fake-access"})
    assert store.load() == {"id_token": "fake-id", "access_token": "fake-access"}


def test_4kb_token_is_split_and_rejoined(mem):
    store = TokenStore(POOL)
    tokens = big_tokens()
    store.save(tokens)
    entries = {u: v for (s, u), v in mem.data.items() if s == SERVICE}
    chunks = [u for u in entries if u.startswith(f"{POOL}#")]
    assert len(chunks) >= 7  # ~7.1 KB payload / 1000 chars
    assert max(len(v) for v in entries.values()) <= CHUNK_CHARS < WINDOWS_ENTRY_CHARS
    assert json.loads(entries[POOL])["chunks"] == len(chunks)
    assert store.load() == tokens


def test_entries_are_keyed_by_pool_and_do_not_collide(mem):
    a, b = TokenStore("us-east-1_POOLA"), TokenStore("us-east-1_POOLB")
    a.save({"id_token": "id-a", "access_token": "acc-a"})
    b.save({"id_token": "id-b", "access_token": "acc-b"})
    assert a.load()["id_token"] == "id-a" and b.load()["id_token"] == "id-b"
    assert all(s == SERVICE for s, _ in mem.data)


def test_nothing_stored_means_not_signed_in(mem):
    assert TokenStore(POOL).load() is None


def test_smaller_save_removes_stale_chunks(mem):
    store = TokenStore(POOL)
    store.save(big_tokens())
    store.save(FAKE_TOKENS)
    assert sorted(u for _, u in mem.data) == [POOL, f"{POOL}#0"]
    assert store.load() == stored_tokens()


def test_delete_removes_every_entry(mem):
    store = TokenStore(POOL)
    store.save(big_tokens())
    n = len(mem.data)
    assert store.delete() == n
    assert mem.data == {}
    assert store.load() is None
    assert store.delete() == 0  # second delete is a no-op, not an error


# --- corrupt or partial entries ----------------------------------------------

@pytest.mark.parametrize("manifest", [
    "not json", "[]", "{}", '{"v": 2, "chunks": 1, "sha256": "x"}',
    '{"v": 1, "chunks": 0, "sha256": "x"}', '{"v": 1, "chunks": true, "sha256": "x"}',
    '{"v": 1, "chunks": 999, "sha256": "x"}', '{"v": 1, "chunks": 1}',
])
def test_corrupt_manifest_says_run_login(mem, manifest):
    store = TokenStore(POOL)
    store.save(FAKE_TOKENS)
    mem.data[(SERVICE, POOL)] = manifest
    with pytest.raises(StoredSessionCorrupt, match="run agentledger login"):
        store.load()


def test_missing_chunk_says_run_login(mem):
    store = TokenStore(POOL)
    store.save(big_tokens())
    del mem.data[(SERVICE, f"{POOL}#2")]
    with pytest.raises(StoredSessionCorrupt, match="part 2 missing.*run agentledger login"):
        store.load()


def test_tampered_chunk_fails_integrity_check(mem):
    # Same length, still valid JSON once rejoined: only the hash catches it.
    store = TokenStore(POOL)
    store.save(big_tokens())
    key = (SERVICE, f"{POOL}#1")
    mem.data[key] = mem.data[key].replace("I", "X")
    with pytest.raises(StoredSessionCorrupt, match="integrity check.*run agentledger login"):
        store.load()


def test_payload_that_is_not_a_token_bundle_is_rejected(mem):
    import hashlib
    payload = json.dumps({"id_token": 5, "access_token": "a"})
    mem.data[(SERVICE, f"{POOL}#0")] = payload
    mem.data[(SERVICE, POOL)] = json.dumps({"v": 1, "chunks": 1,
                                            "sha256": hashlib.sha256(payload.encode()).hexdigest()})
    with pytest.raises(StoredSessionCorrupt, match="missing tokens"):
        TokenStore(POOL).load()


def test_interrupted_save_is_not_read_as_a_session(mem):
    # New chunks written, manifest write fails: load must not return old + new mixed.
    store = TokenStore(POOL)
    store.save(big_tokens())
    mem.fail_set_on = POOL
    with pytest.raises(StorageError, match="Can't write"):
        store.save(big_tokens(5000))
    with pytest.raises(StoredSessionCorrupt):
        store.load()


def test_delete_cleans_up_after_corrupt_manifest(mem):
    store = TokenStore(POOL)
    store.save(big_tokens())
    mem.data[(SERVICE, POOL)] = "garbage"
    store.delete()
    assert mem.data == {}


def test_corrupt_errors_do_not_contain_token_values(mem):
    store = TokenStore(POOL)
    store.save(FAKE_TOKENS)
    mem.data[(SERVICE, f"{POOL}#0")] += "x"
    with pytest.raises(StoredSessionCorrupt) as e:
        store.load()
    for v in stored_tokens().values():
        assert v not in str(e.value)


# --- refusals and backend failures --------------------------------------------

@pytest.mark.parametrize("tokens", [
    {}, {"id_token": "fake-id"}, {"access_token": "fake-access"},
    {"id_token": "", "access_token": "fake-access"}, {"id_token": 5, "access_token": "fake-access"},
])
def test_refuses_to_store_without_id_and_access_token(mem, tokens):
    with pytest.raises(StorageError, match="Refusing to store"):
        TokenStore(POOL).save(tokens)
    assert mem.data == {}


@pytest.mark.parametrize("pool", ["", "   ", None])
def test_empty_pool_id_rejected(pool):
    with pytest.raises(ValueError, match="user_pool_id"):
        TokenStore(pool)


def test_unreadable_backend_names_the_credential_store(mem):
    mem.fail_reads = True
    with pytest.raises(StorageError, match="OS credential store") as e:
        TokenStore(POOL).load()
    assert e.value.__cause__ is None and e.value.__suppress_context__


# --- never a token file -------------------------------------------------------

def _refuse_disk_writes(monkeypatch):
    real_open, real_os_open = builtins.open, os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND

    def guarded_open(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            raise AssertionError(f"wrote to disk: {file!r} mode {mode!r}")
        return real_open(file, mode, *a, **k)

    def guarded_os_open(path, flags, *a, **k):
        if flags & write_flags:
            raise AssertionError(f"wrote to disk: {path!r}")
        return real_os_open(path, flags, *a, **k)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_open)
    monkeypatch.setattr(os, "open", guarded_os_open)


def test_guard_catches_a_file_write(monkeypatch, tmp_path):
    # Control: the guard below really does catch a write.
    _refuse_disk_writes(monkeypatch)
    with pytest.raises(AssertionError, match="wrote to disk"):
        (tmp_path / "tokens.json").write_text("x")


def test_save_load_delete_write_nothing_to_disk(mem, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _refuse_disk_writes(monkeypatch)
    store = TokenStore(POOL)
    store.save(big_tokens())
    assert store.load() == big_tokens()
    store.delete()
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []
