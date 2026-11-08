"""The hash-chain proof of concept: tampering is detected, honest data verifies."""

import copy

from ledger.hashchain import heads, seal, verify_chain
from tests.ledger.helpers import accepted_workflow


def events():
    return [*accepted_workflow("wf_a", "a", 1), *accepted_workflow("wf_b", "b", 2)]


def kinds(problems):
    return sorted({p.kind for p in problems})


def test_untouched_events_verify():
    ev = events()
    assert verify_chain(ev, seal(ev)) == []


def test_chain_is_per_workflow_and_deterministic():
    ev = events()
    s = seal(ev)
    assert s == seal(copy.deepcopy(ev))
    assert {r["workflow"] for r in s} == {"wf_a", "wf_b"}
    assert [r["seq"] for r in s if r["workflow"] == "wf_a"] == list(range(1, 9))
    assert all(r["prev_hash"] == "0" * 64 for r in s if r["seq"] == 1)


def test_modified_event_is_detected():
    ev = events()
    s = seal(ev)
    ev[2]["status"] = "failed"
    assert kinds(verify_chain(ev, s)) == ["modified"]


def test_deleted_middle_event_is_detected():
    ev = events()
    s = seal(ev)
    del ev[2]
    assert "deleted" in kinds(verify_chain(ev, s))


def test_deleted_last_event_is_detected():
    ev = events()
    s = seal(ev)
    last_a = max(i for i, e in enumerate(ev) if e["workflow_id"] == "wf_a")
    del ev[last_a]
    assert kinds(verify_chain(ev, s)) == ["deleted"]


def test_reordered_events_are_detected():
    ev = events()
    s = seal(ev)
    ev[0], ev[1] = ev[1], ev[0]
    assert "out_of_order" in kinds(verify_chain(ev, s))


def test_inserted_event_is_detected():
    ev = events()
    s = seal(ev)
    extra = {**ev[0], "event_id": "evt_forged", "decision": "allow"}
    ev.insert(1, extra)
    assert "inserted" in kinds(verify_chain(ev, s))


def test_events_appended_after_sealing_are_reported_as_unsealed():
    ev = events()
    s = seal(ev)
    ev.append({**ev[0], "event_id": "evt_late"})
    assert kinds(verify_chain(ev, s)) == ["unsealed"]


def test_a_second_record_for_the_same_position_is_a_fork():
    ev = events()
    s = seal(ev)
    s.append({**s[0], "hash": "f" * 64})
    assert "fork" in kinds(verify_chain(ev, s))


def test_missing_predecessor_breaks_the_link():
    ev = events()
    s = seal(ev)
    del s[1]  # the sealed list lost a record
    assert "broken_link" in kinds(verify_chain(ev, s))


def test_stored_hash_mismatch_is_detected():
    ev = events()
    s = seal(ev)
    s[3]["hash"] = "0" * 64
    assert verify_chain(ev, s)


def test_duplicate_event_id_is_reported():
    ev = events()
    s = seal(ev)
    ev.append(copy.deepcopy(ev[0]))
    assert "duplicate_event_id" in kinds(verify_chain(ev, s))


def test_a_rewritten_pair_is_caught_only_by_a_stored_head():
    """Honest limit: someone who rewrites events AND the sealed list passes verify_chain.
    The head hash, kept somewhere they cannot reach, is what catches it."""
    ev = events()
    head = heads(seal(ev))
    ev[2]["status"] = "failed"
    forged = seal(ev)  # attacker re-seals the changed events
    assert verify_chain(ev, forged) == []  # internally consistent
    assert verify_chain(ev, forged, expected_heads=head)  # but the head moved


def test_empty_and_unknown_workflow_events_work():
    ev = [{"event_id": "evt_1", "decision": "allow"}, {"event_id": "evt_2", "decision": "deny"}]
    s = seal(ev)
    assert s[0]["workflow"] == "_none" and verify_chain(ev, s) == []
    assert verify_chain([], []) == []
