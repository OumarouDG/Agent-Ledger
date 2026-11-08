"""Proof of concept: a per-workflow hash chain over audit events. Opt-in and read-only.

This does NOT replace gateway/audit.py and is not on the live path. It builds a separate
"sealed" list from events that already exist, and checks a list of events against it.

What it can detect, given a sealed copy that was kept safe: an event changed, deleted, moved,
inserted, duplicated, or a second record claiming the same position (a fork).

What it cannot do: prove the events were honest BEFORE they were sealed, or stop someone who
can rewrite both the events and the sealed list. For that, keep the head hash somewhere the
writer cannot reach (for example a restricted S3 Object Lock bucket). Nothing here does that.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

SCHEMA = 1
GENESIS = "0" * 64
NO_WORKFLOW = "_none"


def canonical(event: dict) -> str:
    """Stable text for an event: sorted keys, no spaces."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(event: dict, prev: str, seq: int, workflow: str) -> str:
    body = f"{SCHEMA}|{workflow}|{seq}|{prev}|{canonical(event)}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _wf(event: dict) -> str:
    return event.get("workflow_id") or NO_WORKFLOW


def seal(events: Iterable[dict]) -> list[dict]:
    """One sealed record per event, chained inside its workflow. Input order is the order."""
    prev: dict[str, str] = {}
    count: dict[str, int] = {}
    out = []
    for e in events:
        wf = _wf(e)
        seq = count.get(wf, 0) + 1
        p = prev.get(wf, GENESIS)
        h = _digest(e, p, seq, wf)
        out.append({"schema": SCHEMA, "workflow": wf, "seq": seq, "event_id": e.get("event_id"),
                    "prev_hash": p, "hash": h})
        prev[wf], count[wf] = h, seq
    return out


def heads(sealed: Iterable[dict]) -> dict[str, str]:
    """The last hash of each workflow. Store these somewhere the event writer cannot change."""
    out: dict[str, str] = {}
    for r in sealed:
        out[r["workflow"]] = r["hash"]
    return out


@dataclass(frozen=True)
class Problem:
    kind: str  # modified | deleted | inserted | unsealed | fork | broken_link | out_of_order | duplicate_event_id | bad_schema
    workflow: str
    seq: int | None
    event_id: str | None

    def __str__(self) -> str:
        return f"{self.kind}: workflow {self.workflow}, seq {self.seq}, event {self.event_id}"


def verify_chain(events: list[dict], sealed: list[dict],
                 expected_heads: dict[str, str] | None = None) -> list[Problem]:
    """Compare events with their sealed records. An empty list means they agree."""
    problems: list[Problem] = []
    by_wf_events: dict[str, list[dict]] = {}
    seen_ids: set[str] = set()
    for e in events:
        eid = e.get("event_id")
        if eid in seen_ids:
            problems.append(Problem("duplicate_event_id", _wf(e), None, eid))
        seen_ids.add(eid)
        by_wf_events.setdefault(_wf(e), []).append(e)

    by_wf_sealed: dict[str, list[dict]] = {}
    for r in sealed:
        if r.get("schema") != SCHEMA:
            problems.append(Problem("bad_schema", r.get("workflow", "?"), r.get("seq"), r.get("event_id")))
            continue
        by_wf_sealed.setdefault(r["workflow"], []).append(r)

    for wf in sorted(set(by_wf_events) | set(by_wf_sealed)):
        recs, evs = by_wf_sealed.get(wf, []), by_wf_events.get(wf, [])
        seqs = [r["seq"] for r in recs]
        for s in sorted({s for s in seqs if seqs.count(s) > 1}):
            problems.append(Problem("fork", wf, s, None))  # two records claim one position
        if seqs != sorted(seqs):
            problems.append(Problem("out_of_order", wf, None, None))
        prev = GENESIS
        for i, r in enumerate(recs):
            expected_seq = i + 1
            if r["seq"] != expected_seq or r["prev_hash"] != prev:
                problems.append(Problem("broken_link", wf, r["seq"], r.get("event_id")))
            if i < len(evs):
                e = evs[i]
                if e.get("event_id") != r.get("event_id"):
                    sealed_ids = {x.get("event_id") for x in recs}
                    event_ids = {x.get("event_id") for x in evs}
                    if r.get("event_id") not in event_ids:
                        kind = "deleted"  # a sealed event is gone
                    elif e.get("event_id") not in sealed_ids:
                        kind = "inserted"  # an event that was never sealed sits in the middle
                    else:
                        kind = "out_of_order"
                    problems.append(Problem(kind, wf, expected_seq, e.get("event_id")))
                elif _digest(e, r["prev_hash"], r["seq"], wf) != r["hash"]:
                    problems.append(Problem("modified", wf, r["seq"], r.get("event_id")))
            else:
                problems.append(Problem("deleted", wf, r["seq"], r.get("event_id")))
            prev = r["hash"]
        for e in evs[len(recs):]:
            problems.append(Problem("unsealed", wf, None, e.get("event_id")))  # appended after sealing
        if expected_heads and wf in expected_heads and recs and recs[-1]["hash"] != expected_heads[wf]:
            problems.append(Problem("broken_link", wf, recs[-1]["seq"], "head does not match the stored head"))
    return problems
