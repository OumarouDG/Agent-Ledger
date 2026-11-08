"""Print the gateway audit file (JSON lines) as a readable timeline.

    python scripts/audit_timeline.py                      # gateway-audit.jsonl in the cwd
    python scripts/audit_timeline.py path/to/audit.jsonl
    python scripts/audit_timeline.py --denied             # only denied calls
    python scripts/audit_timeline.py --last 10
    cat gateway-audit.jsonl | python scripts/audit_timeline.py -

Read-only. Lines that are not valid JSON are shown as warnings, never skipped silently.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone

DEFAULT_PATH = "gateway-audit.jsonl"


def load(lines) -> tuple[list[dict], list[tuple[int, str]]]:
    """Return (events, bad_lines). A bad line is (line_number, text)."""
    events, bad = [], []
    for n, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
            if not isinstance(e, dict):
                raise ValueError("not an object")
            events.append(e)
        except ValueError:
            bad.append((n, raw[:80]))
    return events, bad


def _resource(e: dict) -> str:
    r = e.get("resource") or {}
    parts = []
    if r.get("repository"):
        parts.append(r["repository"])
    if r.get("branch"):
        parts.append(f"branch={r['branch']}")
    if r.get("path"):
        parts.append(f"path={r['path']}")
    if r.get("issue") is not None:
        parts.append(f"issue=#{r['issue']}")
    return " ".join(parts)


def _when(e: dict) -> str:
    ts = e.get("ts")
    return (datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")
            if isinstance(ts, (int, float)) else "--:--:--")


def _format_usage(e: dict) -> str:
    r = e.get("resource") or {}
    return (f"{_when(e)}  USAGE  {e.get('agent_id') or '?':<12} {e.get('tool') or '?':<14} "
            f"model={r.get('model')} tokens in={r.get('input_tokens')} out={r.get('output_tokens')}")

def _format_outcome(e: dict) -> str:
    ok = e.get("status") == "succeeded"
    a = e.get("artifact") or {}
    bits = []
    if a.get("kind"):
        bits.append(a["kind"])
    if a.get("sha"):
        bits.append(f"sha={str(a['sha'])[:10]}")
    if a.get("branch") and a.get("kind") != "issue":
        bits.append(f"branch={a['branch']}")
    if a.get("number") is not None:
        bits.append(f"#{a['number']}")
    if e.get("error"):
        bits.append(f"error={e['error']}")
    if e.get("elapsed_ms") is not None:
        bits.append(f"{e['elapsed_ms']}ms")
    return (f"{_when(e)}  {'DONE ' if ok else 'FAIL '}  {e.get('agent_id') or '?':<12} "
            f"{e.get('tool') or '?':<14} {' '.join(bits)}")


def format_event(e: dict) -> str:
    if e.get("decision") == "usage":
        return _format_usage(e)
    if e.get("decision") == "outcome":
        return _format_outcome(e)
    when = _when(e)
    verdict = {"allow": "ALLOW", "lock": "LOCK "}.get(e.get("decision"), "DENY ")
    line = (f"{when}  {verdict}  {e.get('agent_id') or '?':<12} "
            f"{e.get('tool') or '?':<14} {_resource(e)}")
    if e.get("decision") not in ("allow",):
        line += f"  <- {e.get('reason')}"
    who = []
    if e.get("grant_id"):
        who += [f"grant={e.get('grant_id')}", f"workflow={e.get('workflow_id')}"]
    if e.get("activity_id"):
        who.append(f"act={e['activity_id']}")
    if e.get("human_id"):
        who.append(f"owner={e['human_id']}")
    return line.rstrip() + ("\n" + " " * 18 + "(" + ", ".join(who) + ")" if who else "")


def summary(events: list[dict]) -> str:
    calls = [e for e in events if e.get("decision") in ("allow", "deny")]
    allowed = sum(1 for e in calls if e.get("decision") == "allow")
    denied = len(calls) - allowed
    reasons = Counter(e.get("reason") for e in calls if e.get("decision") == "deny")
    out = f"{len(calls)} calls: {allowed} allowed, {denied} denied"
    if reasons:
        out += " (" + ", ".join(f"{r} x{n}" for r, n in reasons.most_common()) + ")"
    locks = sum(1 for e in events if e.get("decision") == "lock")
    if locks:
        out += f"; {locks} grant lock(s)"
    outs = [e for e in events if e.get("decision") == "outcome"]
    if outs:
        done = len({e.get('activity_id') for e in outs if e.get('status') == 'succeeded'})
        failed = len({e.get('activity_id') for e in outs if e.get('status') != 'succeeded'})
        out += f"; {done} succeeded, {failed} failed"
    usage = [e.get("resource") or {} for e in events if e.get("decision") == "usage"]
    if usage:
        tin = sum(u.get("input_tokens") or 0 for u in usage)
        tout = sum(u.get("output_tokens") or 0 for u in usage)
        out += f"; {len(usage)} model call(s), {tin} tokens in, {tout} out"
    return out

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH, help="audit file, or - for stdin")
    ap.add_argument("--denied", action="store_true", help="show only denied calls")
    ap.add_argument("--last", type=int, metavar="N", help="show only the last N events")
    args = ap.parse_args(argv)

    try:
        if args.path == "-":
            events, bad = load(sys.stdin)
        else:
            with open(args.path, encoding="utf-8") as f:
                events, bad = load(f)
    except OSError as e:
        print(f"cannot read {args.path}: {type(e).__name__}", file=sys.stderr)
        return 2

    shown = [e for e in events if not args.denied or e.get("decision") in ("deny", "lock")
             or (e.get("decision") == "outcome" and e.get("status") != "succeeded")]
    if args.last:
        shown = shown[-args.last:]
    for e in shown:
        print(format_event(e))
    for n, text in bad:
        print(f"WARNING: line {n} is not valid JSON: {text!r}", file=sys.stderr)
    print("-" * 60)
    print(summary(events))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
