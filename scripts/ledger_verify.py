"""Seal and verify the audit file with the hash-chain proof of concept. Never edits the audit file.

    python scripts/ledger_verify.py seal   gateway-audit.jsonl sealed.jsonl [--heads heads.json]
    python scripts/ledger_verify.py verify gateway-audit.jsonl sealed.jsonl [--heads heads.json]

`seal` writes a separate file. Sealing today does not prove the events were honest before today.
Store heads.json somewhere the gateway's writer cannot change; without that, someone who can
rewrite both files can make them agree. Exit 0 = they agree, 1 = a problem was found, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_timeline as tl  # noqa: E402
from ledger.hashchain import heads, seal, verify_chain  # noqa: E402


def _read_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        events, bad = tl.load(f)
    if bad:
        raise ValueError(f"{path}: line {bad[0][0]} is not valid JSON")
    return events


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", choices=["seal", "verify"])
    ap.add_argument("audit")
    ap.add_argument("sealed")
    ap.add_argument("--heads", metavar="FILE")
    args = ap.parse_args(argv)
    try:
        events = _read_jsonl(args.audit)
        if args.command == "seal":
            sealed = seal(events)
            with open(args.sealed, "w", encoding="utf-8") as f:
                f.write("".join(json.dumps(r, sort_keys=True) + "\n" for r in sealed))
            h = heads(sealed)
            if args.heads:
                Path(args.heads).write_text(json.dumps(h, indent=2, sort_keys=True), encoding="utf-8")
            print(f"sealed {len(sealed)} events in {len(h)} workflow(s) -> {args.sealed}")
            for wf, hh in sorted(h.items()):
                print(f"  head {wf}: {hh}")
            return 0
        sealed = _read_jsonl(args.sealed)
        expected = json.loads(Path(args.heads).read_text(encoding="utf-8")) if args.heads else None
    except (OSError, ValueError) as e:
        print(f"failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    problems = verify_chain(events, sealed, expected)
    if not problems:
        print(f"OK: {len(events)} events agree with the sealed copy"
              + (" and the stored heads" if expected else " (no stored heads given: weaker check)"))
        return 0
    for p in problems:
        print(f"PROBLEM  {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
