"""Copy the audit events shipped to CloudWatch into a local JSONL file. Read-only on AWS.

    python scripts/pull_audit_from_cloudwatch.py audit-from-cloudwatch.jsonl
    python scripts/pull_audit_from_cloudwatch.py out.jsonl --hours 24

Needs your own AWS login in the terminal (logs:FilterLogEvents). It only reads. Lines that are
not JSON objects are skipped and counted. Duplicates are harmless: the ledger drops repeated
event ids. CloudWatch is a viewing copy, so this is a copy of a copy; the file on the gateway
host remains the record.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

LOG_GROUP = "/agentledger/gateway-audit"
REGION = "us-east-1"


def pull(client, log_group: str, start_ms: int | None) -> tuple[list[dict], int]:
    events: list[dict] = []
    skipped = 0
    kwargs = {"logGroupName": log_group}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    while True:
        page = client.filter_log_events(**kwargs)
        for item in page.get("events", []):
            try:
                obj = json.loads(item["message"])
            except (ValueError, KeyError, TypeError):
                skipped += 1
                continue
            if isinstance(obj, dict):
                events.append(obj)
            else:
                skipped += 1
        token = page.get("nextToken")
        if not token:
            return events, skipped
        kwargs["nextToken"] = token


def main(argv=None, client=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--hours", type=float, help="only the last N hours (default: everything)")
    ap.add_argument("--log-group", default=LOG_GROUP)
    args = ap.parse_args(argv)
    try:
        if client is None:
            import boto3
            client = boto3.client("logs", region_name=REGION)
        start = int((time.time() - args.hours * 3600) * 1000) if args.hours else None
        events, skipped = pull(client, args.log_group, start)
        events.sort(key=lambda e: (e.get("ts") or 0, e.get("event_id") or ""))
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e, sort_keys=True) + "\n" for e in events))
    except Exception as e:  # expired credentials, missing group, no boto3: say which, never print secrets
        print(f"failed: {type(e).__name__}", file=sys.stderr)
        return 2
    print(f"wrote {len(events)} events to {args.out}" + (f" ({skipped} skipped)" if skipped else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
