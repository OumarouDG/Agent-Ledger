"""Write the gateway audit file as one static HTML page. A fallback view, NOT the AWS Console.

    python scripts/audit_report.py                          # gateway-audit.jsonl -> audit-report.html
    python scripts/audit_report.py audit.jsonl out.html
    python scripts/audit_report.py --workflow wf_001

Read-only on the audit file. Every value is HTML-escaped. No scripts, no network.
"""

from __future__ import annotations

import argparse
import sys
from html import escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_timeline as tl  # noqa: E402

CSS = ("body{font:14px system-ui,sans-serif;margin:24px;background:#fff;color:#111}"
       "table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;"
       "padding:4px 8px;text-align:left;vertical-align:top}th{background:#f3f3f3}"
       ".ALLOW,.DONE{color:#0a6b2d}.DENY,.FAIL{color:#b00020}.LOCK{color:#b00020;font-weight:bold}"
       ".USAGE{color:#555}.note{background:#fff4d6;padding:8px;margin-bottom:12px}")


def _kind(e: dict) -> str:
    d = e.get("decision")
    if d == "usage":
        return "USAGE"
    if d == "outcome":
        return "DONE" if e.get("status") == "succeeded" else "FAIL"
    return {"allow": "ALLOW", "lock": "LOCK"}.get(d, "DENY")


def _detail(e: dict) -> str:
    a = e.get("artifact") or {}
    r = e.get("resource") or {}
    bits = [f"{k}={v}" for k, v in (("kind", a.get("kind")), ("sha", str(a.get("sha") or "")[:10] or None),
                                    ("#", a.get("number")), ("branch", r.get("branch") or a.get("branch")),
                                    ("path", r.get("path")), ("model", r.get("model")),
                                    ("merged_by", a.get("merged_by")), ("error", e.get("error")))
            if v not in (None, "")]
    if e.get("decision") in ("deny", "lock"):
        bits.append(f"reason={e.get('reason')}")
    return " ".join(bits)


def render(events: list[dict], workflow: str | None = None) -> str:
    if workflow:
        events = [e for e in events if e.get("workflow_id") == workflow]
    rows = []
    for e in events:
        k = _kind(e)
        cells = [tl._when(e), f'<span class="{k}">{k}</span>', escape(str(e.get("agent_id") or "?")),
                 escape(str(e.get("tool") or "?")), escape(_detail(e)),
                 escape(str(e.get("grant_id") or "")), escape(str(e.get("workflow_id") or ""))]
        rows.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
    head = "".join(f"<th>{h}</th>" for h in
                   ("Time (UTC)", "Result", "Agent", "Tool", "Detail", "Grant", "Workflow"))
    title = "AgentLedger audit" + (f" - {escape(workflow)}" if workflow else "")
    return (f"<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title>"
            f"<style>{CSS}</style><h1>{title}</h1>"
            "<p class=\"note\">Static report built from the gateway audit file. "
            "This is not the AWS Console or CloudWatch.</p>"
            f"<p>{escape(tl.summary(events))}</p>"
            f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(rows)}</tbody></table></html>")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=tl.DEFAULT_PATH)
    ap.add_argument("out", nargs="?", default="audit-report.html")
    ap.add_argument("--workflow")
    args = ap.parse_args(argv)
    try:
        with open(args.path, encoding="utf-8") as f:
            events, bad = tl.load(f)
        Path(args.out).write_text(render(events, args.workflow), encoding="utf-8")
    except OSError as e:
        print(f"failed: {type(e).__name__}", file=sys.stderr)
        return 2
    for n, text in bad:
        print(f"WARNING: line {n} is not valid JSON: {text!r}", file=sys.stderr)
    print(f"wrote {args.out} ({len(events)} events)")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
