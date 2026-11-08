"""Provenance report from the gateway audit file. Read-only. Nothing is written unless --html/--json-out.

    python scripts/ledger_report.py gateway-audit.jsonl --workflow wf_001
    python scripts/ledger_report.py audit.jsonl --declarations deps.json
    python scripts/ledger_report.py audit.jsonl --trace artifact:owner/repo:<sha>
    python scripts/ledger_report.py --synthetic            # invented 3-workflow sample, labelled

deps.json is a list of {"artifact": id, "depends_on": id, "declared_by": name, "note": text}.
A declared dependency is CONFIRMED only if the upstream artifact was seen with GitHub evidence.
Otherwise it is shown as a candidate and never counted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_timeline as tl  # noqa: E402
from ledger import (Declaration, acceptance_state, build_graph, metrics_for_workflow,  # noqa: E402
                    regression_impact, reuse_credits, trace_downstream, trace_upstream)
from ledger.chain import deliverable_chain, render_chain  # noqa: E402
from ledger.evidence import accepted_commits  # noqa: E402
from ledger.sample import LABEL, sample_declarations, sample_events  # noqa: E402

DEFAULT_PATH = "gateway-audit.jsonl"


def load_declarations(path: str) -> list[Declaration]:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raise ValueError("declarations file must be a JSON list")
    return [Declaration(str(d["artifact"]), str(d["depends_on"]), str(d.get("declared_by") or "unknown"),
                        d.get("source_event_id"), str(d.get("note") or "")) for d in raw]


def _short(artifact_id: str) -> str:
    parts = artifact_id.split(":")
    tail = parts[-1]
    return ":".join(parts[:-1] + [tail[:10] if len(tail) == 40 else tail])


def _metric_line(name: str, m: dict) -> str:
    val = "n/a" if m["value"] is None else m["value"]
    frac = f" ({m['numerator']}/{m['denominator']})" if m.get("denominator") is not None else ""
    extra = f"  [{m['evidence_level']}, {len(m['event_ids'])} event ids]"
    if m.get("missing"):
        extra += f"  UNKNOWN: {len(m['missing'])}"
    return f"  {name:30} {val}{frac}{extra}"


def render(events: list[dict], declarations: list[Declaration], workflow: str | None,
           label: str | None = None, show_ids: bool = False) -> str:
    g = build_graph(events, declarations)
    out: list[str] = []
    if label:
        out += ["=" * 70, label, "=" * 70]
    out.append(f"{len(g.events)} events, {len(g.nodes)} nodes, {len(g.edges)} edges"
               + (f", {len(g.rejected)} edge(s) rejected" if g.rejected else ""))
    wfs = sorted({e.get("workflow_id") for e in g.events if e.get("workflow_id")})
    if workflow:
        wfs = [w for w in wfs if w == workflow]
    for wf in wfs:
        m = metrics_for_workflow(g, wf)
        out += ["", f"Workflow {wf}", "  metrics (workflow performance, not worker value):"]
        for name, met in m.items():
            if isinstance(met, dict) and "evidence_level" in met:
                out.append(_metric_line(name, met))
                if show_ids and met["event_ids"]:
                    out.append("      events: " + ", ".join(met["event_ids"]))
        out.append("  not computed: " + ", ".join(m["not_computed"]))

    accepted = accepted_commits(g)
    out += ["", "Deliverables"]
    prs = sorted((n for n in g.nodes.values() if n.attrs.get("kind") == "pull_request"
                  and n.attrs.get("observed")), key=lambda n: n.id)
    for pr in prs:
        st = acceptance_state(g, pr.id)
        out.append(f"  {_short(pr.id)}  {st.state}  ({st.reason})")
    if not prs:
        out.append("  (none recorded)")

    out += ["", "Evidence chain per deliverable"]
    for pr in prs:
        out += render_chain(deliverable_chain(g, pr.id))
    if not prs:
        out.append("  (none)")

    out += ["", "Lineage (confirmed edges only)"]
    any_edge = False
    for cid_ in sorted(accepted):
        up = trace_upstream(g, cid_)
        if up.artifacts or up.candidates:
            any_edge = True
            out.append(f"  {_short(cid_)}  ACCEPTED")
            for a in up.artifacts:
                out.append(f"      derived from {_short(a)}")
            for c in up.candidates:
                out.append(f"      CANDIDATE (not followed): {_short(c.to_id)}  [{c.evidence_level}] {c.note}")
    if not any_edge:
        out.append("  no cross-workflow dependency recorded")
    credits = reuse_credits(g)
    if credits.credits:
        out += ["", f"Reuse credits ({credits.policy}): a count of verified influence, not value"]
        for up_id, c in sorted(credits.credits.items()):
            out.append(f"  {_short(up_id)}  {c['count']} accepted deliverable(s) built on it")
            for d in c["accepted_deliverables"]:
                n_paths = len(c["paths"].get(d["artifact"], []))
                out.append(f"      via {_short(d['artifact'])} ({n_paths} path(s))")
        out += ["  assumptions:"] + [f"    - {a}" for a in credits.assumptions]
    if g.rejected:
        out += ["", "Rejected edges"] + [f"  {_short(r['from'])} -> {_short(r['to'])}: {r['reason']}" for r in g.rejected]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH)
    ap.add_argument("--workflow")
    ap.add_argument("--declarations", metavar="FILE")
    ap.add_argument("--trace", metavar="ARTIFACT_ID")
    ap.add_argument("--regression", metavar="ARTIFACT_ID", help="what depends on a defective artifact")
    ap.add_argument("--synthetic", action="store_true", help="invented 3-workflow sample, labelled")
    ap.add_argument("--ids", action="store_true", help="list the event ids behind each metric")
    ap.add_argument("--json", action="store_true", help="print the graph and metrics as JSON")
    args = ap.parse_args(argv)

    bad: list = []
    label = None
    try:
        if args.synthetic:
            events, decls, label = sample_events(), sample_declarations(), LABEL
        else:
            with open(args.path, encoding="utf-8") as f:
                events, bad = tl.load(f)
            decls = load_declarations(args.declarations) if args.declarations else []
    except (OSError, ValueError, KeyError) as e:
        print(f"failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    g = build_graph(events, decls)
    if args.json:
        wfs = sorted({e.get("workflow_id") for e in g.events if e.get("workflow_id")})
        doc = {"label": label, "graph": g.to_dict(),
               "metrics": {w: metrics_for_workflow(g, w) for w in wfs if not args.workflow or w == args.workflow},
               "reuse": reuse_credits(g).to_dict()}
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        print(render(events, decls, args.workflow, label, args.ids))
    if args.trace:
        print()
        for fn in (trace_upstream, trace_downstream):
            r = fn(g, args.trace)
            print(f"{r.direction}: " + ("not found" if not r.found else ", ".join(_short(a) for a in r.artifacts) or "none"))
    if args.regression:
        print()
        print(json.dumps(regression_impact(g, args.regression), indent=2))
    for n, text in bad:
        print(f"WARNING: line {n} is not valid JSON: {text!r}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
