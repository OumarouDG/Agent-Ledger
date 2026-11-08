"""Presentation data for the graph viewer. It decides nothing about evidence.

Every status shown here comes from ledger.evidence, ledger.chain or ledger.metrics. This file
only copies those answers, plus whitelisted attributes, into plain JSON for the page.
Nothing here reads a secret: only fields from the audit schema are copied, and long values are cut.
"""

from __future__ import annotations

import json
from pathlib import Path

from .chain import deliverable_chain
from .evidence import acceptance_state, validate_artifact
from .lineage import trace_downstream, trace_upstream
from .metrics import metrics_for_workflow
from .models import ProvenanceGraph

OK, BAD, WARN, NEUTRAL = "ok", "bad", "warn", "neutral"
MAX_VALUE = 200
LAYERS = {"Human": 0, "Grant": 1, "Agent": 2, "Workflow": 3, "Activity": 4, "Issue": 5, "Branch": 5,
          "Commit": 5, "TestRun": 6, "PullRequest": 7, "GitHubUser": 8}
SAFE_KEYS = {
    "Activity": ("tool", "agent_id", "grant_id", "workflow_id", "decision", "reason", "outcome_status",
                 "locked"),
    "Grant": ("grant_id", "human_id", "agent_id", "workflow_id", "locked"),
    "Agent": ("agent_id",), "Human": ("human_id", "source"), "Workflow": ("workflow_id",),
    "Artifact": ("kind", "repository", "sha", "branch", "path", "number", "state", "run_id", "status",
                 "conclusion", "url", "head_sha", "merged", "merged_by", "approved_by", "observed"),
}
DISPLAY = {"git_commit": "Commit", "git_branch": "Branch", "issue": "Issue", "test_run": "TestRun",
           "pull_request": "PullRequest"}


def _cut(v):
    if isinstance(v, str):
        return v if len(v) <= MAX_VALUE else v[:MAX_VALUE] + "..."
    if isinstance(v, (list, tuple)):
        return [_cut(x) for x in v][:20]
    if isinstance(v, (bool, int, float)) or v is None:
        return v
    return _cut(str(v))


def _kind(n) -> str:
    if n.type == "Artifact":
        return DISPLAY.get(n.attrs.get("kind"), "Artifact")
    if n.type == "Human" and n.attrs.get("source") == "github":
        return "GitHubUser"
    return n.type


def _status(g: ProvenanceGraph, n, kind: str) -> tuple[str, str]:
    a = n.attrs
    if kind == "Activity":
        if a.get("kind") == "identity":
            return NEUTRAL, "AUTHENTICATED (no grant needed)"
        if a.get("decision") == "deny":
            return BAD, f"DENIED: {a.get('reason')}. Not executed."
        out = a.get("outcome_status")
        tag = " (grant locked)" if a.get("locked") else ""
        if a.get("decision") == "allow" or out:
            if out == "succeeded":
                return OK, "ALLOWED, outcome SUCCEEDED" + tag
            if out == "failed":
                return BAD, "ALLOWED, outcome FAILED" + tag
            return WARN, "ALLOWED, outcome UNKNOWN (none recorded)" + tag
        return NEUTRAL, "recorded"
    if not a.get("observed", True) and n.type == "Artifact":
        return WARN, "NOT OBSERVED (named by a declaration only)"
    if kind == "Commit":
        st = validate_artifact(g, a.get("sha"))
        return {"VALIDATED": OK, "FAILED": BAD, "MISMATCH": BAD}.get(st.state, WARN), f"{st.state}: {st.reason}"
    if kind == "TestRun":
        if a.get("status") != "completed":
            return WARN, f"NOT FINISHED ({a.get('status')})"
        if a.get("conclusion") == "success":
            return OK, "PASSED for the commit it ran on"
        return BAD, f"FAILED ({a.get('conclusion')})"
    if kind == "PullRequest":
        st = acceptance_state(g, n.id)
        if st.state == "ACCEPTED":
            return OK, f"ACCEPTED: {st.reason}"
        if st.state == "MERGED":
            return WARN, f"MERGED, not accepted: {st.reason}"
        return WARN, f"{st.state}: {st.reason} (last seen {a.get('state') or 'unknown'})"
    return NEUTRAL, ""


def _label(n, kind: str) -> str:
    a = n.attrs
    if kind == "Commit":
        return f"commit {str(a.get('sha') or '')[:8]}"
    if kind == "PullRequest":
        return f"PR #{a.get('number')}"
    if kind == "TestRun":
        return f"CI run {a.get('run_id')}"
    if kind == "Issue":
        return f"issue #{a.get('number')}"
    if kind == "Branch":
        return f"branch {str(a.get('branch') or '')[-22:]}"
    if kind == "Activity":
        return f"{a.get('tool') or 'activity'}"
    return n.id.split(":", 1)[-1][:28]


def _events(n) -> list[str]:
    ids = list(n.attrs.get("source_event_ids") or []) + list(n.attrs.get("event_ids") or [])
    return list(dict.fromkeys(ids))[:30]


def build_view(g: ProvenanceGraph, *, synthetic_label: str | None = None, workflow: str | None = None,
               pr: int | None = None) -> dict:
    nodes = []
    for n in sorted(g.nodes.values(), key=lambda n: n.id):
        kind = _kind(n)
        cls, text = _status(g, n, kind)
        safe = SAFE_KEYS.get(n.type, ())
        nodes.append({
            "id": n.id, "kind": kind, "layer": LAYERS.get(kind, 5), "label": _label(n, kind),
            "class": cls, "status": text, "evidence_level": n.attrs.get("evidence_level"),
            "workflow": n.attrs.get("workflow_id"), "workflows": n.attrs.get("workflows", []),
            "details": {k: _cut(n.attrs[k]) for k in safe if k in n.attrs and n.attrs[k] is not None},
            "event_ids": _events(n),
        })
    edges = [{**e.to_dict(), "candidate": not e.is_confirmed} for e in
             sorted(g.edges.values(), key=lambda e: e.edge_id)]
    ids = {n["id"] for n in nodes}

    chains = {}
    for n in sorted(g.nodes.values(), key=lambda n: n.id):
        if n.attrs.get("kind") != "pull_request" or not n.attrs.get("observed"):
            continue
        ch = deliverable_chain(g, n.id)
        members = {l["id"] for l in ch["links"] if l.get("id")}
        commit = next((l["id"] for l in ch["links"] if l["link"] == "commit"), None)
        for l in ch["links"]:
            if l["link"] == "tool activity" and l["id"]:
                members.add(l["id"])
        if commit and commit in g.nodes:
            members.update(x for x in g.nodes[commit].attrs.get("generated_by", []))
        members &= ids
        chains[n.id] = {"state": ch["state"], "reason": ch["reason"], "complete": ch["complete"],
                        "links": ch["links"], "nodes": sorted(members),
                        "edges": [e["edge_id"] for e in edges
                                  if e["from"] in members and e["to"] in members]}

    traces = {}
    for n in g.nodes.values():
        if n.type == "Artifact" and any(e.relation == "DERIVED_FROM" for e in g.out_edges(n.id) + g.in_edges(n.id)):
            up, down = trace_upstream(g, n.id), trace_downstream(g, n.id)
            traces[n.id] = {"up": up.artifacts, "up_edges": [e.edge_id for e in up.edges],
                            "down": down.artifacts, "down_edges": [e.edge_id for e in down.edges],
                            "candidates": [e.edge_id for e in up.candidates + down.candidates]}

    wfs = sorted({e.get("workflow_id") for e in g.events if e.get("workflow_id")})
    workflows = {}
    for wf in wfs:
        m = metrics_for_workflow(g, wf)
        scope = {n["id"] for n in nodes if n["workflow"] == wf or wf in n["workflows"]}
        for e in edges:  # one hop out so a workflow's activities show who and what they touched
            if e["from"] in scope and e["relation"] != "PART_OF":
                scope.add(e["to"])
        workflows[wf] = {
            "nodes": sorted(scope & ids),
            "metrics": {k: {"value": v["value"], "numerator": v.get("numerator"),
                            "denominator": v.get("denominator"), "evidence_level": v["evidence_level"],
                            "unknown": v.get("unknown_outcomes", len(v.get("missing", []))),
                            "event_count": len(v["event_ids"]), "note": v.get("note", "")}
                        for k, v in m.items() if isinstance(v, dict) and "evidence_level" in v},
        }
    return {"synthetic": synthetic_label, "nodes": nodes, "edges": edges, "chains": chains,
            "traces": traces, "workflows": workflows, "rejected": g.rejected,
            "initial": {"workflow": workflow, "pr": pr}}


def render_html(view: dict) -> str:
    data = json.dumps(view, sort_keys=True).replace("</", "<\\/").replace("<!--", "<\\!--")
    page = (Path(__file__).parent / "viewer.html").read_text(encoding="utf-8")
    return page.replace("__LEDGER_DATA__", data)
