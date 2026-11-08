"""The full evidence chain behind one accepted pull request.

human -> grant -> agent -> tool activity -> commit sha -> passing CI on the same sha -> merged PR.
Every link carries its evidence level and the event id it came from. A link that has no
evidence is reported as missing, not filled in.
"""

from __future__ import annotations

from .evidence import acceptance_state
from .models import ProvenanceGraph


def _first_edge(g: ProvenanceGraph, node_id: str, relation: str, prefix: str | None = None):
    for e in sorted(g.out_edges(node_id), key=lambda e: e.edge_id):
        if e.relation == relation and (prefix is None or e.to_id.startswith(prefix)):
            return e
    return None


def _link(label: str, node_id: str | None, edge=None, **extra) -> dict:
    d = {"link": label, "id": node_id}
    if edge is not None:
        d.update(evidence_level=edge.evidence_level, source_event_id=edge.source_event_id)
    d.update(extra)
    if node_id is None:
        d["missing"] = True
    return d


def deliverable_chain(g: ProvenanceGraph, pr_id: str) -> dict:
    """Chain for a pull request. `state` is ACCEPTED only when every required link exists."""
    state = acceptance_state(g, pr_id)
    pr = g.nodes.get(pr_id)
    links: list[dict] = []
    head = _first_edge(g, pr_id, "HEAD_COMMIT") if pr else None
    commit = g.nodes.get(head.to_id) if head else None
    gen = (commit.attrs.get("generated_by") or []) if commit else []
    act = g.nodes.get(sorted(gen)[0]) if gen else None
    act_edges = {}
    if act:
        for rel, pre in (("AUTHORIZED_BY", "human:"), ("AUTHORIZED_BY", "grant:"), ("EXECUTED_BY", "agent:")):
            act_edges[(rel, pre)] = _first_edge(g, act.id, rel, pre)
    human = act_edges.get(("AUTHORIZED_BY", "human:"))
    grant = act_edges.get(("AUTHORIZED_BY", "grant:"))
    agent = act_edges.get(("EXECUTED_BY", "agent:"))
    val = _first_edge(g, commit.id, "VALIDATED_BY") if commit else None
    acc = _first_edge(g, pr_id, "ACCEPTED_BY") if pr else None

    links.append(_link("human (grant owner)", human.to_id if human else None, human))
    links.append(_link("grant", grant.to_id if grant else None, grant))
    links.append(_link("agent (verified identity)", agent.to_id if agent else None, agent))
    links.append(_link("tool activity", act.id if act else None, tool=act.attrs.get("tool") if act else None))
    links.append(_link("commit", commit.id if commit else None, head,
                       sha=commit.attrs.get("sha") if commit else None))
    links.append(_link("passing CI, same sha", val.to_id if val else None, val))
    links.append(_link("merged pull request", pr_id if pr else None, acc,
                       merged_by=pr.attrs.get("merged_by") if pr else None))
    return {"pull_request": pr_id, "state": state.state, "reason": state.reason, "links": links,
            "complete": all(not l.get("missing") for l in links)}


def render_chain(chain: dict) -> list[str]:
    out = [f"  {chain['pull_request']}  {chain['state']}" + ("" if chain["complete"] else "  (chain incomplete)")]
    for l in chain["links"]:
        who = l["id"] if l["id"] else "MISSING"
        ev = f"  [{l['evidence_level']}, {l['source_event_id']}]" if l.get("evidence_level") else ""
        out.append(f"      {l['link']:28} {who}{ev}")
    return out
