"""Backward and forward traversal over confirmed lineage edges.

Tracing is a question of fact: which verified artifacts are reachable. It says nothing about
how much credit anyone deserves. Candidate (unconfirmed) edges are listed but never followed.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .models import Edge, ProvenanceGraph


@dataclass
class TraceResult:
    root: str
    direction: str  # upstream | downstream
    found: bool
    artifacts: list[str] = field(default_factory=list)  # reached, root excluded, each once
    edges: list[Edge] = field(default_factory=list)  # confirmed edges followed, each once
    candidates: list[Edge] = field(default_factory=list)  # seen but not followed

    def to_dict(self) -> dict:
        return {"root": self.root, "direction": self.direction, "found": self.found,
                "artifacts": self.artifacts, "edges": [e.to_dict() for e in self.edges],
                "candidates_not_followed": [e.to_dict() for e in self.candidates]}


def _trace(g: ProvenanceGraph, artifact_id: str, direction: str) -> TraceResult:
    res = TraceResult(artifact_id, direction, artifact_id in g.nodes)
    if not res.found:
        return res
    step = g.upstream_edges if direction == "upstream" else g.downstream_edges
    visited, queue, used = {artifact_id}, deque([artifact_id]), set()
    while queue:
        cur = queue.popleft()
        for e in sorted(step(cur), key=lambda e: e.edge_id):
            if not e.is_confirmed:
                if e.edge_id not in used:
                    used.add(e.edge_id)
                    res.candidates.append(e)
                continue
            if e.edge_id not in used:
                used.add(e.edge_id)
                res.edges.append(e)
            nxt = e.to_id if direction == "upstream" else e.from_id
            if nxt not in visited:  # a shared dependency is reached once, however many paths lead to it
                visited.add(nxt)
                res.artifacts.append(nxt)
                queue.append(nxt)
    return res


def trace_upstream(g: ProvenanceGraph, artifact_id: str) -> TraceResult:
    """Everything this artifact was derived from, along confirmed edges."""
    return _trace(g, artifact_id, "upstream")


def trace_downstream(g: ProvenanceGraph, artifact_id: str) -> TraceResult:
    """Everything derived from this artifact, along confirmed edges."""
    return _trace(g, artifact_id, "downstream")


def all_paths(g: ProvenanceGraph, start: str, end: str, limit: int = 50) -> list[list[str]]:
    """Every simple path start -> end along confirmed upstream edges, as lists of edge ids.

    Used to show the exact routes behind a reuse count. Capped so a large graph cannot hang."""
    out: list[list[str]] = []

    def walk(cur: str, trail: list[str], seen: frozenset[str]) -> None:
        if len(out) >= limit:
            return
        if cur == end and trail:
            out.append(trail)
            return
        for e in sorted(g.upstream_edges(cur), key=lambda e: e.edge_id):
            if e.is_confirmed and e.to_id not in seen:
                walk(e.to_id, trail + [e.edge_id], seen | {e.to_id})

    walk(start, [], frozenset({start}))
    return out
