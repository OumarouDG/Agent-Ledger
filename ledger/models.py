"""Typed graph: nodes, evidence-tagged edges, and the rules that keep it a DAG."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Evidence standards (shared/event.schema.json "evidenceLevels").
VERIFIED, EXTERNAL, REPORTED, INFERRED = "verified", "external", "reported", "inferred"
EVIDENCE_LEVELS = (VERIFIED, EXTERNAL, REPORTED, INFERRED)
CONFIRMED, CANDIDATE = "confirmed", "candidate"

# The only relation that carries lineage between artifacts. Everything else describes
# one workflow's own evidence chain or points at agents, grants and humans.
LINEAGE_RELATIONS = frozenset({"DERIVED_FROM"})


def iso_utc(ts: Any) -> str | None:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def edge_digest(from_id: str, to_id: str, relation: str) -> str:
    return "edge_" + hashlib.sha256(f"{from_id}|{relation}|{to_id}".encode()).hexdigest()[:16]


@dataclass
class Node:
    id: str
    type: str  # Human | Agent | Grant | Workflow | Activity | Artifact
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    edge_id: str
    from_id: str
    to_id: str
    relation: str
    source_event_id: str | None
    evidence_level: str
    confidence: str  # confirmed | candidate
    observed_at: str | None
    note: str = ""

    @property
    def is_confirmed(self) -> bool:
        return self.confidence == CONFIRMED and self.evidence_level in (VERIFIED, EXTERNAL)

    def to_dict(self) -> dict:
        d = {"edge_id": self.edge_id, "from": self.from_id, "to": self.to_id,
             "relation": self.relation, "source_event_id": self.source_event_id,
             "evidence_level": self.evidence_level, "confidence": self.confidence,
             "observed_at": self.observed_at}
        if self.note:
            d["note"] = self.note
        return d


class ProvenanceGraph:
    """Nodes by stable id, edges by stable digest. Adding the same fact twice changes nothing."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self.rejected: list[dict] = []  # edges refused (cycle, unknown node) and why
        self.events: list[dict] = []  # de-duplicated audit events, in input order
        self._out: dict[str, list[str]] = {}
        self._in: dict[str, list[str]] = {}

    # --- nodes ---------------------------------------------------------------------------
    def node(self, node_id: str, type_: str, **attrs: Any) -> Node:
        n = self.nodes.get(node_id)
        if n is None:
            n = self.nodes[node_id] = Node(node_id, type_, {})
        for k, v in attrs.items():
            if v is not None:
                n.attrs[k] = v
        return n

    # --- edges ---------------------------------------------------------------------------
    def add_edge(self, from_id: str, to_id: str, relation: str, *, source_event_id: str | None,
                 evidence_level: str, confidence: str = CONFIRMED, observed_at: str | None = None,
                 note: str = "") -> Edge | None:
        """Add an edge once. A lineage edge that would close a cycle is rejected and recorded."""
        if evidence_level not in EVIDENCE_LEVELS:
            raise ValueError(f"unknown evidence level {evidence_level!r}")
        eid = edge_digest(from_id, to_id, relation)
        if eid in self.edges:
            return self.edges[eid]
        if relation in LINEAGE_RELATIONS and confidence == CONFIRMED:
            if from_id == to_id or self.reaches(to_id, from_id):
                self.rejected.append({"from": from_id, "to": to_id, "relation": relation,
                                      "reason": "cycle", "source_event_id": source_event_id})
                return None
        edge = Edge(eid, from_id, to_id, relation, source_event_id, evidence_level, confidence,
                    observed_at, note)
        self.edges[eid] = edge
        self._out.setdefault(from_id, []).append(eid)
        self._in.setdefault(to_id, []).append(eid)
        return edge

    def out_edges(self, node_id: str, relations: frozenset[str] | None = None) -> list[Edge]:
        return [e for e in (self.edges[i] for i in self._out.get(node_id, ()))
                if relations is None or e.relation in relations]

    def in_edges(self, node_id: str, relations: frozenset[str] | None = None) -> list[Edge]:
        return [e for e in (self.edges[i] for i in self._in.get(node_id, ()))
                if relations is None or e.relation in relations]

    def upstream_edges(self, artifact_id: str) -> list[Edge]:
        """Lineage edges pointing from this artifact to what it was derived from."""
        return self.out_edges(artifact_id, LINEAGE_RELATIONS)

    def downstream_edges(self, artifact_id: str) -> list[Edge]:
        return self.in_edges(artifact_id, LINEAGE_RELATIONS)

    def reaches(self, start: str, goal: str) -> bool:
        """True if goal is reachable from start along confirmed lineage edges."""
        seen, stack = set(), [start]
        while stack:
            cur = stack.pop()
            if cur == goal:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(e.to_id for e in self.upstream_edges(cur) if e.is_confirmed)
        return False

    def to_dict(self) -> dict:
        """Deterministic export: sorted ids, no timestamps of our own."""
        return {
            "nodes": [{"id": n.id, "type": n.type, "attrs": _plain(n.attrs)}
                      for n in sorted(self.nodes.values(), key=lambda n: n.id)],
            "edges": [e.to_dict() for e in sorted(self.edges.values(), key=lambda e: e.edge_id)],
            "rejected": sorted(self.rejected, key=lambda r: (r["from"], r["to"], r["relation"])),
        }


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _plain(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(v) for v in value)
    return value
