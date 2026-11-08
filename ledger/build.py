"""Turn the gateway audit stream into a ProvenanceGraph. Read-only; no network.

Rules this file keeps:
- An event only becomes a fact if the gateway wrote it. Nothing is guessed from timing.
- Artifact ids are stable across workflows: the same commit is the same node everywhere.
- Missing evidence leaves a state pending or unknown. It never becomes success.
- A cross-workflow dependency must be declared. It is confirmed only if the upstream
  artifact was itself observed with external (GitHub) evidence; otherwise it stays a candidate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from .models import (CANDIDATE, CONFIRMED, EXTERNAL, INFERRED, REPORTED, VERIFIED, ProvenanceGraph,
                      iso_utc)

# What each guarded tool does to the artifact its outcome names.
GENERATES = {"commit_file": "git_commit", "create_branch": "git_branch",
             "open_pull_request": "pull_request"}
UNKNOWN_REPO = "unknown"


@dataclass(frozen=True)
class Declaration:
    """A statement that `artifact_id` was built on `depends_on` (both artifact ids)."""
    artifact_id: str
    depends_on: str
    declared_by: str
    source_event_id: str | None = None
    note: str = ""


def event_key(e: dict) -> str:
    """The event's id, or a digest of its content for old records that have none."""
    eid = e.get("event_id")
    if isinstance(eid, str) and eid:
        return eid
    raw = json.dumps(e, sort_keys=True, default=str)
    return "legacy_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def event_kind(e: dict) -> str:
    k = e.get("event")
    if k in ("decision", "outcome", "usage", "sentinel", "identity"):
        return k
    return {"allow": "decision", "deny": "decision", "outcome": "outcome", "usage": "usage",
            "lock": "sentinel"}.get(e.get("decision"), "decision")


def artifact_id(kind: str, a: dict, repo: str) -> str | None:
    if kind == "git_commit" and a.get("sha"):
        return f"artifact:{repo}:{a['sha']}"
    if kind == "git_branch" and a.get("branch"):
        return f"artifact:{repo}:branch:{a['branch']}"
    if kind == "issue" and a.get("number") is not None:
        return f"artifact:{repo}:issue:{a['number']}"
    if kind == "test_run" and a.get("run_id") is not None:
        return f"artifact:{repo}:run:{a['run_id']}"
    if kind == "pull_request" and a.get("number") is not None:
        return f"artifact:{repo}:pr:{a['number']}"
    return None


def build_graph(events: Iterable[dict], declarations: Iterable[Declaration] = ()) -> ProvenanceGraph:
    g = ProvenanceGraph()
    seen: set[str] = set()
    ordered: list[tuple[int, str, dict]] = []
    for e in events:
        if not isinstance(e, dict):
            continue
        key = event_key(e)
        if key in seen:
            continue  # the same line twice is one fact
        seen.add(key)
        ordered.append((len(ordered), key, e))
        g.events.append({**e, "event_id": key})

    commit_repo: dict[str, str] = {}  # sha -> repository, for lookups that omit the repository
    for _, _, e in ordered:
        a = e.get("artifact") or {}
        if event_kind(e) == "outcome" and a.get("kind") == "git_commit" and a.get("sha"):
            commit_repo.setdefault(a["sha"], a.get("repository") or UNKNOWN_REPO)

    for seq, key, e in ordered:
        kind = event_kind(e)
        if kind == "sentinel":
            _sentinel(g, e, key)
        elif kind == "decision" or kind == "identity":
            _decision(g, e, key, kind)
        elif kind == "outcome":
            _outcome(g, e, key, seq, commit_repo)
        elif kind == "usage":
            _usage(g, e, key)

    _derived_edges(g)
    _declared_edges(g, sorted(declarations, key=lambda d: (d.artifact_id, d.depends_on)))
    return g


# --- activities -----------------------------------------------------------------------------

def _activity(g: ProvenanceGraph, e: dict, key: str) -> str:
    act = e.get("activity_id") or f"legacy:{key}"
    nid = f"activity:{act}"
    g.node(nid, "Activity", activity_id=act, tool=e.get("tool"), agent_id=e.get("agent_id"),
           grant_id=e.get("grant_id"), workflow_id=e.get("workflow_id"))
    return nid


def _link_actor(g: ProvenanceGraph, act: str, e: dict, key: str, allowed: bool) -> None:
    at = iso_utc(e.get("ts"))
    agent, grant, human, wf = (e.get("agent_id"), e.get("grant_id"), e.get("human_id"),
                               e.get("workflow_id"))
    if agent:
        g.node(f"agent:{agent}", "Agent", agent_id=agent)
        # Allowed calls were executed by the verified agent; denied calls were only requested.
        g.add_edge(act, f"agent:{agent}", "EXECUTED_BY" if allowed else "REQUESTED_BY",
                   source_event_id=key, evidence_level=VERIFIED, observed_at=at)
    if wf:
        g.node(f"workflow:{wf}", "Workflow", workflow_id=wf)
        g.add_edge(act, f"workflow:{wf}", "PART_OF", source_event_id=key,
                   evidence_level=VERIFIED, observed_at=at)
    if human:
        g.node(f"human:{human}", "Human", human_id=human, source="grant_owner")
    if grant:
        g.node(f"grant:{grant}", "Grant", grant_id=grant, human_id=human, agent_id=agent,
               workflow_id=wf)
    if allowed:  # a denied call was not authorized by the grant, so it gets no such edge
        if grant:
            g.add_edge(act, f"grant:{grant}", "AUTHORIZED_BY", source_event_id=key,
                       evidence_level=VERIFIED, observed_at=at)
        if human:
            g.add_edge(act, f"human:{human}", "AUTHORIZED_BY", source_event_id=key,
                       evidence_level=VERIFIED, observed_at=at)


def _decision(g: ProvenanceGraph, e: dict, key: str, kind: str) -> None:
    act = _activity(g, e, key)
    allowed = e.get("decision") == "allow"
    n = g.nodes[act]
    n.attrs.update({"kind": kind, "decision": e.get("decision"), "reason": e.get("reason"),
                    "ts": e.get("ts")})
    n.attrs.setdefault("event_ids", []).append(key)
    n.attrs["decision_event_id"] = key
    _link_actor(g, act, e, key, allowed)


def _sentinel(g: ProvenanceGraph, e: dict, key: str) -> None:
    act = _activity(g, e, key)
    n = g.nodes[act]
    n.attrs["locked"] = True
    n.attrs["lock_event_id"] = key
    n.attrs.setdefault("event_ids", []).append(key)
    if e.get("grant_id"):
        g.node(f"grant:{e['grant_id']}", "Grant", grant_id=e["grant_id"], locked=True)


def _usage(g: ProvenanceGraph, e: dict, key: str) -> None:
    act = _activity(g, e, key)
    r = e.get("resource") or {}
    n = g.nodes[act]
    n.attrs["usage"] = {"model": r.get("model"), "input_tokens": r.get("input_tokens"),
                        "output_tokens": r.get("output_tokens"), "event_id": key}
    n.attrs["outcome_status"] = e.get("status") or "succeeded"
    n.attrs.setdefault("event_ids", []).append(key)


# --- artifacts ------------------------------------------------------------------------------

def _outcome(g: ProvenanceGraph, e: dict, key: str, seq: int, commit_repo: dict[str, str]) -> None:
    act = _activity(g, e, key)
    n = g.nodes[act]
    n.attrs["outcome_status"] = e.get("status")
    n.attrs["outcome_event_id"] = key
    n.attrs.setdefault("event_ids", []).append(key)
    if e.get("error"):
        n.attrs["error"] = e["error"]
    if e.get("agent_id") and "decision_event_id" not in n.attrs:
        _link_actor(g, act, e, key, allowed=True)  # old record: the outcome is all we have

    a = e.get("artifact") or {}
    if e.get("status") != "succeeded" or not isinstance(a, dict) or not a.get("kind"):
        return
    kind = a["kind"]
    repo = a.get("repository") or commit_repo.get(a.get("sha") or "") or UNKNOWN_REPO
    aid = artifact_id(kind, a, repo)
    if aid is None:
        return
    level = EXTERNAL if e.get("evidence") == "external" else VERIFIED
    attrs: dict[str, Any] = {"kind": kind, "repository": repo, "observed": True, "seq": seq,
                             "evidence_level": level}
    if kind == "git_commit":
        attrs.update(sha=a.get("sha"), branch=a.get("branch"), path=a.get("path"))
    elif kind == "git_branch":
        attrs.update(branch=a.get("branch"), sha=a.get("sha"))
    elif kind == "issue":
        attrs.update(number=a.get("number"), state=a.get("state"))
    elif kind == "test_run":
        attrs.update(sha=a.get("sha"), run_id=a.get("run_id"), status=a.get("status"),
                     conclusion=a.get("conclusion"), url=a.get("url"))
    elif kind == "pull_request":  # the latest reading of a pull request wins
        attrs.update(number=a.get("number"), head_sha=a.get("sha"), state=a.get("state"),
                     merged=bool(a.get("merged")), merged_by=a.get("merged_by"),
                     approved_by=a.get("approved_by"), head_branch=a.get("head_branch"))
    node = g.node(aid, "Artifact", **attrs)
    node.attrs.setdefault("source_event_ids", []).append(key)
    if n.attrs.get("workflow_id"):
        wfs = node.attrs.setdefault("workflows", [])
        if n.attrs["workflow_id"] not in wfs:
            wfs.append(n.attrs["workflow_id"])

    at = iso_utc(e.get("ts"))
    tool = e.get("tool")
    relation = "GENERATED" if GENERATES.get(tool) == kind else "USED"
    g.add_edge(act, aid, relation, source_event_id=key, evidence_level=level, observed_at=at)
    if relation == "GENERATED":
        node.attrs.setdefault("generated_by", []).append(act)


def _artifacts(g: ProvenanceGraph, kind: str) -> list:
    return sorted((n for n in g.nodes.values()
                   if n.type == "Artifact" and n.attrs.get("kind") == kind and n.attrs.get("observed")),
                  key=lambda n: n.id)


def _derived_edges(g: ProvenanceGraph) -> None:
    """Edges that join artifacts to each other, from the final reading of each."""
    commits = {n.attrs["sha"]: n for n in _artifacts(g, "git_commit") if n.attrs.get("sha")}
    latest_run: dict[str, Any] = {}
    for run in _artifacts(g, "test_run"):
        sha = run.attrs.get("sha")
        if sha and (sha not in latest_run or run.attrs["seq"] > latest_run[sha].attrs["seq"]):
            latest_run[sha] = run  # a later lookup replaces an earlier one
    branches = {(n.attrs["repository"], n.attrs.get("branch")): n for n in _artifacts(g, "git_branch")}

    for sha, commit in commits.items():
        b = branches.get((commit.attrs["repository"], commit.attrs.get("branch")))
        if b:
            g.add_edge(commit.id, b.id, "ON_BRANCH", source_event_id=_first(commit),
                       evidence_level=EXTERNAL)
        run = latest_run.get(sha)
        if run is None:
            continue
        g.add_edge(commit.id, run.id, "TESTED_BY", source_event_id=_first(run), evidence_level=EXTERNAL)
        if run.attrs.get("status") == "completed" and run.attrs.get("conclusion") == "success":
            g.add_edge(commit.id, run.id, "VALIDATED_BY", source_event_id=_first(run),
                       evidence_level=EXTERNAL)

    for pr in _artifacts(g, "pull_request"):
        head = commits.get(pr.attrs.get("head_sha") or "")
        if head:
            g.add_edge(pr.id, head.id, "HEAD_COMMIT", source_event_id=_first(pr), evidence_level=EXTERNAL)
        if pr.attrs.get("merged") and pr.attrs.get("merged_by"):
            login = pr.attrs["merged_by"]
            g.node(f"human:github/{login}", "Human", human_id=login, source="github")
            g.add_edge(pr.id, f"human:github/{login}", "ACCEPTED_BY", source_event_id=_first(pr),
                       evidence_level=EXTERNAL, note="merged by; this is not an approval")
        for who in pr.attrs.get("approved_by") or ():
            g.node(f"human:github/{who}", "Human", human_id=who, source="github")
            g.add_edge(pr.id, f"human:github/{who}", "APPROVED_BY", source_event_id=_first(pr),
                       evidence_level=EXTERNAL)

    # A branch was probably made for the workflow's issue, but no event says so: candidate only.
    for b in _artifacts(g, "git_branch"):
        for wf in b.attrs.get("workflows", []):
            issues = [i for i in _artifacts(g, "issue") if wf in i.attrs.get("workflows", [])
                      and i.attrs["repository"] == b.attrs["repository"]]
            if len(issues) == 1:
                g.add_edge(b.id, issues[0].id, "DERIVED_FROM", source_event_id=_first(b),
                           evidence_level=INFERRED, confidence=CANDIDATE,
                           note=f"same workflow {wf}; not stated by any event")


def _first(node) -> str | None:
    ids = node.attrs.get("source_event_ids") or []
    return ids[0] if ids else None


def _declared_edges(g: ProvenanceGraph, declarations: list[Declaration]) -> None:
    for d in declarations:
        frm, to = g.nodes.get(d.artifact_id), g.nodes.get(d.depends_on)
        observed = bool(frm and to and frm.attrs.get("observed") and to.attrs.get("observed")
                        and to.attrs.get("evidence_level") == EXTERNAL)
        note = f"declared by {d.declared_by}" + (f": {d.note}" if d.note else "")
        for aid in (d.artifact_id, d.depends_on):
            if aid not in g.nodes:
                g.node(aid, "Artifact", observed=False)
        if observed:
            g.add_edge(d.artifact_id, d.depends_on, "DERIVED_FROM", source_event_id=d.source_event_id,
                       evidence_level=EXTERNAL, confidence=CONFIRMED,
                       note=note + " (upstream seen with GitHub evidence)")
        else:
            g.add_edge(d.artifact_id, d.depends_on, "DERIVED_FROM", source_event_id=d.source_event_id,
                       evidence_level=REPORTED, confidence=CANDIDATE,
                       note=note + " (not confirmed)")
