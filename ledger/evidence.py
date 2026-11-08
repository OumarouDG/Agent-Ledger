"""Evidence states for commits and pull requests. Same rules as scripts/work_chain.py.

Missing evidence is PENDING, never success. A merge is not an approval. A test run only
counts for the exact commit SHA it ran on.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import ProvenanceGraph


@dataclass(frozen=True)
class EvidenceState:
    state: str  # VALIDATED | FAILED | PENDING | MISMATCH
    reason: str
    run_node: str | None = None


def _observed(g: ProvenanceGraph, kind: str):
    return [n for n in sorted(g.nodes.values(), key=lambda n: n.id)
            if n.type == "Artifact" and n.attrs.get("kind") == kind and n.attrs.get("observed")]


def validate_artifact(g: ProvenanceGraph, sha: str, run_id: object | None = None) -> EvidenceState:
    """Is this commit validated by a passing test run for the same SHA?"""
    if not any(c.attrs.get("sha") == sha for c in _observed(g, "git_commit")):
        return EvidenceState("PENDING", "no commit with this sha was recorded")
    runs = [r for r in _observed(g, "test_run")]
    if run_id is not None:
        chosen = [r for r in runs if str(r.attrs.get("run_id")) == str(run_id)]
        if not chosen:
            return EvidenceState("PENDING", f"test run {run_id} was not recorded")
        run = chosen[-1]
        if run.attrs.get("sha") != sha:
            return EvidenceState("MISMATCH", f"run {run_id} tested a different commit", run.id)
    else:
        same = [r for r in runs if r.attrs.get("sha") == sha]
        if not same:
            return EvidenceState("PENDING", "no test run recorded for this commit")
        run = max(same, key=lambda r: r.attrs["seq"])  # a later lookup replaces an earlier one
    if run.attrs.get("status") != "completed":
        return EvidenceState("PENDING", "test run not finished", run.id)
    if run.attrs.get("conclusion") == "success":
        return EvidenceState("VALIDATED", "passing run for the same sha", run.id)
    return EvidenceState("FAILED", f"run concluded {run.attrs.get('conclusion')}", run.id)


def acceptance_state(g: ProvenanceGraph, pr_id: str) -> EvidenceState:
    """ACCEPTED only for a merged pull request whose head commit is VALIDATED."""
    pr = g.nodes.get(pr_id)
    if pr is None or pr.attrs.get("kind") != "pull_request":
        return EvidenceState("PENDING", "unknown pull request")
    if not pr.attrs.get("merged"):
        return EvidenceState("PENDING", "not merged")
    head = pr.attrs.get("head_sha")
    ev = validate_artifact(g, head) if head else EvidenceState("PENDING", "no head sha")
    if ev.state == "VALIDATED":
        return EvidenceState("ACCEPTED", "merged, and the head commit passed its tests", ev.run_node)
    return EvidenceState("MERGED", f"merged, but the head commit is {ev.state}: {ev.reason}", ev.run_node)


def accepted_commits(g: ProvenanceGraph) -> dict[str, str]:
    """{commit artifact id: pull request id} for every ACCEPTED pull request."""
    out: dict[str, str] = {}
    commits = {c.attrs.get("sha"): c.id for c in _observed(g, "git_commit")}
    for pr in _observed(g, "pull_request"):
        if acceptance_state(g, pr.id).state == "ACCEPTED":
            cid = commits.get(pr.attrs.get("head_sha"))
            if cid:
                out.setdefault(cid, pr.id)
    return out
