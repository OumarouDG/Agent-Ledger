"""Workflow metrics with the numerator, denominator, evidence level and event ids behind each.

An activity (one guarded call) can have a decision line, an outcome line and a usage line. It is
counted once. A call with no outcome is UNKNOWN, not succeeded. Token counts are not dollars.
"""

from __future__ import annotations

from .evidence import acceptance_state, accepted_commits, validate_artifact
from .lineage import trace_downstream, trace_upstream
from .models import EXTERNAL, VERIFIED, ProvenanceGraph


def _m(value, *, numerator=None, denominator=None, evidence: str, event_ids=(), missing=(),
       note: str = "", **extra) -> dict:
    out = {"value": value, "numerator": numerator, "denominator": denominator,
           "evidence_level": evidence, "event_ids": sorted(set(event_ids)),
           "missing": sorted(set(missing))}
    if note:
        out["note"] = note
    out.update(extra)
    return out


def _rate(num: int, den: int):
    return None if den == 0 else round(num / den, 4)


def _activities(g: ProvenanceGraph, workflow_id: str) -> list:
    return sorted((n for n in g.nodes.values() if n.type == "Activity"
                   and n.attrs.get("workflow_id") == workflow_id), key=lambda n: n.id)


def _generated_by_workflow(g: ProvenanceGraph, workflow_id: str, kind: str) -> list:
    acts = {a.id for a in _activities(g, workflow_id)}
    return [n for n in sorted(g.nodes.values(), key=lambda n: n.id)
            if n.type == "Artifact" and n.attrs.get("kind") == kind and n.attrs.get("observed")
            and acts & set(n.attrs.get("generated_by", []))]


def metrics_for_workflow(g: ProvenanceGraph, workflow_id: str) -> dict:
    acts = _activities(g, workflow_id)
    wf_events = [e for e in g.events if e.get("workflow_id") == workflow_id]
    stamps = [e["ts"] for e in wf_events if isinstance(e.get("ts"), (int, float))]
    guarded = [a for a in acts if a.attrs.get("kind") == "decision" and a.attrs.get("decision") in ("allow", "deny")]
    allowed = [a for a in guarded if a.attrs["decision"] == "allow"]
    denied = [a for a in guarded if a.attrs["decision"] == "deny"]

    by_call: dict[str, int] = {}
    for a in guarded:
        k = f"{a.attrs.get('agent_id') or '?'}/{a.attrs.get('tool') or '?'}"
        by_call[k] = by_call.get(k, 0) + 1

    ok = [a for a in allowed if a.attrs.get("outcome_status") == "succeeded"]
    bad = [a for a in allowed if a.attrs.get("outcome_status") == "failed"]
    unknown = [a for a in allowed if a.attrs.get("outcome_status") not in ("succeeded", "failed")]

    usage = [a.attrs["usage"] for a in acts if a.attrs.get("usage")]
    tin = sum(u.get("input_tokens") or 0 for u in usage)
    tout = sum(u.get("output_tokens") or 0 for u in usage)

    commits = [c for c in _generated_by_workflow(g, workflow_id, "git_commit")
               if c.attrs.get("evidence_level") == EXTERNAL]
    validated = [c for c in commits if validate_artifact(g, c.attrs["sha"]).state == "VALIDATED"]
    prs = _generated_by_workflow(g, workflow_id, "pull_request")
    accepted = [p for p in prs if acceptance_state(g, p.id).state == "ACCEPTED"]

    own = {c.id for c in commits}
    upstream: set[str] = set()
    reuse: set[str] = set()
    accepted_all = set(accepted_commits(g))
    for c in commits:
        upstream.update(trace_upstream(g, c.id).artifacts)
        reuse.update(d for d in trace_downstream(g, c.id).artifacts if d in accepted_all and d not in own)

    src = lambda nodes: [i for n in nodes for i in n.attrs.get("source_event_ids", [])]  # noqa: E731

    return {
        "workflow_id": workflow_id,
        "window": {"first_ts": min(stamps) if stamps else None, "last_ts": max(stamps) if stamps else None},
        "guarded_decisions": _m(len(guarded), evidence=VERIFIED, event_ids=[a.attrs["decision_event_id"] for a in guarded],
                                breakdown=dict(sorted(by_call.items())),
                                note="distinct activities; identity calls (ping, whoami) excluded"),
        "denial_rate": _m(_rate(len(denied), len(guarded)), numerator=len(denied), denominator=len(guarded),
                          evidence=VERIFIED, event_ids=[a.attrs["decision_event_id"] for a in denied],
                          reasons=_count(a.attrs.get("reason") for a in denied)),
        "execution_failure_rate": _m(_rate(len(bad), len(ok) + len(bad)), numerator=len(bad),
                                     denominator=len(ok) + len(bad), evidence=VERIFIED,
                                     event_ids=[a.attrs["outcome_event_id"] for a in bad if "outcome_event_id" in a.attrs],
                                     missing=[a.id for a in unknown],
                                     unknown_outcomes=len(unknown),
                                     note="allowed calls with no outcome line are UNKNOWN and not counted as succeeded"),
        "model_usage": _m(len(usage), evidence=VERIFIED, event_ids=[u["event_id"] for u in usage],
                          input_tokens=tin, output_tokens=tout,
                          note="tokens, not USD; a price needs model id, date, region and a versioned table"),
        "grant_locks": _m(sum(1 for a in acts if a.attrs.get("locked")), evidence=VERIFIED,
                          event_ids=[a.attrs["lock_event_id"] for a in acts if a.attrs.get("locked")]),
        "verified_commits": _m(len(commits), evidence=EXTERNAL, event_ids=src(commits),
                               artifacts=[c.id for c in commits]),
        "validated_deliverables": _m(len(validated), numerator=len(validated), denominator=len(commits),
                                     evidence=EXTERNAL, event_ids=src(validated),
                                     artifacts=[c.id for c in validated],
                                     note="passing GitHub run for the exact same sha"),
        "accepted_deliverables": _m(len(accepted), numerator=len(accepted), denominator=len(prs),
                                    evidence=EXTERNAL, event_ids=src(accepted),
                                    artifacts=[p.id for p in accepted],
                                    note="merged and head commit validated; a merge is not an approval"),
        "verified_upstream_artifacts": _m(len(upstream), evidence=EXTERNAL, artifacts=sorted(upstream),
                                          note="confirmed lineage edges only"),
        "confirmed_downstream_reuse": _m(len(reuse), evidence=EXTERNAL, artifacts=sorted(reuse),
                                         note="accepted deliverables from other work that derive from this workflow's commits"),
        "not_computed": ["first_pass_ci_success", "cost_usd_per_verified_outcome", "value_score"],
    }


def _count(items) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[str(i)] = out.get(str(i), 0) + 1
    return dict(sorted(out.items()))
