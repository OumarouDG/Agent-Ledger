"""A deliberately small, illustrative impact policy. It counts; it does not value.

reuse_count_v1: every ACCEPTED deliverable gives one reuse credit to each unique upstream
artifact reachable along confirmed edges. The number is a count of verified influence. It is
not a share of business value, and it says nothing about how good any agent is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evidence import accepted_commits
from .lineage import all_paths, trace_downstream, trace_upstream
from .models import ProvenanceGraph

POLICY = "reuse_count_v1"
ASSUMPTIONS = (
    "Only ACCEPTED deliverables count (merged, head commit passed its tests).",
    "Only confirmed edges count. Candidate and reported edges are ignored.",
    "A shared upstream artifact gets one credit per accepted deliverable, however many paths lead to it.",
    "A credit is a count of verified influence, not a share of value.",
)


@dataclass
class ImpactReport:
    policy: str = POLICY
    assumptions: tuple[str, ...] = ASSUMPTIONS
    credits: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"policy": self.policy, "assumptions": list(self.assumptions),
                "credits": {k: self.credits[k] for k in sorted(self.credits)}}


def reuse_credits(g: ProvenanceGraph) -> ImpactReport:
    report = ImpactReport()
    for accepted, pr in sorted(accepted_commits(g).items()):
        for upstream in trace_upstream(g, accepted).artifacts:
            c = report.credits.setdefault(upstream, {"count": 0, "accepted_deliverables": [], "paths": {}})
            c["count"] += 1
            c["accepted_deliverables"].append({"artifact": accepted, "pull_request": pr})
            c["paths"][accepted] = all_paths(g, accepted, upstream)
    return report


def regression_impact(g: ProvenanceGraph, artifact_id: str) -> dict:
    """A defect reported on one artifact. Reports what depends on it. Blames nobody upstream."""
    down = trace_downstream(g, artifact_id)
    up = trace_upstream(g, artifact_id)
    return {
        "artifact": artifact_id,
        "found": down.found,
        "affected_downstream": down.artifacts,
        "upstream_not_assigned": up.artifacts,
        "statement": ("The defect is associated with this artifact only. Upstream artifacts are "
                      "listed for investigation, not blamed: no verified causal link points at them."),
    }
