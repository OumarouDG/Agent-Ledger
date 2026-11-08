"""SYNTHETIC events for showing cross-workflow lineage. Nothing here happened.

The real audit has one workflow per issue. To show a chain across workflows before one exists,
this builds audit lines in the gateway's own shape for three invented commits (A, B, C) in
three invented workflows. Reports label everything built from it SYNTHETIC.
"""

from __future__ import annotations

from .build import Declaration

REPO = "synthetic/demo"
LABEL = "SYNTHETIC SAMPLE: invented events, not from the gateway"


def sha(c: str) -> str:
    return c * 40


def commit_id(c: str) -> str:
    return f"artifact:{REPO}:{sha(c)}"


def _line(n: int, kind: str, tool: str, wf: str, act: str, **kw) -> dict:
    return {"event_id": f"evt_syn_{n:04d}", "ts": 1_000_000 + n, "event": kind, "tool": tool,
            "workflow_id": wf, "agent_id": "agent_coder", "grant_id": f"gr_syn_{wf}",
            "human_id": "alice", "activity_id": act, **kw}


def sample_events() -> list[dict]:
    out: list[dict] = []
    n = 0

    def add(kind, tool, wf, act, **kw):
        nonlocal n
        n += 1
        out.append(_line(n, kind, tool, wf, act, **kw))

    for i, c in enumerate("abc"):
        wf, num = f"wf_syn_{c}", i + 1
        for tool, art in (
            ("commit_file", {"kind": "git_commit", "repository": REPO, "sha": sha(c),
                             "branch": f"agentledger/{wf}/x", "path": f"{c}.py"}),
            ("get_test_result", {"kind": "test_run", "repository": REPO, "sha": sha(c),
                                 "run_id": 100 + i, "status": "completed", "conclusion": "success",
                                 "url": "synthetic"}),
            ("open_pull_request", {"kind": "pull_request", "repository": REPO, "number": num,
                                   "sha": sha(c), "state": "open", "merged": False}),
            ("get_pull_request", {"kind": "pull_request", "repository": REPO, "number": num,
                                  "sha": sha(c), "state": "closed", "merged": True,
                                  "merged_by": "synthetic-reviewer", "approved_by": []}),
        ):
            act = f"act_syn_{c}_{tool}"
            add("decision", tool, wf, act, decision="allow", reason="allowed", resource={})
            add("outcome", tool, wf, act, decision="outcome", status="succeeded",
                reason="completed", artifact=art, evidence="external", source="github_api")
    return out


def sample_declarations() -> list[Declaration]:
    """C was built on B, and B on A."""
    return [Declaration(commit_id("c"), commit_id("b"), "agent_coder", note="synthetic"),
            Declaration(commit_id("b"), commit_id("a"), "agent_coder", note="synthetic")]
