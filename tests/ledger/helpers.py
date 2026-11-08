"""Event builders shaped like the gateway's real audit lines. No AWS, no network."""

from __future__ import annotations

import itertools

REPO = "o/r"
_ids = itertools.count(1)
_ts = itertools.count(1000)


def sha(c: str) -> str:
    return c * 40


def ev(kind, tool, wf, *, agent="agent_coder", grant="gr_1", human="alice", act=None, **kw):
    """One audit line. kind is decision | outcome | usage | sentinel."""
    n = next(_ids)
    base = {"event_id": f"evt_{n:04d}", "ts": next(_ts), "event": kind, "tool": tool,
            "workflow_id": wf, "agent_id": agent, "grant_id": grant, "human_id": human,
            "activity_id": act or f"act_{n:04d}"}
    base.update(kw)
    return base


def allowed(tool, wf, act, **kw):
    return ev("decision", tool, wf, act=act, decision="allow", reason="allowed", resource={}, **kw)


def denied(tool, wf, act, reason="branch_not_permitted", **kw):
    return ev("decision", tool, wf, act=act, decision="deny", reason=reason, resource={}, **kw)


def done(tool, wf, act, artifact, **kw):
    return ev("outcome", tool, wf, act=act, decision="outcome", status="succeeded", reason="completed",
              artifact=artifact, evidence="external", source="github_api", **kw)


def commit_events(wf, c, repo=REPO, branch=None, path="f.py"):
    """get the decision + outcome for committing sha(c) on a branch."""
    act = f"act_commit_{wf}_{c}"
    return [allowed("commit_file", wf, act),
            done("commit_file", wf, act, {"kind": "git_commit", "repository": repo, "sha": sha(c),
                                          "branch": branch or f"agentledger/{wf}/b", "path": path})]


def run_events(wf, c, conclusion="success", status="completed", run_id=None, repo=REPO, tested_sha=None):
    act = f"act_run_{wf}_{c}_{run_id or ''}"
    return [allowed("get_test_result", wf, act, agent="agent_tester"),
            done("get_test_result", wf, act,
                 {"kind": "test_run", "repository": repo, "sha": tested_sha or sha(c),
                  "run_id": run_id or ord(c), "status": status, "conclusion": conclusion, "url": "u"},
                 agent="agent_tester")]


def pr_events(wf, c, number, merged=True, by="OumarouDG", repo=REPO, head=None, approved=None):
    act = f"act_pr_{wf}_{number}"
    return [allowed("open_pull_request", wf, act),
            done("open_pull_request", wf, act,
                 {"kind": "pull_request", "repository": repo, "number": number, "sha": head or sha(c),
                  "state": "open", "merged": False}),
            *([allowed("get_pull_request", wf, act + "r", agent="agent_tester"),
               done("get_pull_request", wf, act + "r",
                    {"kind": "pull_request", "repository": repo, "number": number, "sha": head or sha(c),
                     "state": "closed", "merged": True, "merged_by": by, "approved_by": approved or []},
                    agent="agent_tester")] if merged else [])]


def accepted_workflow(wf, c, number, repo=REPO):
    """A whole accepted chain: commit, passing run, merged PR."""
    return [*commit_events(wf, c, repo), *run_events(wf, c, repo=repo), *pr_events(wf, c, number, repo=repo)]


def cid(c, repo=REPO):
    return f"artifact:{repo}:{sha(c)}"
