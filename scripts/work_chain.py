"""Print, per workflow, the chain from issue to accepted change, using only audit evidence.

    python scripts/work_chain.py                      # gateway-audit.jsonl in the cwd
    python scripts/work_chain.py path/to/audit.jsonl
    python scripts/work_chain.py --workflow wf_001

Read-only. A step is VALIDATED or ACCEPTED only when GitHub's own answer is in the audit:
a passing test run for that exact commit SHA, and a pull request GitHub says was merged.
Anything missing says PENDING. Nothing is inferred and nothing is scored.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_timeline import load  # noqa: E402

DEFAULT_PATH = "gateway-audit.jsonl"


def _artifacts(events, kind):
    """Successful outcomes of one kind, oldest first, one per activity."""
    seen, out = set(), []
    for e in events:
        a = e.get("artifact") or {}
        if (e.get("decision") == "outcome" and e.get("status") == "succeeded"
                and a.get("kind") == kind and e.get("activity_id") not in seen):
            seen.add(e.get("activity_id"))
            out.append((e, a))
    return out


def build(events: list[dict]) -> dict[str, dict]:
    """Group the evidence by workflow. Returns {workflow_id: report dict}."""
    by_wf: dict[str, list[dict]] = {}
    for e in events:
        if e.get("workflow_id"):
            by_wf.setdefault(e["workflow_id"], []).append(e)
    return {wf: _report(evs) for wf, evs in by_wf.items()}


def _report(evs: list[dict]) -> dict:
    owners = sorted({e["human_id"] for e in evs if e.get("human_id")})
    agents = sorted({e["agent_id"] for e in evs if e.get("agent_id")})
    grants = sorted({e["grant_id"] for e in evs if e.get("grant_id")})
    runs: dict[str, dict] = {}
    for _, a in _artifacts(evs, "test_run"):
        runs[a["sha"]] = a  # later lookups replace earlier ones
    commits = []
    for e, a in _artifacts(evs, "git_commit"):
        run = runs.get(a.get("sha"))
        if run is None:
            state = "PENDING (no test run recorded for this commit)"
        elif run.get("conclusion") == "success":
            state = "VALIDATED"
        elif run.get("status") != "completed":
            state = "PENDING (test run not finished)"
        else:
            state = f"FAILED ({run.get('conclusion')})"
        commits.append({"sha": a["sha"], "branch": a.get("branch"), "path": a.get("path"),
                        "tests": run, "state": state})
    prs: dict[int, dict] = {}
    for _, a in _artifacts(evs, "pull_request"):
        prs[a["number"]] = a  # latest reading of each pull request wins
    validated = {c["sha"] for c in commits if c["state"] == "VALIDATED"}
    pull_requests = []
    for number, a in sorted(prs.items()):
        if a.get("merged") and a.get("sha") in validated:
            state = "ACCEPTED (merged, head commit passed its tests)"
        elif a.get("merged"):
            state = "MERGED but the head commit has no passing test recorded"
        else:
            state = "PENDING (not merged)"
        pull_requests.append({**a, "state": state})
    denies = [e for e in evs if e.get("decision") == "deny"]
    reasons: dict[str, int] = {}
    for e in denies:
        reasons[e.get("reason")] = reasons.get(e.get("reason"), 0) + 1
    return {
        "owners": owners, "agents": agents, "grants": grants,
        "issues": [a for _, a in _artifacts(evs, "issue")],
        "branches": [a for _, a in _artifacts(evs, "git_branch")],
        "commits": commits, "pull_requests": pull_requests,
        "denied": len(denies), "denied_reasons": reasons,
        "locks": sum(1 for e in evs if e.get("decision") == "lock"),
        "failed": sum(1 for e in evs if e.get("decision") == "outcome" and e.get("status") == "failed"),
    }


def render(wf: str, r: dict) -> str:
    out = [f"Workflow {wf}",
           f"  owner(s): {', '.join(r['owners']) or '?'}   agent(s): {', '.join(r['agents']) or '?'}"
           f"   grant(s): {', '.join(r['grants']) or '?'}"]
    for i in r["issues"]:
        out.append(f"  issue         #{i.get('number')} in {i.get('repository')} (read from GitHub)")
    for b in r["branches"]:
        out.append(f"  branch        {b.get('branch')} at {str(b.get('sha'))[:10]}")
    for c in r["commits"]:
        out.append(f"  commit        {c['sha'][:10]}  {c.get('path')}  on {c.get('branch')}")
        t = c["tests"]
        detail = f"run {t['run_id']}, {t.get('conclusion') or t.get('status')}" if t else "none yet"
        out.append(f"    tests       {c['state']}  [{detail}]")
    if not r["commits"]:
        out.append("  commit        none recorded")
    for p in r["pull_requests"]:
        who = f", merged by {p['merged_by']}" if p.get("merged_by") else ""
        appr = f", approved by {', '.join(p['approved_by'])}" if p.get("approved_by") else ""
        out.append(f"  pull request  #{p['number']}{who}{appr}")
        out.append(f"    acceptance  {p['state']}")
    if not r["pull_requests"]:
        out.append("  pull request  none recorded")
    why = ", ".join(f"{k} x{n}" for k, n in sorted(r["denied_reasons"].items()))
    out.append(f"  refused       {r['denied']} call(s)" + (f" ({why})" if why else "")
               + f"; {r['locks']} lock(s); {r['failed']} failed action(s)")
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH)
    ap.add_argument("--workflow", help="show only this workflow id")
    args = ap.parse_args(argv)
    try:
        with open(args.path, encoding="utf-8") as f:
            events, bad = load(f)
    except OSError as e:
        print(f"cannot read {args.path}: {type(e).__name__}", file=sys.stderr)
        return 2
    reports = build(events)
    if args.workflow:
        reports = {k: v for k, v in reports.items() if k == args.workflow}
    if not reports:
        print("no workflow evidence found")
    for wf, r in sorted(reports.items()):
        print(render(wf, r))
        print()
    for n, text in bad:
        print(f"WARNING: line {n} is not valid JSON: {text!r}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
