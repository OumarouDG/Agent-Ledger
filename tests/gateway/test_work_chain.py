"""work_chain.py: only GitHub-confirmed evidence can make a step VALIDATED or ACCEPTED."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "work_chain", Path(__file__).resolve().parents[2] / "scripts" / "work_chain.py")
wc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wc)

SHA = "a" * 40
OTHER = "b" * 40
BASE = {"workflow_id": "wf1", "agent_id": "agent_coder", "human_id": "alice", "grant_id": "g1"}
_n = [0]


def event(kind, outcome_status="succeeded", **artifact):
    _n[0] += 1
    return {**BASE, "decision": "outcome", "status": outcome_status, "activity_id": f"act_{_n[0]}",
            "tool": "x", "artifact": {"kind": kind, **artifact}}


def commit_event(sha=SHA):
    return event("git_commit", sha=sha, branch="agentledger/wf1/f", path="g.py", repository="o/r")


def run_event(sha=SHA, conclusion="success", status="completed", run_id=1):
    return event("test_run", sha=sha, conclusion=conclusion, status=status, run_id=run_id)


def pr_event(merged, sha=SHA, number=7, by="OumarouDG", approved=None):
    return event("pull_request", number=number, sha=sha, merged=merged, merged_by=by if merged else None,
               approved_by=approved)


def report(*events):
    return wc.build(list(events))["wf1"]


def test_commit_without_a_test_run_is_pending():
    r = report(commit_event())
    assert r["commits"][0]["state"].startswith("PENDING")


def test_commit_is_validated_only_by_a_passing_run_for_that_exact_sha():
    assert report(commit_event(), run_event())["commits"][0]["state"] == "VALIDATED"
    other = report(commit_event(), run_event(sha=OTHER))["commits"][0]["state"]
    assert other.startswith("PENDING")


def test_failed_and_unfinished_runs_never_validate():
    assert report(commit_event(), run_event(conclusion="failure"))["commits"][0]["state"] == "FAILED (failure)"
    assert report(commit_event(), run_event(status="in_progress", conclusion=None))["commits"][0][
        "state"].startswith("PENDING")


def test_a_later_passing_run_replaces_an_earlier_failure():
    r = report(commit_event(), run_event(conclusion="failure", run_id=1), run_event(run_id=2))
    assert r["commits"][0]["state"] == "VALIDATED" and r["commits"][0]["tests"]["run_id"] == 2


def test_merged_pull_request_is_accepted_only_if_its_head_commit_passed():
    good = report(commit_event(), run_event(), pr_event(True))["pull_requests"][0]["state"]
    assert good.startswith("ACCEPTED")
    untested = report(commit_event(), pr_event(True))["pull_requests"][0]["state"]
    assert untested.startswith("MERGED but")
    wrong_head = report(commit_event(), run_event(), pr_event(True, sha=OTHER))["pull_requests"][0]["state"]
    assert wrong_head.startswith("MERGED but")


def test_unmerged_pull_request_is_pending():
    assert report(commit_event(), run_event(), pr_event(False))["pull_requests"][0]["state"].startswith("PENDING")


def test_failed_actions_leave_no_artifacts_and_are_counted():
    r = report(event("git_commit", outcome_status="failed", sha=SHA), commit_event(OTHER))
    assert [c["sha"] for c in r["commits"]] == [OTHER] and r["failed"] == 1


def test_the_same_activity_is_not_counted_twice():
    c = commit_event()
    assert len(report(c, dict(c))["commits"]) == 1


def test_denials_and_locks_are_summarised():
    r = report(commit_event(), {**BASE, "decision": "deny", "reason": "branch_not_permitted"},
               {**BASE, "decision": "deny", "reason": "branch_not_permitted"},
               {**BASE, "decision": "lock"})
    assert r["denied"] == 2 and r["denied_reasons"] == {"branch_not_permitted": 2} and r["locks"] == 1


def test_render_says_pending_when_nothing_is_recorded():
    text = wc.render("wf1", report({**BASE, "decision": "allow"}))
    assert "none recorded" in text and "ACCEPTED" not in text and "VALIDATED" not in text


def test_cli_prints_the_chain_and_handles_missing_files(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in (commit_event(), run_event(), pr_event(True))) + "\n")
    assert wc.main([str(p)]) == 0
    printed = capsys.readouterr().out
    assert "VALIDATED" in printed and "ACCEPTED" in printed and "merged by OumarouDG" in printed
    assert wc.main([str(tmp_path / "nope.jsonl")]) == 2
    assert "cannot read" in capsys.readouterr().err
    assert wc.main([str(p), "--workflow", "nope"]) == 0
    assert "no workflow evidence" in capsys.readouterr().out
