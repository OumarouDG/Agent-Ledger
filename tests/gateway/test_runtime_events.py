"""A runtime-shaped workflow (Lead, Coder, Tester, Rogue; child grants) shows up whole in
work_chain.py and in audit_report.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import audit_report  # noqa: E402
import work_chain  # noqa: E402

SHA = "a" * 40
WF = "wf_002"


def _e(i, agent, grant, tool, decision, **kw):
    return {"event_id": f"evt_{i}", "ts": 1000 + i, "agent_id": agent, "grant_id": grant,
            "workflow_id": WF, "human_id": "alice", "tool": tool, "decision": decision,
            "activity_id": f"act_{i}", **kw}


EVENTS = [
    _e(1, "agent_lead", "gr_root", "get_issue", "outcome", status="succeeded",
       artifact={"kind": "issue", "repository": "o/r", "number": 1, "state": "open"}),
    _e(2, "agent_coder", "gr_coder", "create_branch", "outcome", status="succeeded",
       artifact={"kind": "git_branch", "branch": "agentledger/wf_002/coder/x", "sha": "b" * 40}),
    _e(3, "agent_coder", "gr_coder", "commit_file", "outcome", status="succeeded",
       artifact={"kind": "git_commit", "branch": "agentledger/wf_002/coder/x",
                 "path": "greeting.py", "sha": SHA}),
    _e(4, "agent_tester", "gr_tester", "get_test_result", "outcome", status="succeeded",
       artifact={"kind": "test_run", "sha": SHA, "run_id": 7, "status": "completed",
                 "conclusion": "success", "url": "u"}),
    _e(5, "agent_coder", "gr_coder", "open_pull_request", "outcome", status="succeeded",
       artifact={"kind": "pull_request", "number": 4, "sha": SHA, "merged": False}),
    _e(6, "agent_tester", "gr_tester", "get_pull_request", "outcome", status="succeeded",
       artifact={"kind": "pull_request", "number": 4, "sha": SHA, "merged": True,
                 "merged_by": "alice", "approved_by": []}),
    _e(7, "agent_coder", "gr_coder", "create_branch", "deny", reason="parent_grant_revoked"),
    _e(8, "agent_rogue", "gr_rogue", "create_branch", "deny", reason="tool_not_permitted"),
]


def test_work_chain_reports_the_whole_runtime_workflow():
    text = work_chain.render(WF, work_chain.build(EVENTS)[WF])
    for agent in ("agent_lead", "agent_coder", "agent_tester", "agent_rogue"):
        assert agent in text
    assert "VALIDATED" in text and "ACCEPTED" in text
    assert "parent_grant_revoked" in text


def test_audit_report_shows_every_runtime_agent_and_denial():
    html = audit_report.render(EVENTS, WF)
    for agent in ("agent_lead", "agent_coder", "agent_tester", "agent_rogue"):
        assert agent in html
    assert "parent_grant_revoked" in html and "merged_by=alice" in html
