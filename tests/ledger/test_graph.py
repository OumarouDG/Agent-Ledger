"""Graph construction, evidence states and metric integrity (brief section 10)."""

import importlib.util
import json
from pathlib import Path

from ledger import (Declaration, acceptance_state, build_graph, metrics_for_workflow,
                    validate_artifact)
from tests.ledger.helpers import (REPO, accepted_workflow, allowed, cid, commit_events, denied, done,
                                  ev, pr_events, run_events, sha)

WF = "wf_a"


def _wc():
    spec = importlib.util.spec_from_file_location(
        "work_chain", Path(__file__).resolve().parents[2] / "scripts" / "work_chain.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_same_event_twice_is_one_fact():
    events = accepted_workflow(WF, "a", 1)
    once, twice = build_graph(events), build_graph(events + events)
    assert once.to_dict() == twice.to_dict()
    assert len(twice.events) == len(events)


def test_decision_outcome_and_usage_are_one_activity():
    act = "act_model"
    events = [allowed("llm_converse", WF, act),
              ev("usage", "llm_converse", WF, act=act, decision="usage", status="succeeded",
                 resource={"model": "m", "input_tokens": 10, "output_tokens": 5})]
    g = build_graph(events)
    m = metrics_for_workflow(g, WF)
    assert m["guarded_decisions"]["value"] == 1
    assert m["model_usage"]["value"] == 1 and m["model_usage"]["input_tokens"] == 10
    assert m["execution_failure_rate"]["missing"] == []  # usage counts as a recorded result


def test_commit_without_matching_run_is_never_validated():
    g = build_graph([*commit_events(WF, "a"), *run_events(WF, "a", tested_sha=sha("b"), run_id=9)])
    assert validate_artifact(g, sha("a")).state == "PENDING"
    assert validate_artifact(g, sha("a"), run_id=9).state == "MISMATCH"


def test_failed_or_unfinished_runs_do_not_validate():
    failed = build_graph([*commit_events(WF, "a"), *run_events(WF, "a", conclusion="failure")])
    assert validate_artifact(failed, sha("a")).state == "FAILED"
    running = build_graph([*commit_events(WF, "a"),
                           *run_events(WF, "a", status="in_progress", conclusion=None)])
    assert validate_artifact(running, sha("a")).state == "PENDING"


def test_merged_pull_request_with_unvalidated_head_is_merged_not_accepted():
    g = build_graph([*commit_events(WF, "a"), *pr_events(WF, "a", 7)])
    assert acceptance_state(g, f"artifact:{REPO}:pr:7").state == "MERGED"
    ok = build_graph(accepted_workflow(WF, "a", 7))
    assert acceptance_state(ok, f"artifact:{REPO}:pr:7").state == "ACCEPTED"
    wrong_head = build_graph([*commit_events(WF, "a"), *run_events(WF, "a"),
                              *pr_events(WF, "a", 7, head=sha("b"))])
    assert acceptance_state(wrong_head, f"artifact:{REPO}:pr:7").state == "MERGED"


def test_accepted_edges_exist_but_approval_is_separate():
    g = build_graph(accepted_workflow(WF, "a", 7))
    rels = {(e.relation, e.to_id) for e in g.edges.values() if e.from_id == f"artifact:{REPO}:pr:7"}
    assert ("ACCEPTED_BY", "human:github/OumarouDG") in rels
    assert not any(r == "APPROVED_BY" for r, _ in rels)  # merged is not approved


def test_denied_call_gets_no_authorized_by_edge():
    g = build_graph([allowed("get_issue", WF, "act_ok"), denied("create_branch", WF, "act_no")])
    ok = {e.relation for e in g.edges.values() if e.from_id == "activity:act_ok"}
    no = {e.relation for e in g.edges.values() if e.from_id == "activity:act_no"}
    assert {"AUTHORIZED_BY", "EXECUTED_BY"} <= ok
    assert "AUTHORIZED_BY" not in no and "EXECUTED_BY" not in no and "REQUESTED_BY" in no


def test_missing_outcome_is_unknown_not_succeeded():
    g = build_graph([allowed("commit_file", WF, "act_1"),
                     allowed("create_branch", WF, "act_2"),
                     done("create_branch", WF, "act_2", {"kind": "git_branch", "repository": REPO,
                                                         "branch": "agentledger/wf_a/b", "sha": sha("0")})])
    m = metrics_for_workflow(g, WF)["execution_failure_rate"]
    assert m["unknown_outcomes"] == 1 and m["missing"] == ["activity:act_1"]
    assert m["denominator"] == 1  # only the recorded outcome is in the denominator


def test_old_records_without_new_fields_still_parse():
    old = [{"ts": 1, "decision": "allow", "agent_id": "agent_coder", "tool": "get_issue"},
           {"ts": 2, "decision": "deny", "reason": "unknown_grant", "tool": "get_issue"},
           {"ts": 3, "decision": "outcome", "status": "succeeded", "tool": "x", "workflow_id": "w",
            "artifact": {"kind": "git_commit", "sha": sha("a")}}]
    g = build_graph(old)
    assert len(g.events) == 3
    assert f"artifact:unknown:{sha('a')}" in g.nodes


def test_every_metric_number_links_to_event_ids():
    events = [*accepted_workflow(WF, "a", 1), denied("create_branch", WF, "act_no")]
    g = build_graph(events)
    m = metrics_for_workflow(g, WF)
    ids = {e["event_id"] for e in events}
    for name in ("guarded_decisions", "denial_rate", "verified_commits", "validated_deliverables",
                 "accepted_deliverables"):
        assert m[name]["event_ids"], name
        assert set(m[name]["event_ids"]) <= ids, name
    # 4 allowed calls in the chain (commit, test lookup, open PR, read PR) plus 1 denial
    assert m["denial_rate"]["numerator"] == 1 and m["denial_rate"]["denominator"] == 5
    assert m["accepted_deliverables"]["value"] == 1


def test_build_is_deterministic_and_json_safe():
    events = [*accepted_workflow(WF, "a", 1), *accepted_workflow("wf_b", "b", 2)]
    a, b = build_graph(events).to_dict(), build_graph(list(events)).to_dict()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_agrees_with_work_chain_on_the_same_events():
    wc = _wc()
    cases = {
        "accepted": accepted_workflow(WF, "a", 1),
        "merged_untested": [*commit_events(WF, "a"), *pr_events(WF, "a", 1)],
        "pending": [*commit_events(WF, "a"), *pr_events(WF, "a", 1, merged=False)],
        "failed": [*commit_events(WF, "a"), *run_events(WF, "a", conclusion="failure"),
                   *pr_events(WF, "a", 1)],
    }
    for name, events in cases.items():
        report = wc.build(events)[WF]
        g = build_graph(events)
        mine = acceptance_state(g, f"artifact:{REPO}:pr:1").state
        theirs = report["pull_requests"][0]["state"].split()[0]
        assert mine == theirs.rstrip(":"), (name, mine, theirs)
        commit_state = validate_artifact(g, sha("a")).state
        assert report["commits"][0]["state"].split()[0] == commit_state, name


def test_audit_report_inputs_unchanged_by_graph_build():
    events = accepted_workflow(WF, "a", 1)
    before = json.dumps(events, sort_keys=True)
    build_graph(events)
    assert json.dumps(events, sort_keys=True) == before  # read-only consumer
