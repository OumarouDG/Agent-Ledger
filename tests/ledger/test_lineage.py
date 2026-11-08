"""Cross-workflow lineage: chains, diamonds, cycles, candidates, reuse counts, regressions."""

from ledger import (Declaration, build_graph, metrics_for_workflow, regression_impact,
                    reuse_credits, trace_downstream, trace_upstream)
from tests.ledger.helpers import accepted_workflow, cid, commit_events


def decl(frm, to, by="agent_coder"):
    return Declaration(cid(frm), cid(to), by)


def world(*pairs, extra=()):
    """Workflows wf_x for each commit letter, all accepted, plus the given declarations."""
    letters = sorted({c for p in pairs for c in p} | set(extra))
    events = [e for i, c in enumerate(letters) for e in accepted_workflow(f"wf_{c}", c, 10 + i)]
    return build_graph(events, [decl(a, b) for a, b in pairs])


def test_a_b_c_chain_traces_back_through_every_workflow():
    g = world(("c", "b"), ("b", "a"))  # C built on B, B built on A
    up = trace_upstream(g, cid("c"))
    assert up.artifacts == [cid("b"), cid("a")]
    assert trace_downstream(g, cid("a")).artifacts == [cid("b"), cid("c")]
    assert trace_upstream(g, cid("a")).artifacts == []


def test_diamond_counts_the_shared_root_once():
    g = world(("d", "b"), ("d", "c"), ("b", "a"), ("c", "a"))
    up = trace_upstream(g, cid("d"))
    assert sorted(up.artifacts) == sorted([cid("a"), cid("b"), cid("c")])
    assert up.artifacts.count(cid("a")) == 1
    credit = reuse_credits(g).credits[cid("a")]
    # A is reached by D, B and C (each accepted once), and the two routes to D are both shown.
    assert credit["count"] == 3
    assert len(credit["paths"][cid("d")]) == 2


def test_reported_only_dependency_is_not_followed_or_credited():
    # B declares a dependency on a commit that no event ever showed GitHub evidence for.
    g = build_graph(accepted_workflow("wf_b", "b", 2), [decl("b", "z")])
    edge = next(e for e in g.edges.values() if e.relation == "DERIVED_FROM")
    assert (edge.evidence_level, edge.confidence) == ("reported", "candidate")
    up = trace_upstream(g, cid("b"))
    assert up.artifacts == [] and [c.to_id for c in up.candidates] == [cid("z")]
    assert reuse_credits(g).credits == {}


def test_declaration_from_unobserved_downstream_is_a_candidate():
    g = build_graph(commit_events("wf_a", "a"), [decl("q", "a")])
    assert trace_upstream(g, cid("q")).artifacts == []


def test_cycle_is_rejected_deterministically():
    # Declarations are applied in sorted order, so a -> b is kept and b -> a closes the loop.
    g = world(("b", "a"), ("a", "b"))
    assert trace_upstream(g, cid("a")).artifacts == [cid("b")]
    assert trace_upstream(g, cid("b")).artifacts == []  # the closing edge was refused
    assert [(r["from"], r["to"], r["reason"]) for r in g.rejected] == [(cid("b"), cid("a"), "cycle")]
    assert g.to_dict() == world(("b", "a"), ("a", "b")).to_dict()  # same answer every time


def test_self_dependency_is_rejected():
    g = world(("a", "a"))
    assert trace_upstream(g, cid("a")).artifacts == []
    assert g.rejected and g.rejected[0]["reason"] == "cycle"


def test_regression_on_c_does_not_blame_a_or_b():
    g = world(("c", "b"), ("b", "a"))
    r = regression_impact(g, cid("c"))
    assert r["affected_downstream"] == []
    assert r["upstream_not_assigned"] == [cid("b"), cid("a")]
    assert "not blamed" in r["statement"]
    mid = regression_impact(g, cid("b"))
    assert mid["affected_downstream"] == [cid("c")]


def test_reuse_credit_counts_only_accepted_deliverables():
    # C is merged but its head never passed tests, so it earns A no credit.
    from tests.ledger.helpers import commit_events as ce, pr_events
    events = [*accepted_workflow("wf_a", "a", 1), *ce("wf_c", "c"), *pr_events("wf_c", "c", 3)]
    g = build_graph(events, [decl("c", "a")])
    assert trace_upstream(g, cid("c")).artifacts == [cid("a")]  # lineage is a fact
    assert reuse_credits(g).credits.get(cid("a")) is None  # but nothing was accepted


def test_workflow_metrics_report_upstream_and_downstream_reuse():
    g = world(("c", "b"), ("b", "a"))
    mb = metrics_for_workflow(g, "wf_b")
    assert mb["verified_upstream_artifacts"]["artifacts"] == [cid("a")]
    assert mb["confirmed_downstream_reuse"]["artifacts"] == [cid("c")]
    ma = metrics_for_workflow(g, "wf_a")
    assert ma["verified_upstream_artifacts"]["value"] == 0
    assert ma["confirmed_downstream_reuse"]["value"] == 2


def test_same_commit_seen_in_two_workflows_is_one_node():
    ev1 = accepted_workflow("wf_one", "a", 1)
    ev2 = commit_events("wf_two", "a")
    g = build_graph(ev1 + ev2)
    commits = [n for n in g.nodes.values() if n.attrs.get("kind") == "git_commit"]
    assert len(commits) == 1 and sorted(commits[0].attrs["workflows"]) == ["wf_one", "wf_two"]
