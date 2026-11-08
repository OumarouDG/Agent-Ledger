"""The evidence chain and the ledger_report command."""

import importlib.util
import json
from pathlib import Path

from ledger import build_graph
from ledger.chain import deliverable_chain
from ledger.sample import sample_declarations, sample_events
from tests.ledger.helpers import REPO, accepted_workflow, commit_events, pr_events, run_events

spec = importlib.util.spec_from_file_location(
    "ledger_report", Path(__file__).resolve().parents[2] / "scripts" / "ledger_report.py")
lr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lr)

PR = f"artifact:{REPO}:pr:7"


def test_accepted_pr_has_every_link_with_evidence():
    g = build_graph(accepted_workflow("wf_a", "a", 7))
    chain = deliverable_chain(g, PR)
    assert chain["state"] == "ACCEPTED" and chain["complete"]
    by = {l["link"]: l for l in chain["links"]}
    assert by["human (grant owner)"]["id"] == "human:alice"
    assert by["agent (verified identity)"]["id"] == "agent:agent_coder"
    assert by["commit"]["sha"] == "a" * 40
    assert by["passing CI, same sha"]["evidence_level"] == "external"
    assert by["merged pull request"]["merged_by"] == "OumarouDG"
    assert all(l["source_event_id"] for l in chain["links"] if l["link"] != "tool activity")


def test_unvalidated_pr_chain_is_marked_incomplete_not_filled_in():
    g = build_graph([*commit_events("wf_a", "a"), *pr_events("wf_a", "a", 7)])
    chain = deliverable_chain(g, PR)
    assert chain["state"] == "MERGED" and not chain["complete"]
    ci = next(l for l in chain["links"] if l["link"].startswith("passing CI"))
    assert ci["missing"] and ci["id"] is None


def test_failed_ci_and_unmerged_pr_are_named_not_hidden():
    """Found on the real audit: an open PR whose CI failed must not look merged or merely missing."""
    g = build_graph([*commit_events("wf_a", "a"), *run_events("wf_a", "a", conclusion="failure"),
                     *pr_events("wf_a", "a", 7, merged=False)])
    chain = deliverable_chain(g, PR)
    by = {l["link"]: l for l in chain["links"]}
    assert by["passing CI, same sha"]["id"] is None
    assert "failure" in by["passing CI, same sha"]["not_passing"]
    assert by["merged pull request"]["id"] is None and by["merged pull request"]["missing"]
    assert not chain["complete"] and chain["state"] == "PENDING"
    from ledger.chain import render_chain
    text = "\n".join(render_chain(chain))
    assert "NOT PASSING" in text and "not merged" in text


def test_open_pr_with_passing_ci_is_incomplete_until_merged():
    g = build_graph([*commit_events("wf_a", "a"), *run_events("wf_a", "a"),
                     *pr_events("wf_a", "a", 7, merged=False)])
    chain = deliverable_chain(g, PR)
    assert not chain["complete"] and chain["state"] == "PENDING"


def test_report_labels_the_synthetic_sample(capsys):
    assert lr.main(["--synthetic"]) == 0
    out = capsys.readouterr().out
    assert "SYNTHETIC SAMPLE" in out and "Reuse credits" in out
    assert "not a share of value" in out or "not value" in out


def test_report_on_a_real_style_file_has_no_synthetic_label(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in accepted_workflow("wf_a", "a", 7)), encoding="utf-8")
    assert lr.main([str(path), "--workflow", "wf_a"]) == 0
    out = capsys.readouterr().out
    assert "SYNTHETIC" not in out and "ACCEPTED" in out
    assert "no cross-workflow dependency recorded" in out


def test_report_json_is_valid_and_complete(tmp_path, capsys):
    assert lr.main(["--synthetic", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["label"].startswith("SYNTHETIC") and doc["graph"]["nodes"] and doc["reuse"]["credits"]


def test_report_reads_a_declarations_file(tmp_path, capsys):
    from ledger.sample import REPO as SREPO, commit_id
    path = tmp_path / "audit.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in sample_events()), encoding="utf-8")
    decls = tmp_path / "deps.json"
    decls.write_text(json.dumps([{"artifact": commit_id("c"), "depends_on": commit_id("a"),
                                  "declared_by": "agent_coder"}]), encoding="utf-8")
    assert lr.main([str(path), "--declarations", str(decls)]) == 0
    assert "derived from" in capsys.readouterr().out


def test_report_missing_file_is_a_clean_error(tmp_path, capsys):
    assert lr.main([str(tmp_path / "nope.jsonl")]) == 2


def test_sample_graph_matches_the_a_b_c_shape():
    from ledger import trace_upstream
    from ledger.sample import commit_id
    g = build_graph(sample_events(), sample_declarations())
    assert trace_upstream(g, commit_id("c")).artifacts == [commit_id("b"), commit_id("a")]
