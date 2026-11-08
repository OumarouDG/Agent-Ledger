"""The graph viewer shows the ledger's answers and decides nothing itself."""

import importlib.util
import json
import re
from pathlib import Path

from ledger import build_graph
from ledger.sample import sample_declarations, sample_events
from ledger.visualize import build_view, render_html
from tests.ledger.helpers import (REPO, accepted_workflow, allowed, cid, commit_events, denied, done,
                                  pr_events, run_events)

PR = f"artifact:{REPO}:pr:7"


def view(events, decls=()):
    return build_view(build_graph(events, list(decls)))


def node(v, nid):
    return next(n for n in v["nodes"] if n["id"] == nid)


def test_accepted_pr_chain_is_green_and_complete_with_event_ids():
    v = view(accepted_workflow("wf_a", "a", 7))
    assert node(v, PR)["class"] == "ok" and node(v, PR)["status"].startswith("ACCEPTED")
    assert node(v, cid("a"))["status"].startswith("VALIDATED")
    ch = v["chains"][PR]
    assert ch["complete"] and ch["state"] == "ACCEPTED"
    assert {"human:alice", f"artifact:{REPO}:run:{ord('a')}", PR} <= set(ch["nodes"])
    confirmed = [e for e in v["edges"] if e["edge_id"] in ch["edges"]]
    assert confirmed and all(e["source_event_id"] for e in confirmed if e["relation"] != "PART_OF")


def test_unmerged_pr_is_never_green_or_accepted():
    v = view([*commit_events("wf_a", "a"), *run_events("wf_a", "a"), *pr_events("wf_a", "a", 7, merged=False)])
    n = node(v, PR)
    assert n["class"] == "warn" and "ACCEPTED" not in n["status"].split(":")[0]
    assert not v["chains"][PR]["complete"]


def test_failed_ci_is_red_and_the_commit_is_not_validated():
    v = view([*commit_events("wf_a", "a"), *run_events("wf_a", "a", conclusion="failure"),
              *pr_events("wf_a", "a", 7, merged=False)])
    run = node(v, f"artifact:{REPO}:run:{ord('a')}")
    assert run["class"] == "bad" and run["status"].startswith("FAILED")
    assert node(v, cid("a"))["class"] == "bad"
    link = next(l for l in v["chains"][PR]["links"] if l["link"].startswith("passing CI"))
    assert link["id"] is None and "failure" in link["not_passing"]


def test_wrong_sha_run_does_not_validate():
    v = view([*commit_events("wf_a", "a"), *run_events("wf_a", "a", tested_sha="b" * 40, run_id=9)])
    assert node(v, cid("a"))["class"] == "warn"  # PENDING, never green


def test_unknown_outcome_is_amber_and_denied_is_red_and_not_executed():
    v = view([allowed("commit_file", "wf_a", "act_u"), denied("create_branch", "wf_a", "act_d")])
    assert node(v, "activity:act_u")["class"] == "warn" and "UNKNOWN" in node(v, "activity:act_u")["status"]
    d = node(v, "activity:act_d")
    assert d["class"] == "bad" and "Not executed" in d["status"]
    rel = {e["relation"] for e in v["edges"] if e["from"] == "activity:act_d"}
    assert "EXECUTED_BY" not in rel and "AUTHORIZED_BY" not in rel


def test_authorized_alone_is_not_green_unless_an_outcome_succeeded():
    v = view([allowed("get_issue", "wf_a", "act_x")])
    assert node(v, "activity:act_x")["class"] == "warn"


def test_candidate_and_synthetic_edges_are_marked_and_not_in_traces():
    g = build_graph(accepted_workflow("wf_b", "b", 2), [__import__("ledger").Declaration(cid("b"), cid("z"), "x")])
    v = build_view(g)
    cand = [e for e in v["edges"] if e["candidate"]]
    assert cand and all(e["confidence"] == "candidate" for e in cand)
    t = v["traces"][cid("b")]
    assert t["up"] == [] and t["candidates"]
    syn = build_view(build_graph(sample_events(), sample_declarations()), synthetic_label="SYNTHETIC SAMPLE: invented")
    html = render_html(syn)
    assert syn["synthetic"] and "SYNTHETIC SAMPLE" in html


def test_synthetic_trace_goes_c_to_b_to_a():
    from ledger.sample import commit_id
    v = build_view(build_graph(sample_events(), sample_declarations()), synthetic_label="x")
    assert v["traces"][commit_id("c")]["up"] == [commit_id("b"), commit_id("a")]
    assert v["traces"][commit_id("a")]["down"] == [commit_id("b"), commit_id("c")]


def test_html_is_offline_and_escapes_hostile_text():
    evil = "</script><img src=x onerror=alert(1)>"
    events = accepted_workflow("wf_a", "a", 7)
    events[1]["artifact"]["path"] = evil
    events[1]["artifact"]["access_token"] = "SECRET-TOKEN-VALUE"
    html = render_html(view(events))
    assert "SECRET-TOKEN-VALUE" not in html and "access_token" not in html
    assert evil not in html and "<\\/script>" in html
    assert not re.search(r"<script[^>]+src=|<link\b|@import|url\(\s*['\"]?https?:", html)
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    m = re.search(r'<script id="data" type="application/json">(.*?)</script>', html, re.S)
    assert json.loads(m.group(1))["nodes"]


def test_view_is_deterministic():
    ev = accepted_workflow("wf_a", "a", 7)
    assert render_html(view(ev)) == render_html(view(list(ev)))


def test_cli_writes_a_page(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location(
        "ledger_graph", Path(__file__).resolve().parents[2] / "scripts" / "ledger_graph.py")
    lg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lg)
    audit, out = tmp_path / "a.jsonl", tmp_path / "g.html"
    audit.write_text("\n".join(json.dumps(e) for e in accepted_workflow("wf_a", "a", 7)), encoding="utf-8")
    assert lg.main([str(audit), "--out", str(out), "--workflow", "wf_a", "--pr", "7"]) == 0
    assert "AgentLedger provenance" in out.read_text(encoding="utf-8")
    assert lg.main(["--synthetic", "--out", str(tmp_path / "s.html")]) == 0
    assert "SYNTHETIC" in (tmp_path / "s.html").read_text(encoding="utf-8")
    assert lg.main([str(tmp_path / "nope.jsonl"), "--out", str(out)]) == 2
