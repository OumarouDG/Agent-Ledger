"""The audit timeline script: formatting, filtering, and bad-line handling."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "audit_timeline", Path(__file__).resolve().parents[2] / "scripts" / "audit_timeline.py")
tl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tl)

ALLOW = {"ts": 1794104927, "decision": "allow", "agent_id": "agent_coder", "tool": "create_branch",
         "grant_id": "grant_001", "workflow_id": "wf_001", "human_id": "alice", "reason": "allowed",
         "resource": {"repository": "o/r", "branch": "agentledger/wf_001/x"}}
DENY = {**ALLOW, "decision": "deny", "reason": "branch_not_permitted",
        "resource": {"repository": "o/r", "branch": "main"}}


def write(tmp_path, *lines):
    p = tmp_path / "audit.jsonl"
    p.write_text("\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n")
    return str(p)


def test_allow_and_deny_lines():
    a, d = tl.format_event(ALLOW), tl.format_event(DENY)
    assert "ALLOW" in a and "branch=agentledger/wf_001/x" in a and "<-" not in a
    assert "DENY" in d and "<- branch_not_permitted" in d and "branch=main" in d
    assert "grant=grant_001" in a and "owner=alice" in a


def test_missing_fields_do_not_crash():
    assert "DENY" in tl.format_event({})


def test_summary_counts_reasons():
    s = tl.summary([ALLOW, DENY, DENY])
    assert "3 calls: 1 allowed, 2 denied" in s and "branch_not_permitted x2" in s


def test_cli_denied_only_and_last(tmp_path, capsys):
    path = write(tmp_path, ALLOW, DENY, ALLOW)
    assert tl.main([path, "--denied"]) == 0
    out = capsys.readouterr().out
    assert "DENY" in out and "ALLOW" not in out
    assert tl.main([path, "--last", "1"]) == 0
    assert capsys.readouterr().out.count("ALLOW") == 1


def test_bad_line_is_reported_not_skipped(tmp_path, capsys):
    path = write(tmp_path, ALLOW, "{not json", DENY)
    assert tl.main([path]) == 1
    cap = capsys.readouterr()
    assert "line 2 is not valid JSON" in cap.err and "2 calls" in cap.out


def test_unreadable_file_exits_2(tmp_path, capsys):
    assert tl.main([str(tmp_path / "nope.jsonl")]) == 2
    assert "cannot read" in capsys.readouterr().err


LOCK = {**ALLOW, "decision": "lock", "reason": "repeated_violations", "tool": "create_branch",
        "resource": {}}
USAGE = {**ALLOW, "decision": "usage", "tool": "llm_converse", "reason": "completed",
         "resource": {"model": "m.x-v1:0", "input_tokens": 14, "output_tokens": 20}}


def test_lock_and_usage_lines():
    assert "LOCK" in tl.format_event(LOCK) and "repeated_violations" in tl.format_event(LOCK)
    u = tl.format_event(USAGE)
    assert "USAGE" in u and "model=m.x-v1:0" in u and "in=14" in u and "out=20" in u


def test_summary_separates_calls_locks_and_tokens():
    s = tl.summary([ALLOW, DENY, LOCK, USAGE, USAGE])
    assert "2 calls: 1 allowed, 1 denied" in s
    assert "1 grant lock(s)" in s and "2 model call(s), 28 tokens in, 40 out" in s


def test_denied_filter_keeps_locks_and_drops_usage(tmp_path, capsys):
    path = write(tmp_path, ALLOW, DENY, LOCK, USAGE)
    assert tl.main([path, "--denied"]) == 0
    out = capsys.readouterr().out
    assert "DENY" in out and "LOCK" in out and "USAGE" not in out and "ALLOW" not in out