import importlib.util
import json
from pathlib import Path

from tests.ledger.helpers import accepted_workflow

spec = importlib.util.spec_from_file_location(
    "ledger_verify", Path(__file__).resolve().parents[2] / "scripts" / "ledger_verify.py")
lv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lv)


def write(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def test_seal_then_verify_then_tamper(tmp_path, capsys):
    audit, sealed, heads = tmp_path / "a.jsonl", tmp_path / "s.jsonl", tmp_path / "h.json"
    events = accepted_workflow("wf_a", "a", 1)
    write(audit, events)
    assert lv.main(["seal", str(audit), str(sealed), "--heads", str(heads)]) == 0
    assert lv.main(["verify", str(audit), str(sealed), "--heads", str(heads)]) == 0
    before = audit.read_text(encoding="utf-8")

    events[1]["status"] = "failed"
    write(audit, events)
    capsys.readouterr()
    assert lv.main(["verify", str(audit), str(sealed)]) == 1
    assert "modified" in capsys.readouterr().out
    assert before != audit.read_text(encoding="utf-8")


def test_verify_never_changes_the_audit_file(tmp_path):
    audit, sealed = tmp_path / "a.jsonl", tmp_path / "s.jsonl"
    write(audit, accepted_workflow("wf_a", "a", 1))
    snapshot = audit.read_bytes()
    lv.main(["seal", str(audit), str(sealed)])
    lv.main(["verify", str(audit), str(sealed)])
    assert audit.read_bytes() == snapshot


def test_bad_input_is_a_clean_error(tmp_path):
    assert lv.main(["verify", str(tmp_path / "nope"), str(tmp_path / "nope2")]) == 2
