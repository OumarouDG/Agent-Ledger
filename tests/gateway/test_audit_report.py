import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import audit_report  # noqa: E402


def test_report_escapes_and_filters(tmp_path):
    events = [
        {"ts": 1, "decision": "deny", "reason": "<script>alert(1)</script>", "agent_id": "a",
         "tool": "t", "workflow_id": "wf_1", "grant_id": "g"},
        {"ts": 2, "decision": "allow", "agent_id": "b", "tool": "t", "workflow_id": "wf_2"},
    ]
    src, out = tmp_path / "a.jsonl", tmp_path / "r.html"
    src.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    assert audit_report.main([str(src), str(out), "--workflow", "wf_1"]) == 0
    html = out.read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "wf_2" not in html
    assert "not the AWS Console" in html
