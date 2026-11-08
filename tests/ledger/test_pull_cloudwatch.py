import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "pull", Path(__file__).resolve().parents[2] / "scripts" / "pull_audit_from_cloudwatch.py")
pull = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pull)


class FakeLogs:
    def __init__(self):
        self.calls = []

    def filter_log_events(self, **kw):
        self.calls.append(kw)
        if "nextToken" not in kw:
            return {"events": [{"message": json.dumps({"event_id": "evt_2", "ts": 2})},
                               {"message": "not json"}], "nextToken": "t"}
        return {"events": [{"message": json.dumps({"event_id": "evt_1", "ts": 1})},
                           {"message": "[1, 2]"}]}


def test_pages_are_followed_bad_lines_skipped_and_output_sorted(tmp_path, capsys):
    out = tmp_path / "o.jsonl"
    client = FakeLogs()
    assert pull.main([str(out)], client=client) == 0
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    assert [e["event_id"] for e in lines] == ["evt_1", "evt_2"]
    assert len(client.calls) == 2 and "2 skipped" in capsys.readouterr().out


def test_aws_failure_is_a_clean_error_without_details(tmp_path, capsys):
    class Boom:
        def filter_log_events(self, **kw):
            raise RuntimeError("secret-looking detail")

    assert pull.main([str(tmp_path / "o.jsonl")], client=Boom()) == 2
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "secret-looking" not in err
