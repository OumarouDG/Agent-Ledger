import importlib.util
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from tests.ledger.helpers import accepted_workflow

spec = importlib.util.spec_from_file_location(
    "serve_ledger_view", Path(__file__).resolve().parents[2] / "scripts" / "serve_ledger_view.py")
sv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv)


def start(audit):
    srv = ThreadingHTTPServer((sv.BIND, 0), sv.make_handler(str(audit)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def get(srv, path="/", host=None):
    port = srv.server_address[1]
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Host": host or f"127.0.0.1:{port}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), dict(e.headers)


def test_serves_a_fresh_page_on_loopback_only(tmp_path):
    audit = tmp_path / "a.jsonl"
    audit.write_text("\n".join(json.dumps(e) for e in accepted_workflow("wf_a", "a", 7)), encoding="utf-8")
    srv = start(audit)
    try:
        assert srv.server_address[0] == "127.0.0.1"
        code, body, headers = get(srv)
        assert code == 200 and "AgentLedger provenance" in body and headers["Cache-Control"] == "no-store"
        assert get(srv, "/other")[0] == 404
        assert get(srv, host="evil.example")[0] == 403
        assert get(srv, host="127.0.0.1:18001")[0] == 200  # the browser's port behind a tunnel
        assert get(srv, host="localhost:18001")[0] == 200
        for bad in ("127.0.0.1.evil.com:8001", "evil.com:127", "127.0.0.1:abc", ""):
            assert get(srv, host=bad)[0] == 403, bad
        audit.write_text("\n".join(json.dumps(e) for e in accepted_workflow("wf_b", "b", 8)), encoding="utf-8")
        assert "wf_b" in get(srv)[1]  # re-read on every load
    finally:
        srv.shutdown()


def test_unreadable_audit_is_a_clean_500_without_details(tmp_path):
    srv = start(tmp_path / "missing.jsonl")
    try:
        code, body, _ = get(srv)
        assert code == 500 and "missing" not in body and "Errno" not in body
    finally:
        srv.shutdown()


def test_refuses_the_gateway_port(capsys):
    assert sv.main(["--port", "8000"]) == 2
