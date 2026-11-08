"""Two fail-closed gaps found in the overnight read-through."""

from gateway.authorization import authorize
from gateway.sentinel import Sentinel


class ExplodingStore:
    def get(self, grant_id):
        raise ValueError("adapter bug")


def test_unexpected_store_error_is_a_denial_not_a_crash():
    d = authorize(ExplodingStore(), agent_id="agent_coder", grant_id="g1",
                  workflow_id="wf", tool="get_issue")
    assert not d.allowed and d.reason == "grant_store_unavailable"


def test_lock_holds_even_when_the_lock_file_cannot_be_written(tmp_path):
    # The parent folder is missing: reads say "no file", writes fail.
    s = Sentinel(tmp_path / "missing" / "q.json", threshold=2)
    s.violation("g1", "tool_not_permitted")
    assert s.violation("g1", "tool_not_permitted")
    assert s.is_locked("g1")
    assert not s.is_locked("g2")
