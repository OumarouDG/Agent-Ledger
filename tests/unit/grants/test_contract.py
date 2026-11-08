"""Contract test: the gateway's own authorize() run against a stubbed DynamoGrantStore.

Each case queues exactly the GetItem calls authorize() should make; the fixture then checks
none were left over, so a case that stops early or reads too much fails.
"""

from __future__ import annotations

import pytest

from controlplane.grants.store import DynamoGrantStore
from gateway.authorization import authorize
from tests.unit.grants.stubs import NOW, PAST, TABLE, expect_get, item, stubbed_client


@pytest.fixture
def stub():
    client, stubber = stubbed_client()
    with stubber:
        yield DynamoGrantStore(TABLE, client=client), stubber
        stubber.assert_no_pending_responses()


def decide(store, grant_id="gr_test1", tool="get_issue"):
    return authorize(store, agent_id="agent_coder", grant_id=grant_id,
                     workflow_id="wf_test", tool=tool, now=NOW)


def test_allow(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item())
    d = decide(store)
    assert d.allowed and d.reason == "allowed"
    assert d.grant.resources["repository"] == "acme/demo"


def test_allow_child_with_active_parent(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(parent_grant_id={"S": "gr_root"}))
    expect_get(stubber, "gr_root", item("gr_root", agent_id={"S": "agent_lead"}))
    assert decide(store).allowed


def test_grant_revoked(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(status={"S": "revoked"}))
    assert decide(store).reason == "grant_revoked"


def test_grant_expired(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(expires_at={"N": str(PAST)}))
    assert decide(store).reason == "grant_expired"


def test_tool_not_permitted(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item())
    assert decide(store, tool="commit_file").reason == "tool_not_permitted"


def test_delegable_tools_alone_never_allow(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(tools={"L": []}, delegable_tools={"L": [{"S": "get_issue"}]}))
    d = decide(store)
    assert not d.allowed and d.reason == "tool_not_permitted"


def test_parent_grant_revoked(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(parent_grant_id={"S": "gr_root"}))
    expect_get(stubber, "gr_root", item("gr_root", status={"S": "revoked"}))
    assert decide(store).reason == "parent_grant_revoked"


def test_parent_grant_missing(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(parent_grant_id={"S": "gr_root"}))
    expect_get(stubber, "gr_root", None)
    assert decide(store).reason == "parent_grant_missing"


def test_unknown_grant(stub):
    store, stubber = stub
    expect_get(stubber, "gr_ghost", None)
    assert decide(store, grant_id="gr_ghost").reason == "unknown_grant"


@pytest.mark.parametrize("code", ["ResourceNotFoundException", "AccessDeniedException",
                                  "ThrottlingException"])
def test_store_error_is_unavailable_not_unknown_grant(stub, code):
    # Bad case: a missing table or denied read reported as unknown_grant (looks like a bad ID).
    store, stubber = stub
    stubber.add_client_error("get_item", service_error_code=code, http_status_code=400)
    assert decide(store).reason == "grant_store_unavailable"


def test_store_error_on_parent_read_is_unavailable(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(parent_grant_id={"S": "gr_root"}))
    stubber.add_client_error("get_item", service_error_code="ThrottlingException", http_status_code=400)
    assert decide(store).reason == "grant_store_unavailable"


def test_malformed_item_is_unavailable(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(tools={"S": "get_issue"}))
    assert decide(store).reason == "grant_store_unavailable"
