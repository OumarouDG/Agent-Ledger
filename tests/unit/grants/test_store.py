"""Offline tests for DynamoGrantStore and store_from_env. DynamoDB is stubbed with botocore Stubber."""

from __future__ import annotations

from dataclasses import replace

import pytest
from botocore.exceptions import EndpointConnectionError

from controlplane.grants.store import (
    TABLE_NAME, DynamoGrantStore, grant_to_item, item_to_grant, store_from_env,
)
from gateway.grants import Grant, GrantStoreError, JsonFileGrantStore
from tests.unit.grants.stubs import FUTURE, TABLE, expect_get, item, stubbed_client


@pytest.fixture
def stub():
    client, stubber = stubbed_client()
    with stubber:
        yield DynamoGrantStore(TABLE, client=client), stubber
        stubber.assert_no_pending_responses()


# --- happy path ---------------------------------------------------------------

def test_item_maps_to_grant_field_by_field(stub):
    store, stubber = stub
    expect_get(stubber, "gr_child", item(
        "gr_child",
        parent_grant_id={"S": "gr_root"},
        tools={"L": [{"S": "get_issue"}, {"S": "commit_file"}]},
        delegable_tools={"L": [{"S": "get_issue"}]},
        resources={"M": {"repository": {"S": "acme/demo"}, "branch": {"S": "feat/x"}}},
    ))
    assert store.get("gr_child") == Grant(
        grant_id="gr_child",
        agent_id="agent_coder",
        workflow_id="wf_test",
        human_id="alice",
        status="active",
        expires_at=FUTURE,
        parent_grant_id="gr_root",
        tools=frozenset({"get_issue", "commit_file"}),
        delegable_tools=frozenset({"get_issue"}),
        resources={"repository": "acme/demo", "branch": "feat/x"},
    )


def test_decimal_expiry_becomes_int(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item())
    g = store.get("gr_test1")
    assert type(g.expires_at) is int and g.expires_at == FUTURE


def test_empty_tool_lists_round_trip(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(tools={"L": []}, delegable_tools={"L": []}))
    g = store.get("gr_test1")
    assert g.tools == frozenset() and g.delegable_tools == frozenset()


def test_absent_optional_fields_default(stub):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(human_id=None, delegable_tools=None, resources=None))
    g = store.get("gr_test1")
    assert (g.human_id, g.parent_grant_id, g.delegable_tools, g.resources) == (None, None, frozenset(), {})


def test_missing_item_gives_none(stub):
    store, stubber = stub
    expect_get(stubber, "gr_ghost", None)
    assert store.get("gr_ghost") is None


def test_two_gets_make_two_calls_no_cache(stub):
    # A revoke between the two reads must be seen by the second one.
    store, stubber = stub
    expect_get(stubber, "gr_test1", item())
    expect_get(stubber, "gr_test1", item(status={"S": "revoked"}))
    assert store.get("gr_test1").status == "active"
    assert store.get("gr_test1").status == "revoked"


def test_eventually_consistent_read_is_refused_by_the_stub():
    # Bad case: a GetItem without ConsistentRead=True. The stub must reject it, so the
    # assertion in expect_get really guards every call.
    client, stubber = stubbed_client()
    expect_get(stubber, "gr_test1", item())
    with stubber, pytest.raises(Exception, match="Expected parameters"):
        client.get_item(TableName=TABLE, Key={"grant_id": {"S": "gr_test1"}})


# --- store errors -------------------------------------------------------------

@pytest.mark.parametrize("code, hint", [
    ("ResourceNotFoundException", "grants_setup.py"),
    ("AccessDeniedException", "may not read"),
    ("ProvisionedThroughputExceededException", "throttled"),
    ("ThrottlingException", "throttled"),
    ("ExpiredTokenException", "fresh Workshop Studio credentials"),
    ("InternalServerError", "check AWS credentials"),
])
def test_client_errors_give_store_error_not_none(stub, code, hint):
    store, stubber = stub
    stubber.add_client_error("get_item", service_error_code=code, http_status_code=400)
    with pytest.raises(GrantStoreError) as e:
        store.get("gr_test1")
    assert code in str(e.value) and hint in str(e.value)


def test_network_error_gives_store_error():
    class Unreachable:
        def get_item(self, **kw):
            raise EndpointConnectionError(endpoint_url="https://dynamodb.us-east-1.amazonaws.com")
    with pytest.raises(GrantStoreError, match="EndpointConnectionError"):
        DynamoGrantStore(TABLE, client=Unreachable()).get("gr_test1")


@pytest.mark.parametrize("grant_id", ["", None, 42])
def test_bad_grant_id_gives_store_error(grant_id):
    class NeverCalled:
        def get_item(self, **kw):
            raise AssertionError("must not call DynamoDB")
    with pytest.raises(GrantStoreError, match="grant_id"):
        DynamoGrantStore(TABLE, client=NeverCalled()).get(grant_id)


@pytest.mark.parametrize("overrides, why", [
    ({"agent_id": None}, "agent_id"),
    ({"agent_id": {"S": ""}}, "agent_id"),
    ({"workflow_id": None}, "workflow_id"),
    ({"status": None}, "status"),
    ({"status": {"N": "1"}}, "status"),
    ({"human_id": {"N": "7"}}, "human_id"),
    ({"parent_grant_id": {"S": ""}}, "parent_grant_id"),
    ({"expires_at": None}, "expires_at"),
    ({"expires_at": {"S": "1800003600"}}, "expires_at"),
    ({"expires_at": {"N": "1800003600.5"}}, "expires_at"),
    ({"expires_at": {"BOOL": True}}, "expires_at"),
    ({"tools": {"SS": ["get_issue"]}}, "tools"),
    ({"tools": {"S": "get_issue"}}, "tools"),
    ({"tools": {"L": [{"N": "1"}]}}, "tools"),
    ({"delegable_tools": {"L": [{"S": ""}]}}, "delegable_tools"),
    ({"resources": {"S": "acme/demo"}}, "resources"),
    ({"resources": {"M": {"repository": {"N": "1"}}}}, "resources.repository"),
    ({"grant_id": {"S": "gr_other"}}, "grant_id"),
    ({"grant_id": None}, "grant_id"),
])
def test_malformed_item_gives_store_error(stub, overrides, why):
    store, stubber = stub
    expect_get(stubber, "gr_test1", item(**overrides))
    with pytest.raises(GrantStoreError, match="malformed") as e:
        store.get("gr_test1")
    assert why in str(e.value)


# --- conditional writes -------------------------------------------------------

GRANT = Grant(grant_id="gr_w1", agent_id="agent_coder", workflow_id="wf_test", human_id="alice",
              expires_at=FUTURE, parent_grant_id="gr_root", tools=frozenset({"get_issue", "commit_file"}),
              delegable_tools=frozenset(), resources={"repository": "acme/demo"})


def test_grant_to_item_round_trips_and_uses_lists():
    raw = grant_to_item(GRANT, created_at=1, created_by="agent_lead")
    assert raw["tools"] == {"L": [{"S": "commit_file"}, {"S": "get_issue"}]}
    assert raw["delegable_tools"] == {"L": []}  # an empty string set would be rejected by DynamoDB
    assert raw["expires_at"] == {"N": str(FUTURE)}
    assert (raw["created_by"], raw["created_at"]) == ({"S": "agent_lead"}, {"N": "1"})
    assert item_to_grant(raw, "gr_w1") == GRANT


def test_grant_to_item_omits_absent_optional_fields():
    raw = grant_to_item(replace(GRANT, human_id=None, parent_grant_id=None), created_at=1, created_by="x")
    assert "human_id" not in raw and "parent_grant_id" not in raw


def test_grant_to_item_refuses_non_int_expiry():
    with pytest.raises(ValueError):
        grant_to_item(replace(GRANT, expires_at=None), created_at=1, created_by="x")


def test_put_new_is_conditional(stub):
    store, stubber = stub
    stubber.add_response("put_item", {}, {
        "TableName": TABLE,
        "Item": grant_to_item(GRANT, created_at=5, created_by="agent_lead"),
        "ConditionExpression": "attribute_not_exists(grant_id)",
    })
    store.put_new(GRANT, created_at=5, created_by="agent_lead")


def test_put_new_existing_id_is_an_error_not_an_overwrite(stub):
    store, stubber = stub
    stubber.add_client_error("put_item", service_error_code="ConditionalCheckFailedException",
                             http_status_code=400)
    with pytest.raises(GrantStoreError, match="already exists"):
        store.put_new(GRANT, created_at=5, created_by="agent_lead")


def test_put_new_access_denied_is_store_error(stub):
    store, stubber = stub
    stubber.add_client_error("put_item", service_error_code="AccessDeniedException", http_status_code=400)
    with pytest.raises(GrantStoreError, match="AccessDeniedException"):
        store.put_new(GRANT, created_at=5, created_by="agent_lead")


def test_mark_revoked_is_conditional(stub):
    store, stubber = stub
    stubber.add_response("update_item", {}, {
        "TableName": TABLE,
        "Key": {"grant_id": {"S": "gr_w1"}},
        "UpdateExpression": "SET #s = :revoked, revoked_at = :at, revoked_by = :by",
        "ConditionExpression": "attribute_exists(grant_id) AND #s <> :revoked",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":revoked": {"S": "revoked"}, ":at": {"N": "7"}, ":by": {"S": "alice"}},
    })
    assert store.mark_revoked("gr_w1", revoked_at=7, revoked_by="alice") is True


def test_mark_revoked_condition_failed_returns_false(stub):
    store, stubber = stub
    stubber.add_client_error("update_item", service_error_code="ConditionalCheckFailedException",
                             http_status_code=400)
    assert store.mark_revoked("gr_w1", revoked_at=7, revoked_by="alice") is False


def test_mark_revoked_throttled_is_store_error(stub):
    store, stubber = stub
    stubber.add_client_error("update_item", service_error_code="ThrottlingException", http_status_code=400)
    with pytest.raises(GrantStoreError, match="ThrottlingException"):
        store.mark_revoked("gr_w1", revoked_at=7, revoked_by="alice")


# --- store_from_env -----------------------------------------------------------

@pytest.fixture
def clean_env(monkeypatch):
    for var in ("AGENTLEDGER_GRANT_STORE", "AGENTLEDGER_GRANTS_TABLE", "AGENTLEDGER_GRANTS_FILE"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


@pytest.mark.parametrize("value", [None, "", "file"])
def test_unset_or_file_gives_json_store(clean_env, tmp_path, value):
    if value is not None:
        clean_env.setenv("AGENTLEDGER_GRANT_STORE", value)
    path = tmp_path / "grants.json"
    path.write_text('{"grants": {"g1": {"agent_id": "a", "workflow_id": "w"}}}')
    clean_env.setenv("AGENTLEDGER_GRANTS_FILE", str(path))
    store = store_from_env()
    assert isinstance(store, JsonFileGrantStore)
    assert store.get("g1").agent_id == "a"  # reads the file the env var names


def test_dynamodb_gives_dynamo_store(clean_env):
    clean_env.setenv("AGENTLEDGER_GRANT_STORE", "dynamodb")
    store = store_from_env()
    assert isinstance(store, DynamoGrantStore) and store.table_name == TABLE_NAME
    assert store._client.meta.region_name == "us-east-1"  # from shared/cognito.json


def test_dynamodb_table_override(clean_env):
    clean_env.setenv("AGENTLEDGER_GRANT_STORE", "dynamodb")
    clean_env.setenv("AGENTLEDGER_GRANTS_TABLE", "other-table")
    assert store_from_env().table_name == "other-table"


@pytest.mark.parametrize("value", ["DynamoDB", "dynamo", "s3", "memory", " dynamodb"])
def test_unknown_store_kind_raises(clean_env, value):
    # Bad case would be quietly falling back to the dev file store.
    clean_env.setenv("AGENTLEDGER_GRANT_STORE", value)
    with pytest.raises(ValueError, match="AGENTLEDGER_GRANT_STORE"):
        store_from_env()
