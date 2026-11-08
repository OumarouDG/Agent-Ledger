"""DynamoDB grant store behind the gateway's `GrantStore` interface.

`DynamoGrantStore.get` reads one grant with a strongly consistent read and no cache, so a
revoke applies to the next call. Every failure to read or parse an item raises
`GrantStoreError`; `None` means only that the item does not exist.

Writes are conditional: `put_new` never overwrites an existing grant and `mark_revoked`
never creates one. Nothing here deletes a grant; the gateway's parent walk needs them.
"""

from __future__ import annotations

import logging
import os
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import BotoCoreError, ClientError

from controlplane.auth.config import load_config
from gateway.grants import Grant, GrantStore, GrantStoreError, JsonFileGrantStore

TABLE_NAME = "agentledger-grants"
WORKFLOW_INDEX = "workflow_id-index"

ENV_STORE = "AGENTLEDGER_GRANT_STORE"  # "dynamodb" | "file" (default)
ENV_TABLE = "AGENTLEDGER_GRANTS_TABLE"  # override the table name
ENV_FILE = "AGENTLEDGER_GRANTS_FILE"  # same variable gateway/server.py reads
DEFAULT_FILE = "gateway-grants.json"

_FIXES = {
    "ResourceNotFoundException": "table missing: run `python infra/grants_setup.py`",
    "ExpiredTokenException": "AWS credentials expired: paste fresh Workshop Studio credentials",
    "ExpiredToken": "AWS credentials expired: paste fresh Workshop Studio credentials",
    "AccessDeniedException": "this role may not read the grants table",
    "ProvisionedThroughputExceededException": "throttled; retry",
    "ThrottlingException": "throttled; retry",
}

_deserializer = TypeDeserializer()
_serializer = TypeSerializer()
log = logging.getLogger("agentledger.grants")


def _region() -> str:
    return load_config()["region"]


def _code(e: ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "ClientError")


def _store_error(e: Exception) -> GrantStoreError:
    if isinstance(e, ClientError):
        code = _code(e)
        hint = _FIXES.get(code, "check AWS credentials and the table name")
        return GrantStoreError(f"grant store unavailable ({code}): {hint}")
    return GrantStoreError(f"grant store unavailable ({type(e).__name__}): can't reach AWS; "
                           "check network and credentials")


class DynamoGrantStore:
    """Reads grants from DynamoDB. Implements `gateway.grants.GrantStore`."""

    def __init__(self, table_name: str = TABLE_NAME, *, client: Any = None,
                 region: str | None = None) -> None:
        self.table_name = table_name
        # Creating a client makes no network call.
        self._client = client or boto3.client("dynamodb", region_name=region or _region())

    def __repr__(self) -> str:
        region = getattr(getattr(self._client, "meta", None), "region_name", "?")
        return f"DynamoGrantStore(table={self.table_name!r}, region={region!r})"

    def get(self, grant_id: str) -> Grant | None:
        if not isinstance(grant_id, str) or not grant_id:
            raise GrantStoreError("grant store: grant_id must be a non-empty string")
        try:
            resp = self._client.get_item(
                TableName=self.table_name,
                Key={"grant_id": {"S": grant_id}},
                ConsistentRead=True,
            )
        except (ClientError, BotoCoreError) as e:
            raise _store_error(e) from e
        item = resp.get("Item")
        if item is None:
            return None
        return item_to_grant(item, grant_id)

    def put_new(self, grant: Grant, *, created_at: int, created_by: str) -> None:
        """Write a new grant. Refuses (GrantStoreError) if the grant_id already exists."""
        try:
            self._client.put_item(
                TableName=self.table_name,
                Item=grant_to_item(grant, created_at=created_at, created_by=created_by),
                ConditionExpression="attribute_not_exists(grant_id)",
            )
        except ClientError as e:
            if _code(e) == "ConditionalCheckFailedException":
                raise GrantStoreError(f"grant {grant.grant_id} already exists; not overwritten") from e
            raise _store_error(e) from e
        except BotoCoreError as e:
            raise _store_error(e) from e

    def mark_revoked(self, grant_id: str, *, revoked_at: int, revoked_by: str) -> bool:
        """Set status=revoked. True if this call revoked it; False if the grant is missing
        or already revoked (the caller re-reads to tell which). Never creates an item."""
        try:
            self._client.update_item(
                TableName=self.table_name,
                Key={"grant_id": {"S": grant_id}},
                UpdateExpression="SET #s = :revoked, revoked_at = :at, revoked_by = :by",
                ConditionExpression="attribute_exists(grant_id) AND #s <> :revoked",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":revoked": {"S": "revoked"},
                    ":at": {"N": str(int(revoked_at))},
                    ":by": {"S": revoked_by},
                },
            )
        except ClientError as e:
            if _code(e) == "ConditionalCheckFailedException":
                return False
            raise _store_error(e) from e
        except BotoCoreError as e:
            raise _store_error(e) from e
        return True

    def by_workflow(self, workflow_id: str) -> list[Grant]:
        """All grants in one workflow, via the GSI. GSI reads are eventually consistent,
        so a revoke made a moment ago may not show yet; `get` is the consistent read."""
        return self._read_all("query", IndexName=WORKFLOW_INDEX,
                              KeyConditionExpression="workflow_id = :w",
                              ExpressionAttributeValues={":w": {"S": workflow_id}})

    def all(self) -> list[Grant]:
        """Every grant in the table (a scan). Fine for a demo-sized table."""
        return self._read_all("scan", ConsistentRead=True)

    def _read_all(self, op: str, **kw: Any) -> list[Grant]:
        out: list[Grant] = []
        try:
            for page in self._client.get_paginator(op).paginate(TableName=self.table_name, **kw):
                for item in page.get("Items", []):
                    gid = item.get("grant_id", {}).get("S", "<no grant_id>")
                    out.append(item_to_grant(item, gid))
        except (ClientError, BotoCoreError) as e:
            raise _store_error(e) from e
        return out


def grant_to_item(grant: Grant, *, created_at: int, created_by: str) -> dict[str, Any]:
    """Raw DynamoDB item for a grant. Tool names are lists (L): DynamoDB rejects empty sets."""
    if not isinstance(grant.expires_at, int) or isinstance(grant.expires_at, bool):
        raise ValueError("grant.expires_at must be an int")
    raw: dict[str, Any] = {
        "grant_id": grant.grant_id,
        "agent_id": grant.agent_id,
        "workflow_id": grant.workflow_id,
        "status": grant.status,
        "expires_at": grant.expires_at,
        "tools": sorted(grant.tools),
        "delegable_tools": sorted(grant.delegable_tools),
        "resources": dict(grant.resources),
        "created_at": int(created_at),
        "created_by": created_by,
    }
    if grant.human_id is not None:
        raw["human_id"] = grant.human_id
    if grant.parent_grant_id is not None:
        raw["parent_grant_id"] = grant.parent_grant_id
    return {k: _serializer.serialize(v) for k, v in raw.items()}


def item_to_grant(item: dict[str, Any], grant_id: str) -> Grant:
    """Convert a raw DynamoDB item (`{"attr": {"S": ...}}`) to a `Grant`. Malformed raises."""
    try:
        raw = {k: _deserializer.deserialize(v) for k, v in item.items()}
    except (TypeError, ValueError, KeyError, AttributeError) as e:
        raise _malformed(grant_id, f"undecodable attribute ({type(e).__name__})") from e

    if raw.get("grant_id") != grant_id:
        raise _malformed(grant_id, "grant_id attribute does not match the key")
    return Grant(
        grant_id=grant_id,
        agent_id=_req_str(raw, "agent_id", grant_id),
        workflow_id=_req_str(raw, "workflow_id", grant_id),
        human_id=_opt_str(raw, "human_id", grant_id),
        status=_req_str(raw, "status", grant_id),
        expires_at=_expiry(raw, grant_id),
        parent_grant_id=_opt_str(raw, "parent_grant_id", grant_id),
        tools=_str_list(raw, "tools", grant_id),
        delegable_tools=_str_list(raw, "delegable_tools", grant_id),
        resources=_resources(raw, grant_id),
    )


def _malformed(grant_id: str, why: str) -> GrantStoreError:
    return GrantStoreError(f"grant store: item {grant_id} is malformed: {why}")


def _req_str(raw: dict, key: str, gid: str) -> str:
    v = raw.get(key)
    if not isinstance(v, str) or not v:
        raise _malformed(gid, f"{key} missing or not a non-empty string")
    return v


def _opt_str(raw: dict, key: str, gid: str) -> str | None:
    v = raw.get(key)
    if v is None:
        return None
    if not isinstance(v, str) or not v:
        raise _malformed(gid, f"{key} is not a non-empty string")
    return v


def _expiry(raw: dict, gid: str) -> int:
    # Every grant we write has an expiry; a missing one is treated as malformed, not "never".
    v = raw.get("expires_at")
    if not isinstance(v, Decimal) or v != v.to_integral_value():
        raise _malformed(gid, "expires_at missing or not a whole number")
    return int(v)


def _str_list(raw: dict, key: str, gid: str) -> frozenset[str]:
    v = raw.get(key, [])
    if not isinstance(v, list) or not all(isinstance(t, str) and t for t in v):
        raise _malformed(gid, f"{key} is not a list of tool names")
    return frozenset(v)


def _resources(raw: dict, gid: str) -> dict[str, Any]:
    v = raw.get("resources", {})
    if not isinstance(v, dict):
        raise _malformed(gid, "resources is not a map")
    repo = v.get("repository")
    if repo is not None and not isinstance(repo, str):
        raise _malformed(gid, "resources.repository is not a string")
    return dict(v)


def store_from_env() -> GrantStore:
    """`AGENTLEDGER_GRANT_STORE=dynamodb` gives DynamoGrantStore; unset or `file` gives the JSON file store.

    Logs which store it picked. With the variable unset, a gateway reads the dev file and never
    sees a revoke made with `agentledger grant revoke`, so that case logs a WARNING.
    """
    kind = os.environ.get(ENV_STORE, "")
    if kind in ("", "file"):
        path = os.environ.get(ENV_FILE, DEFAULT_FILE)
        log.warning("grant store: JSON file %s (dev only; revokes made in DynamoDB are NOT seen). "
                    "Set %s=dynamodb for the real store.", path, ENV_STORE)
        return JsonFileGrantStore(path)
    if kind == "dynamodb":
        store = DynamoGrantStore(os.environ.get(ENV_TABLE) or TABLE_NAME)
        log.info("grant store: %r", store)
        return store
    raise ValueError(f"{ENV_STORE}={kind!r} is not supported: use 'dynamodb' or 'file' (or leave it unset)")
