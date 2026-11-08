"""Choose the grant store from AGENTLEDGER_GRANT_STORE.

    unset or "json"   local JSON file (development only), AGENTLEDGER_GRANTS_FILE
    "dynamodb"        controlplane.grants.store_from_env()  (Joshua's store)

Anything else, or a store that cannot load, stops the gateway at startup. There is no
silent fallback to the file store: asking for DynamoDB and quietly getting a local file
would enforce the wrong grants.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping

from .grants import GrantStore, JsonFileGrantStore


class GrantStoreConfigError(RuntimeError):
    """The requested grant store is unknown or cannot be built."""


def build_grant_store(env: Mapping[str, str]) -> GrantStore:
    mode = (env.get("AGENTLEDGER_GRANT_STORE") or "json").strip().lower()
    if mode == "json":
        return JsonFileGrantStore(env.get("AGENTLEDGER_GRANTS_FILE", "gateway-grants.json"))
    if mode == "dynamodb":
        try:
            module = importlib.import_module("controlplane.grants")
            store = module.store_from_env()
        except Exception as e:
            raise GrantStoreConfigError(
                f"AGENTLEDGER_GRANT_STORE=dynamodb but the store failed to load: "
                f"{type(e).__name__}: {e}") from e
        if not callable(getattr(store, "get", None)):
            raise GrantStoreConfigError("dynamodb store has no get(grant_id) method")
        return store
    raise GrantStoreConfigError(f"unknown AGENTLEDGER_GRANT_STORE {mode!r} (use json or dynamodb)")
