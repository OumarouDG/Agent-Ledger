"""Grant service: the authoritative store for delegation grants."""

from controlplane.grants.store import DynamoGrantStore, store_from_env

__all__ = ["DynamoGrantStore", "store_from_env"]
