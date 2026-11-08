"""Gateway tests must not lock real grants or write lock files into the repo.

Servers built without an explicit Sentinel read these variables when they start, so set them
before any test module creates one. test_sentinel.py passes its own Sentinel when it needs one.
"""

import os
import tempfile

os.environ["AGENTLEDGER_SENTINEL_FILE"] = os.path.join(
    tempfile.mkdtemp(prefix="al-sentinel-"), "quarantine.json")
os.environ["AGENTLEDGER_SENTINEL_THRESHOLD"] = "0"
os.environ["AGENTLEDGER_AUDIT_FILE"] = os.path.join(tempfile.mkdtemp(prefix="al-audit-"), "audit.jsonl")
