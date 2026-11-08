"""AgentLedger CLI: human sign-in and session commands."""

from __future__ import annotations

import sys
from pathlib import Path

__version__ = "0.0.1"

# controlplane/ lives at the repo root, outside this package. The CLI is installed
# editable (`pip install -e cli`), so the repo root is two levels above this file.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "controlplane").is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))
