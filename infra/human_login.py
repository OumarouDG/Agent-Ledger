"""G0 check: sign in as a demo user with authorization code + PKCE.

Thin wrapper over agentledger.login (cli/agentledger/login.py), so the CLI and
this script share one implementation. Demo passwords are in
infra/out/demo-users.local.json.
"""

from __future__ import annotations

import sys
import threading
import time
import webbrowser  # noqa: F401  tests patch human_login.webbrowser.open
from http.server import HTTPServer
from pathlib import Path

import requests  # noqa: F401  tests patch human_login.requests.post

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT, ROOT / "cli"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from agentledger import login  # noqa: E402
from controlplane.auth.config import load_config  # noqa: E402
from controlplane.auth.jwt_verify import Verifier  # noqa: E402

RETRY_HINT = "python infra/human_login.py"
result: dict = {}


def main() -> int:
    # Module attributes are read here, at call time, so tests can patch them on this module.
    return login.run(
        RETRY_HINT,
        result=result,
        load_config=load_config,
        server_cls=HTTPServer,
        threading_mod=threading,
        monotonic=time.monotonic,
        verifier_cls=Verifier,
    )


if __name__ == "__main__":
    sys.exit(main())
