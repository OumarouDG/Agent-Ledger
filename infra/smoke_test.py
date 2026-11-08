"""G0 check: mint a token for every agent and verify it like the gateway will.

Prints claim names and values that are safe to show. Never prints a token.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from controlplane.auth.agent_tokens import mint_agent_token  # noqa: E402
from controlplane.auth.config import load_config  # noqa: E402
from controlplane.auth.jwt_verify import AuthError, Verifier, agent_client_ids  # noqa: E402


def main() -> int:
    cfg = load_config()
    verifier = Verifier.from_config()
    allowed = set(agent_client_ids())
    failures = 0
    print(f"Pool {cfg['user_pool_id']} in {cfg['region']}\n")
    for agent_id in cfg["agents"]:
        try:
            tok = mint_agent_token(agent_id)
            claims = verifier.verify_agent(tok.access_token, allowed, required_scope=f"{cfg['resource_server']}/tools")
            exp = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).strftime("%H:%M UTC")
            print(f"PASS {agent_id:13} client={claims['client_id']} scope='{claims.get('scope')}' expires={exp}")
        except AuthError as e:
            failures += 1
            print(f"FAIL {agent_id:13} verify: {e.reason}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"FAIL {agent_id:13} mint: {type(e).__name__}: {e}")

    # Negative check: a token from one agent must not pass as an unknown client.
    try:
        tok = mint_agent_token("agent_coder")
        verifier.verify_agent(tok.access_token, allowed_client_ids={"not-a-real-client"})
        print("FAIL negative check: unknown client was accepted")
        failures += 1
    except AuthError as e:
        print(f"PASS negative check rejected with {e.reason}")

    print("\nAll good." if not failures else f"\n{failures} failure(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
