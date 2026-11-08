# AgentLedger gateway

FastMCP server at `http://127.0.0.1:8000/mcp`. Every request to `/mcp` needs a valid agent bearer token. There is no unauthenticated mode. Grant-protected tools also need a valid grant.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt -r gateway\requirements.txt
.\.venv\Scripts\python -m gateway.server
```

Run it as a module (`-m gateway.server`) from the repo root, not as `python gateway/server.py`.

The gateway reads `shared/cognito.json` (override with `AGENTLEDGER_COGNITO_CONFIG`) at startup. If it is missing or has no agents, the gateway refuses to start. Restart it after adding agents.

## What a token must be

A Cognito `client_credentials` access token that:

- is signed by the pool's JWKS and not expired, with the configured issuer
- has `token_use=access` and a `client_id` listed in `shared/cognito.json`
- is a machine token (no `username`; human ID tokens are rejected)
- includes the `agentledger/tools` scope

Anything else gets `401` before any tool runs. JWKS lookups run in a worker thread so they do not block the event loop. Raw tokens are never stored or logged.

## Calling it

```powershell
curl.exe -i http://127.0.0.1:8000/mcp   # 401, no token
```

Mint a token with the existing auth tooling, keep it in an environment variable, and send it as `Authorization: Bearer <token>`.

## Kiro config

Kiro expands `${VAR}` from your environment, so no token is stored in the file. Set these before launching Kiro:

- `AGENTLEDGER_TOKEN`: the agent access token (expires; refresh and reconnect)
- `AGENTLEDGER_GRANT_ID` and `AGENTLEDGER_WORKFLOW_ID`: sent as `X-Grant-Id` and `X-Workflow-Id`

`.kiro/settings/mcp.json` has `agentledger-local` (enabled) and `agentledger-ec2` (tunnel on port 18000, disabled until the EC2 tunnel is up).

## Tools

- `agentledger_whoami`, `agentledger_ping`: need a valid agent token only.
- `get_issue`: grant-protected. Development mock that returns issue #42 only; no GitHub call.

## Grant authorization

A grant-protected tool runs this check, failing closed on any doubt: agent known, grant header present, workflow header present, grant exists, grant agent equals the token's agent, workflow matches, status `active`, not expired, every parent grant usable, tool listed in the grant's `tools` (`delegable_tools` never allows execution). Every allow and deny is appended to the audit file. A denied call returns `denied: <reason>`.

**Stub:** there is no grant service yet. `JsonFileGrantStore` reads `AGENTLEDGER_GRANTS_FILE` (default `gateway-grants.json`) on every lookup, so a revoke applies to the next request. Replace it with Joshua's service behind `gateway.grants.GrantStore`. Audit goes to `AGENTLEDGER_AUDIT_FILE` (default `gateway-audit.jsonl`), a placeholder until the Ledger schema is agreed.

Example grants file:

```json
{"grants": {"grant_001": {"agent_id": "agent_coder", "workflow_id": "wf_001", "human_id": "alice",
  "status": "active", "expires_at": 4102444800, "tools": ["get_issue"]}}}
```

## Limitations

- Grants come from a local dev file, not an authoritative service.
- No resource checks (repo/branch), no Sentinel rules, no real GitHub calls yet.
- A token stays valid until it expires; revocation applies to grants, not tokens.
- Plain HTTP on loopback. TLS and exposure are the job of the tunnel or proxy in front.
## Tests

```powershell
.\.venv\Scripts\python -m pytest tests\gateway
```

Offline only: local RSA keys, a fake JWKS lookup, and a server on an ephemeral `127.0.0.1` port.
