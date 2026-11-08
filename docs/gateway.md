# AgentLedger gateway

FastMCP server at `http://127.0.0.1:8000/mcp`. Every request to `/mcp` needs a valid agent bearer token. There is no unauthenticated mode.

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

Keep the token out of the file. Kiro expands `${VAR}` from your environment:

```json
{
  "mcpServers": {
    "agentledger-local": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer ${AGENTLEDGER_TOKEN}" }
    }
  }
}
```

For the EC2 tunnel, use the same `headers` block with the tunnel URL (for example `http://127.0.0.1:18000/mcp`). Set `AGENTLEDGER_TOKEN` before launching Kiro. Tokens expire, so refresh it and restart the MCP connection.

## Tools

- `agentledger_whoami`: the verified `agent_id`, `client_id`, `scopes` and `auth_mode`.
- `agentledger_ping`: connectivity check, same `auth_mode`.

`auth_mode` is `agent_token_verified_no_grants`: the agent identity is verified, nothing more.

## Limitations

- No employee, workflow or grant identity. `whoami` does not report any.
- No per-tool or per-agent authorization; any valid agent token can call every tool.
- No revocation. A token stays valid until it expires.
- Plain HTTP on loopback. TLS and exposure are the job of the tunnel or proxy in front.

## Tests

```powershell
.\.venv\Scripts\python -m pytest tests\gateway
```

Offline only: local RSA keys, a fake JWKS lookup, and a server on an ephemeral `127.0.0.1` port.
