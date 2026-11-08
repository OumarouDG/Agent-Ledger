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

## Launching Kiro against EC2

Close every Kiro window, then run `.\scripts\launch-kiro.ps1` from the repo root. It starts the SSM tunnel (port 18000) if needed, mints the agent token, sets `AGENTLEDGER_TOKEN`, `AGENTLEDGER_GRANT_ID` and `AGENTLEDGER_WORKFLOW_ID` for the new Kiro process only, and starts Kiro. Options: `-Agent`, `-GrantId`, `-WorkflowId`. The token is never printed or written to disk and lasts about 12 hours; run the script again to refresh it. Kiro must be started by the script: a variable set in a terminal after Kiro is running does not reach it.

## Tools

- `agentledger_whoami`, `agentledger_ping`: need a valid agent token only.
- `get_issue`: grant-protected. Reads the issue from the repository named in the grant's `resources.repository`; the agent cannot choose the repo. With the GitHub App settings below it calls GitHub. Without them it is a development mock that returns issue #42 only.

## GitHub App

Set these on the gateway process: `AGENTLEDGER_GITHUB_APP_ID`, `AGENTLEDGER_GITHUB_INSTALLATION_ID`, `AGENTLEDGER_GITHUB_KEY_SECRET` (AWS Secrets Manager secret id holding the App private key PEM). The key is read from Secrets Manager and never written to disk or returned to agents. The instance role needs `secretsmanager:GetSecretValue` on that one secret. A grant must carry `resources.repository` (`owner/name`) or the call is denied with `resource_not_in_grant`.

## Grant authorization

A grant-protected tool runs this check, failing closed on any doubt: agent known, grant header present, workflow header present, grant exists, grant agent equals the token's agent, workflow matches, status `active`, not expired, every parent grant usable, tool listed in the grant's `tools` (`delegable_tools` never allows execution). Every allow and deny is appended to the audit file. A denied call returns `denied: <reason>`.

**Stub:** there is no grant service yet. `JsonFileGrantStore` reads `AGENTLEDGER_GRANTS_FILE` (default `gateway-grants.json`) on every lookup, so a revoke applies to the next request. Replace it with Joshua's service behind `gateway.grants.GrantStore`. Audit goes to `AGENTLEDGER_AUDIT_FILE` (default `gateway-audit.jsonl`), a placeholder until the Ledger schema is agreed.

Example grants file:

```json
{"grants": {"grant_001": {"agent_id": "agent_coder", "workflow_id": "wf_001", "human_id": "alice",
  "status": "active", "expires_at": 4102444800, "tools": ["get_issue"]}}}
```

## Write tools

- `create_branch(branch)`: creates a branch from the grant's `resources.base_branch` (default `main`).
- `commit_file(branch, path, content, message)`: creates or updates one text file (max 100 KB).

Both need `resources.repository` and `resources.branch_prefix` in the grant. The prefix must end with `/` (for example `agentledger/wf_001/`). A branch that does not start with it, including `main`, is denied with `branch_not_permitted` before any GitHub call. Paths may not start with `/`, contain `..` or touch `.git`. The GitHub App's own permissions are the outer limit: it can write contents only on repos where it is installed.

## Model calls

- `llm_converse(messages, model=None, system=None)`: Bedrock Converse using the gateway's own AWS role. `messages` is a list of `{role: user|assistant, content: text}` that alternates, starts and ends with a user message (max 20 messages, 8000 characters each; `system` max 4000).

The grant controls it: `tools` must include `llm_converse`, `resources.models` lists the model ids the agent may use (the first is the default; anything else is denied with `model_not_permitted` before Bedrock is called) and `resources.max_tokens` caps the reply (default 1024, never above 2000). The result has `text`, `stop_reason` and token counts. The model id is written to the audit trail; token counts are not yet. Use ids the account allows, for example `us.amazon.nova-lite-v1:0`.

## Audit

If an audit event cannot be written, the call is denied (`audit_unavailable`).

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
