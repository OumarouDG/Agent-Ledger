# AgentLedger identity provider (Amazon Cognito)

The scripts in this folder create and check the Cognito user pool that gives every human and every agent in AgentLedger its own identity. The gateway and the CLI read the non-secret IDs from `shared/cognito.json`; nobody needs to open the AWS console to use them.

## What setup creates

`python infra/cognito_setup.py` creates or updates, in `us-east-1` by default (`AWS_REGION` overrides):

| Resource | Name / value | Notes |
| --- | --- | --- |
| User pool | `agentledger-pool` | Admin-created users only, case-insensitive usernames, password policy 12+ chars with upper, lower, digit, symbol. Deletion protection off so teardown works. |
| Domain | `agentledger-<last 8 digits of account id>` | Classic hosted UI (managed login version 1). Used for human login and the `/oauth2/token` fallback. |
| Resource server | `agentledger` | Scopes `agentledger/tools`, `agentledger/llm`, `agentledger/messages`. |
| Groups | `engineer`, `reviewer`, `security-admin` | |
| Demo users | `alice` (engineer), `bob` (reviewer), `dana` (security-admin) | Random passwords, written to `infra/out/demo-users.local.json`. Emails are `@acme.test`. |
| Public client `agentledger-cli` | no secret, authorization code + PKCE | Callback `http://localhost:8765/callback`. Scopes `openid email profile`. Access and ID tokens 60 min, refresh 12 h. |
| Public client `agentledger-console` | no secret, authorization code + PKCE | Callback `http://localhost:5173/callback`. Same lifetimes. |
| Agent clients `agentledger-agent_<name>` | one confidential client per agent, with a secret | Only `ALLOW_CLIENT_TOKEN_AUTH`; OAuth flow `client_credentials`. Access tokens last 12 h. |
| Secrets | `agentledger/agents/<agent_id>` in Secrets Manager | JSON with that agent's `client_id` and `client_secret`. |

Agent scope ceilings (a grant can narrow these, never widen them):

| Agent | Scopes |
| --- | --- |
| `agent_lead` | tools, llm, messages |
| `agent_coder` | tools, llm, messages |
| `agent_tester` | tools, llm |
| `agent_rogue` | tools, llm, messages |
| `agent_triage` | tools, llm |

Cognito refuses a mint request for a scope outside the ceiling (`NotAuthorizedException: Client is not allowed to request these scopes`); it does not drop the scope quietly. The live tests check this.

Setup is idempotent. A second run creates nothing: it prints `exists` for the pool and domain, `updated` for the resource server and public clients, and `agent client ready` per agent, and leaves `shared/cognito.json` byte-identical. Each run does write a new version of each agent secret, with the same value.

### Fallbacks

Setup prefers two things and falls back if it can't have them. Either fallback prints a `WARNING` line at the time and a `WARNING` block at the end of the run, and is recorded in `shared/cognito.json`:

- `token_mode`: `get_client_token` (Cognito `GetClientToken`, no domain call) or `oauth2_token` (the domain's `/oauth2/token` endpoint), used only if Cognito rejected `ALLOW_CLIENT_TOKEN_AUTH` for that client.
- `secret_ref`: `secretsmanager:<name>`, or `local:<agent_id>` if Secrets Manager was denied. A `local:` secret lives only on the machine that ran setup.

`mint_agent_token` uses the path `token_mode` names and nothing else. An unknown or missing `token_mode`, or `get_client_token` on a boto3 without that method, raises instead of quietly switching path.

## Agent identity vs. sessions

- **An agent's identity is persistent.** Each agent is one Cognito app client that exists until teardown. Its access token says *which agent this is* (`client_id`, `sub` equal to the client id, `token_use: access`, scope ceiling) and nothing else.
- **What an agent may do right now is not in the token.** Runs, sessions and delegations are grants held by the control plane (`grant_...` IDs). The gateway checks the token for identity and the grant (sent as `X-Grant-Id`) for permission: which tools and models, which workflow, what budget, whether the grant is still live.
- **Revocation works on the grant, not the token.** Agent tokens last 12 hours on purpose: the design is that revoking or quarantining a grant stops the agent at its next call while its token is still valid. Nothing in Cognito changes when a run starts, ends or is revoked.
- **Humans are separate.** Humans sign in with PKCE and get an ID token with `cognito:groups`. `verify_agent` rejects human ID tokens (`wrong_token_use`) and human access tokens (`not_an_agent_token`, from the `username` claim that only human tokens carry).

The grant store and the `X-Grant-Id` check live in the control plane, not in this folder, and are not part of this branch. Nothing here tests revocation.

## How to use it

### 1. Credentials

All scripts use the default AWS credentials file (`%USERPROFILE%\.aws\credentials` on Windows, `~/.aws/credentials` elsewhere). Workshop credentials are temporary. To refresh them:

1. Open the Workshop Studio event page and copy the AWS CLI credentials (access key id, secret access key, session token).
2. Paste them into the `[default]` profile of the credentials file, replacing the old values.
3. Check: `python -c "import boto3; print(boto3.client('sts').get_caller_identity()['Arn'])"` prints the workshop role ARN.

When they expire, `mint_agent_token` raises `AwsCredentialsError` naming the AWS error code and telling you to paste fresh credentials. Setup exits with `Can't reach AWS (...)`.

### 2. Install

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`boto3>=1.43.126` is required for `get_client_token`.

### 3. Setup, smoke test, human login

```powershell
python infra/cognito_setup.py      # create or update; writes shared/cognito.json
python infra/smoke_test.py         # mint and verify a token for every agent, plus one negative check
python infra/human_login.py        # browser sign-in as alice, bob or dana; prints username and groups
```

`smoke_test.py` prints `PASS <agent> client=... scope=... expires=...` per agent and exits 1 if anything fails. It never prints a token.

`human_login.py` opens the managed login page and waits on `localhost:8765` for the redirect. It prints `Signed in: <user>  groups=[...]` and never prints a token. It gives up after 120 s (`Login timed out after 120 s ...`) and exits 1 on Ctrl+C (`Login cancelled`). Demo passwords are in `infra/out/demo-users.local.json`.

### 4. Teardown

```powershell
python infra/cognito_teardown.py
```

Asks you to type `delete`. Then it deletes the domain, the user pool (with every user and client in it), the agent secrets in Secrets Manager (no recovery window), `shared/cognito.json`, `infra/out/demo-users.local.json` and `infra/out/agent-secrets.local.json`. This cannot be undone; rerun setup to start again with new IDs.

## Where secrets live

| What | Where | In git? |
| --- | --- | --- |
| Agent client secrets | Secrets Manager `agentledger/agents/<agent_id>` | no |
| Agent client secrets (fallback only) | `infra/out/agent-secrets.local.json` | no, gitignored |
| Demo user passwords | `infra/out/demo-users.local.json` | no, gitignored |
| Pool, client and agent IDs, scopes, `token_mode`, `secret_ref` | `shared/cognito.json` | yes; a unit test fails if it ever holds a secret, password, JWT, AWS key or long opaque value |
| AWS credentials | your AWS credentials file | no |

Agent secrets are read only by the backend process that mints tokens (`controlplane/auth/agent_tokens.py`). `AgentToken`'s `repr` hides the token, and no script prints one.

## Using it from code

```python
from controlplane.auth.agent_tokens import mint_agent_token
from controlplane.auth.jwt_verify import AuthError, Verifier, agent_client_ids

tok = mint_agent_token("agent_coder")                       # backend only
verifier = Verifier.from_config()                           # issuer + JWKS from shared/cognito.json
claims = verifier.verify_agent(tok.access_token, set(agent_client_ids()), required_scope="agentledger/tools")
agent_id = agent_client_ids()[claims["client_id"]]          # "agent_coder"
```

`AuthError.reason` is safe to log and return: `token_expired`, `wrong_issuer`, `unknown_signing_key`, `invalid_token`, `wrong_token_use`, `unknown_client`, `not_an_agent_token`, `missing_scope`, `wrong_audience`.

`AGENTLEDGER_COGNITO_CONFIG` points `load_config()` at a different config file.

## Test tiers

| Tier | Command | Needs | What it covers |
| --- | --- | --- | --- |
| unit | `pytest -q` | venv only | Config loading, token minting (AWS stubbed with botocore `Stubber`, `requests.post` patched), JWT checks (other issuer, missing claims, `alg=none`, HS256 key confusion, malformed), no secrets in `shared/cognito.json`, setup fallback warnings, human login Ctrl+C and timeout. No network. |
| live | `pytest -q --live` | AWS credentials | Real tokens for every agent verified against the pool's JWKS, scope ceilings, every cross-agent pair rejected, human ID and access tokens rejected by `verify_agent`. |
| run | `python infra/smoke_test.py` | AWS credentials | Same as the first live check, as a script. |
| manual | `python infra/human_login.py` | a browser | Sign-in for each demo user and a wrong password. |

Live tests are marked `@pytest.mark.live` and are skipped unless `--live` is passed. The human-token live tests create a throwaway user `livetest-<hex>` and app client `agentledger-livetest-<hex>` (admin password auth, no secret), sign in once, and delete both at the end of the module. If deletion fails they print a `WARNING` naming what to delete in the console.

## Known limits

- Agent tokens last 12 hours. This is a demo setting, chosen so the demo can show a revoked grant stopping an agent whose token is still valid.
- Human ID and access tokens last 60 minutes, refresh tokens 12 hours.
- `verify_agent` tells human access tokens from agent tokens by the `username` claim. The live tests confirm Cognito sets it today.
- Each `pytest --live` run briefly adds one user and one app client to the pool.
- On a re-run, setup prints nothing for groups and users that already exist.
