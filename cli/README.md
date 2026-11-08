# AgentLedger CLI (`agentledger`)

The CLI signs a human in to the AgentLedger Cognito user pool, keeps the session in the OS credential store, and hands a verified session to the agent runtime. It reads the non-secret pool settings from `shared/cognito.json`, which `python infra/cognito_setup.py` writes (see `infra/README.md`).

## Install

From the repo root, in the venv:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e cli
agentledger --help
```

Install it editable (`-e`). The CLI imports `controlplane/` from the repo root and finds the repo from its own location, so a non-editable install can't find it.

## Commands

| Command | Does | Exit code |
| --- | --- | --- |
| `agentledger login` | Opens Cognito managed login in the browser (authorization code + PKCE), catches the redirect on `localhost:8765`, verifies the ID token, stores the tokens. Prints `Signed in as alice (engineer)`. | 0 signed in; 1 anything else |
| `agentledger whoami` | Verifies the stored ID token and prints user, groups and expiry. If the ID token has expired, refreshes once with the stored refresh token. | 0 verified; 1 not signed in, expired, rejected or not checked |
| `agentledger status` | Signed in, signed out, expired or rejected, plus pool and region. Verifies the ID token, never refreshes. | always 0 |
| `agentledger logout` | Revokes the refresh token at `/oauth2/revoke`, then deletes the stored tokens, even if the revoke failed. | 0 revoke accepted (or nothing to revoke) and tokens deleted; 1 revoke failed or delete failed |

No command prints a token. Error messages name the cause and the fix, for example `Not signed in; run agentledger login.`

The browser page shown after sign-in never says "signed in". The page is sent before the code exchange and the token check, so it says `sign-in received` (or `sign-in failed (...)`). The terminal has the result.

## Grant commands

All four need a signed-in human (`agentledger login`). Signed out or expired, they print the session's message ("run agentledger login") and exit 1. `human_id` always comes from the verified session; there is no flag for it. Grants are written to DynamoDB table `agentledger-grants` (`AGENTLEDGER_GRANTS_TABLE` overrides).

| Command | Does | Exit code |
| --- | --- | --- |
| `agentledger grant create --agent agent_coder --workflow wf_demo --tools get_issue --repo owner/name [--delegable t1,t2] [--ttl 60m]` | Root grant for the agent on your behalf. `--tools` and `--delegable` take comma-separated names, repeated, or both. `--ttl` is `30s`, `60m` or `2h` (default `60m`, at most 4 h). Prints the grant. | 0 created; 1 refused (`Refused: <reason>: ...`) or store error; 2 bad usage |
| `agentledger grant revoke <grant_id>` | Sets `status=revoked`. The gateway denies it and its children at their next call. A second revoke says "already revoked". | 0 revoked or already revoked; 1 unknown ID, not permitted, store error |
| `agentledger grant show <grant_id>` | One grant, from a strongly consistent read. | 0; 1 unknown ID, not permitted, store error |
| `agentledger grant list [--workflow wf_demo]` | Your grants, sorted by expiry. | 0; 1 store error |

Who may do what (`# GUESS:` values in `controlplane/grants/service.py`):

- **Create:** humans in `engineer` or `security-admin`. `reviewer` is refused with `role_not_permitted`.
- **Revoke, show, list:** your own grants. `security-admin` may revoke, show and list any grant.

Refusal reasons: `unknown_agent`, `bad_repository`, `bad_expiry`, `no_tools`, `no_human`, `role_not_permitted`, `human_mismatch`, `bad_request`, `revoke_not_permitted`, `not_permitted`. Child grants (agent to agent) are created by the runtime, not the CLI.

`grant list --workflow` reads a DynamoDB index that can lag a revoke by a moment, and says so. `grant show` is always current.

## Run and probe

Both need a signed-in human and the gateway tunnel (`.\scripts\start-tunnel.ps1`). The gateway URL is `AGENTLEDGER_GATEWAY_URL`, default `http://127.0.0.1:18000/mcp`. Plain `http` is accepted only for this machine (`127.0.0.1`, `localhost`, `::1`); any other host must be `https`, or the agent session refuses to start before a token is minted.

### `agentledger run --issue N [--repo owner/name] [--workflow wf_x] [--step]`

Three agents turn the issue into a pull request. Each one mints its own Cognito token and calls the gateway under its own grant:

| Agent | Grant | Calls, in this order |
| --- | --- | --- |
| `agent_lead` | root, from you: executes `get_issue`, `llm_converse`; may delegate the tools below | `get_issue`, `llm_converse` (plan) |
| `agent_coder` | child of Lead; prefix `agentledger/<wf>/coder/` | `llm_converse` (one file), `create_branch`, `commit_file`, `open_pull_request` |
| `agent_tester` | child of Lead; prefix `agentledger/<wf>/` | `get_test_result` every 10 s for up to 3 min, then `get_pull_request` |

This is scripted orchestration: the order of calls is fixed in code, and the model (`us.amazon.nova-lite-v1:0`, 300 tokens per reply) writes only the plan text and the file. The child grants are delegated using the agent ID verified from Lead's own token. Model output is committed as file content and never run. The runtime refuses a file path that is hidden (`.github/...`), contains `..`, or is a test file; Coder's grant alone would allow those. Tester's report is built in code from GitHub's record for the exact commit. "Passed" means GitHub says `completed` and `success` for that commit and the PR's head is that commit.

- `--workflow`: default a new `wf_<random>`. `wf_001` is refused (the Kiro demo). Each run gets its own branch `agentledger/<wf>/coder/issue-<n>-<run id>`, so one workflow can be run again.
- `--step`: before each call, prints what is next and waits for Enter. The polling loop gets one pause, not one per check. Ctrl+C at a prompt stops the run before that call is sent. To show a revoke mid-run, run `agentledger grant revoke <root grant>` in a second terminal at a prompt; the next call is denied `parent_grant_revoked`.
- Output: one line per call (agent, tool, grant, time, allowed or the denial reason, what came back), then a summary with the grant status read back from the store, branch, commit, PR, test result, latency, and the exit code.
- Grants: a run that finishes (tests passed or not) leaves its grants active until they expire (60 min), for review and `probe`. A run that does not finish (denial, gateway unreachable, Ctrl+C, crash) revokes the root, which the gateway applies to both children at their next call.

| Exit | Meaning |
| --- | --- |
| 0 | tests passed for the PR's head commit |
| 1 | a call was denied, a tool failed, the model's reply was unusable, a grant was refused, or the run was stopped |
| 2 | gateway unreachable (also click's own usage errors, before anything is written) |
| 3 | tests failed, did not finish, no test run was found, or the PR head is not the tested commit |

### `agentledger probe --workflow wf_x [--issue 1] [--until-locked]`

`agent_rogue` attacks a workflow that has an active run. You give Rogue its own fresh root grant (`get_issue` only, prefix `agentledger/<wf>/rogue/`, 15 min), revoked when the probe ends. A baseline `get_issue` on that grant must be allowed; then each attack must be refused with its reason:

| Attack | Expected | Counts toward the Sentinel |
| --- | --- | --- |
| Coder's grant ID with Rogue's token | `grant_agent_mismatch` | no |
| A tool call with no grant | `missing_grant` | no |
| Delegate a child from Lead's grant | `not_parent_holder` (grant service; no gateway call) | no |
| `create_branch main` on its own grant | `tool_not_permitted` | yes |

`--until-locked` sends two more violations (three in a row), then calls `get_issue`, which the grant allows: it must now be denied `grant_quarantined`. The gateway only turns allowed calls into `grant_quarantined`; denied calls keep their own reason after the lock, so the probe cannot watch for the lock directly. It assumes the gateway's threshold is 3. A fresh grant per probe means a lock never carries over.

Exit 0 if every attempt got its expected result; 1 if anything was allowed (`ALLOWED (unexpected)`), a reason was wrong, the baseline failed, or the probe could not start; 2 if the gateway is unreachable.

### Measured once (Nov 7, through the SSM tunnel)

- `agentledger run --issue 1`: 9 gateway calls, median 835 ms, min 576 ms, max 1424 ms; CI result found on the second check. One run; nova-lite at 300 tokens wrote a `greeting.py` that passed the demo test.
- `agentledger_ping` (no grant, no backend), 10 calls: median 239 ms, min 235 ms, max 297 ms. Each call opens a new MCP session, so this is the floor per call.
- Revoke before Coder's `create_branch` with `--step`: denied `parent_grant_revoked` at the next call (165 ms).

### Limits

- The gateway mediates tool calls only. It cannot see an agent's local shell or files, and nothing stops code on this machine from using the AWS credentials directly.
- Agent tokens last 12 hours and cannot be revoked early. Revoking a grant is what stops an agent.
- The test-file and hidden-path rule for Coder is in the runtime, not the grant. A different client with Coder's token and grant could write those paths on its branch.
- Child grants show `active` in the table after the root is revoked; the gateway denies them through the revoked parent. Nothing is cascaded by writing.
- `probe` finds the workflow's grants through an index that can lag; each candidate is re-read with a consistent read before use.

## For the agent runtime

```python
from agentledger.session import current_session, SessionError

s = current_session()          # verified; refreshes once if the ID token expired
s.username, s.groups, s.expires_at, s.id_token, s.access_token
```

`current_session()` raises a `SessionError` subclass with a printable message when there is no usable session:

| Exception | When |
| --- | --- |
| `NotSignedIn` | nothing stored, or the stored entries are unreadable |
| `SessionExpired` | ID token expired and the refresh was refused, failed or impossible (no refresh token) |
| `InvalidSession` | the ID token failed verification for another reason; `.reason` is `wrong_issuer`, `wrong_audience`, `wrong_token_use`, `invalid_token`, `unknown_signing_key`, or `refreshed token: <reason>` |
| `VerifierUnavailable` | the pool's JWKS could not be fetched (network), so the session was not checked |
| `SessionError` | the credential store or `shared/cognito.json` can't be read, or a refreshed session couldn't be saved |

Only the ID token is verified here. The access token is returned as stored; the gateway verifies it on every call.

## Where tokens are stored

`keyring`, service `agentledger`, keyed by the user pool ID. On Windows that is Credential Manager (Control Panel > Credential Manager > Windows Credentials).

- `<pool_id>` holds a small index: format version, number of parts, sha256 of the token bundle.
- `<pool_id>#0` .. `#n-1` hold the JSON bundle (`id_token`, `access_token`, `refresh_token`) in 1000-character parts. Windows caps one entry at 2560 bytes, and keyring stores UTF-16, so one entry holds at most 1280 characters. A real alice session used 4 parts plus the index.
- Parts are written before the index. A missing part, a changed part or an unreadable index is reported as `Stored sign-in ...; run agentledger login`, never returned as a session.
- Nothing is written to disk. A unit test blocks file writes while saving, loading and deleting.

## Known limits

- **Revoked tokens still verify locally until they expire.** `agentledger logout` revokes the refresh token, and Cognito then also revokes the access and ID tokens issued from it, but only for Cognito's own APIs. A JWT is checked by signature, issuer and expiry, so anything that verifies these tokens locally (including the gateway and `controlplane.auth.jwt_verify`) still accepts a human's access and ID tokens for up to 60 minutes after logout. Token lifetimes are not shortened to work around this.
  Agent access is not meant to depend on token expiry. Agent access tokens are separate (one per agent app client, 12 hours) and logout does not touch them; they can't be revoked early. The gateway checks live grant state (`X-Grant-Id`) on every call, so revoking a grant (`agentledger grant revoke`) stops an agent at its next call while its token is still valid. `tests/live/test_live_grants.py` checks this with `authorize()` called directly; it is not yet tested through the gateway.
- **A 200 from `/oauth2/revoke` does not prove a live token was revoked.** Cognito also answers 200 for a token that is already revoked or invalid (AWS docs; checked by `test_second_revoke_of_same_token_still_returns_200`). `logout` therefore prints `revoke accepted by Cognito`, not `revoked`.
- **`whoami` and `status` need the network** to fetch the pool's signing keys (JWKS) on every run (each command is a new process). Without it they say `can't reach the pool's signing keys ... Session not checked` and refuse the session. They do not report the token as bad.
- **One sign-in per pool per OS user.** A second `agentledger login` replaces the stored session.
- **Two processes refreshing at once** can race if refresh-token rotation is turned on for the pool: one of them may store a refresh token the other has already used. Whether rotation is on for `agentledger-cli` was not checked. Not tested.

## Tests

| Tier | Command | Covers |
| --- | --- | --- |
| unit | `pytest -q` | everything above with fakes: in-memory keyring, fake browser and server, JWTs signed by a local RSA key checked by the real `Verifier`, a faked JWKS HTTP layer. Real loopback sockets for the port tests only. |
| live | `pytest -q --live` | real `/oauth2/token` refresh and `/oauth2/revoke` with a throwaway user and app client, deleted afterwards (`tests/live/test_live_cli.py`) |
| run | `agentledger whoami`, `status`, `logout`, `whoami` | after a manual `agentledger login` |

Test files: `tests/unit/cli/` (`test_skeleton.py`, `test_storage.py`, `test_login_command.py`, `test_session.py`, `test_session_commands.py`, `test_silent_failures.py`) and `tests/live/test_live_cli.py`. Grant commands: `tests/unit/grants/test_grant_commands.py`.

Run and probe: `tests/unit/runtime/` runs a real gateway server in-process on `127.0.0.1` with locally signed agent tokens, an in-memory grant store, a fake GitHub App and a fake model (`test_gateway_client.py`, `test_workflow.py`, `test_agents.py`, `test_run_command.py`, `test_probe.py`, `test_silent_failures.py`). `tests/live/test_live_runtime.py` creates real grants under `wf_live_*` workflows with real tokens, checks a few denials at the real gateway when the tunnel is open, and revokes everything at teardown.
