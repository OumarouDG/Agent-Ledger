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
  Agent access is not meant to depend on token expiry. Agent access tokens are separate (one per agent app client, 12 hours) and logout does not touch them. By design, the gateway checks live grant state (`X-Grant-Id`) on every call, so revoking or quarantining a grant stops an agent at its next call while its token is still valid (see "Agent identity vs. sessions" in `infra/README.md`). The grant store and that check are in the gateway lane and are not part of this branch, so nothing in this branch tests them.
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

Test files: `tests/unit/cli/` (`test_skeleton.py`, `test_storage.py`, `test_login_command.py`, `test_session.py`, `test_session_commands.py`, `test_silent_failures.py`) and `tests/live/test_live_cli.py`.
