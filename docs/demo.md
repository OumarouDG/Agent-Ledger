# AgentLedger demo runbook

One story: an agent gets exactly the authority a human delegated, and everything it does (and is refused) is on the record.

## Before the demo (10 minutes)

1. **EC2 is current.** In an SSM shell on `i-02d94a2f0bf2a72db`, from `/home/ssm-user/Agent-Ledger`: `git pull --ff-only origin main`, then `sudo systemctl restart agentledger-gateway`, then `sudo systemctl status agentledger-gateway --no-pager` shows `active (running)`.
2. **Make a fresh grant** (grants live in DynamoDB and last at most 4 hours). Sign in with `agentledger login`, then:
   `agentledger grant create --agent agent_coder --workflow wf_001 --tools get_issue,create_branch,commit_file,llm_converse --repo OumarouDG/agentledger-demo --branch-prefix agentledger/wf_001/ --model us.amazon.nova-lite-v1:0 --ttl 3h`
   Note the grant id it prints (`gr_...`). Add `get_test_result,open_pull_request,get_pull_request` to `--tools` for the extended demo.
3. **Demo repo is clean.** `gh api repos/OumarouDG/agentledger-demo/branches --jq '.[].name'` prints only `main`. Delete leftovers with `gh api -X DELETE repos/OumarouDG/agentledger-demo/git/refs/heads/<branch>`.
4. **Start from a clean audit file** (optional): in the SSM shell, `mv gateway-audit.jsonl gateway-audit.old.jsonl`. The gateway creates a new one on the first call.
5. **Close every Kiro IDE window**, then run `.\scripts\launch-kiro.ps1 -GrantId <the id from step 2>`. It starts the tunnel, mints the `agent_coder` token and starts Kiro with the token, grant and workflow.
6. In Kiro, open a new chat. Confirm `agentledger-ec2` is connected.

## The demo

Say each prompt to Kiro as written. What to expect is on the right.

| # | Prompt to Kiro | Expect | Point to make |
|---|---|---|---|
| 1 | `Call agentledger_whoami` | `agent_id: agent_coder`, scopes, auth mode `agent_token_verified_grants_on_protected_tools` | The gateway knows who the agent is from a signed Cognito token, not from what the agent says. |
| 2 | `Call get_issue with issue_number 1` | The real issue from `agentledger-demo` | Allowed: the grant names this repo. The agent never picked the repo and never saw a GitHub credential. |
| 3 | `Call create_branch with branch main` | `denied: branch_not_permitted` | The grant only allows branches under `agentledger/wf_001/`. |
| 4 | `Call create_branch with branch agentledger/wf_001/demo` | Branch created | Inside the grant: allowed. |
| 5 | `Call commit_file on branch agentledger/wf_001/demo, path notes/hello.txt, content "hello from the agent", message "Add hello"` | Commit sha | The agent did real work, on a branch it is allowed to touch. |
| 6 | `Call commit_file on branch main, path x.txt, content "x", message "no"` | `denied: branch_not_permitted` | The agent cannot change protected code. |
| 7 | **Revoke the grant** (below), then `Call get_issue with issue_number 1` | `denied: grant_revoked` | Same token, same request. A valid token is not enough: authority is checked on every call. |
| 8 | Show the audit (below) | Every call above, allowed and denied | The record exists even for refused calls. |

### Revoke (step 7)

On your laptop, signed in:

```powershell
agentledger grant revoke <grant id>
```

A revoke cannot be undone. Make a new grant (step 2 of "Before the demo") and relaunch Kiro with it to continue.
No restart is needed; the gateway reads the grant on every call.

### Show the audit (step 8)

In the SSM shell:

```bash
.venv/bin/python scripts/audit_timeline.py
```

Read it like this: `ALLOW` or `DENY` is the gateway's decision, made before anything runs. `DONE` or `FAIL` on the next line is what actually happened, with the real commit SHA for commits (it matches GitHub). An `ALLOW` with no `DONE` after it means the action did not finish. `agentledger_whoami` and `agentledger_ping` also appear as `ALLOW` lines.

Useful options: `--denied` shows only refusals and failed actions, `--last 5` the latest five.

### Optional: Sentinel lock (after step 8)

Do this last: it locks the grant, so the other steps stop working until you release it. Restore the grant first if you revoked it in step 7.

1. In Kiro, ask for something the grant does not allow, three times in a row: `Call llm_converse with model anthropic.claude-opus-5 and a user message "hi"`. Each is denied with `model_not_permitted`.
2. Ask for something the grant does allow: `Call get_issue with issue_number 1`. Expect `denied: grant_quarantined`. The third refusal locked the grant.
3. Show the timeline: `.venv/bin/python scripts/audit_timeline.py --last 6`. It shows a `LOCK` line.
4. Release it in the SSM shell: `rm -f gateway-quarantine.json`. No restart needed.

Point to make: the agent kept pushing against its limits, and the gateway cut it off by itself. Two refusals in a row are fine; an allowed call in between starts the count again.
## Extended demo: from commit to accepted change

Only run this once the GitHub App has **Actions: Read-only** and **Pull requests: Read and write** (see `docs/gateway.md`), and your grant lists the tools `get_test_result`, `open_pull_request` and `get_pull_request`. Keep the eight-step demo above as the fallback.

The demo repo's test fails until `greeting.py` with `greet(name)` exists (issue #1).

| # | Prompt to Kiro | Expect |
|---|---|---|
| A | `Call get_issue with issue_number 1`, then `Call create_branch with branch agentledger/wf_001/greet` | Issue and branch |
| B | `Call commit_file on branch agentledger/wf_001/greet, path greeting.py, message "Add greet", content:` followed by a `greet(name)` that returns `Hello, <name>!` and raises `ValueError` for an empty name | A commit SHA |
| C | Wait about 30 seconds, then `Call get_test_result with the commit sha from step B` | `found: true`, `passed: true`, a run id. If `found` is false, wait and ask again. |
| D | `Call open_pull_request from branch agentledger/wf_001/greet with title "Add greet"` | A pull request number |
| E | **You** open the pull request on GitHub and merge it | Human acceptance |
| F | `Call get_pull_request with the number from step D` | `merged: true`, `merged_by` is you |

Then show the whole chain in the SSM shell:

```bash
.venv/bin/python scripts/work_chain.py
```

It prints the issue, branch, commit, test run and pull request, and says `VALIDATED` only for a passing run on that exact commit, and `ACCEPTED` only for a merged pull request whose head commit passed. Anything missing says `PENDING`.

To show a failing test, commit a wrong `greet` to a second branch and ask for its test result: `passed: false`, and the chain says `FAILED (failure)`.

Reset: delete the demo branches (`gh api -X DELETE repos/OumarouDG/agentledger-demo/git/refs/heads/<branch>`). If the pull request was merged, `greeting.py` is now on `main` and the test passes; reset `main` before the next run or use a new issue.

## After the demo

- Revoke the demo grant if you did not already: `agentledger grant revoke <grant id>`.
- Run `.\scripts\reset-demo.ps1` to clean the demo repo.
- Release any Sentinel lock: `rm -f gateway-quarantine.json` in the SSM shell.
- Delete the demo branch: `gh api -X DELETE repos/OumarouDG/agentledger-demo/git/refs/heads/agentledger/wf_001/demo`.

## If something goes wrong

| Symptom | Likely cause |
|---|---|
| `agentledger-ec2` not connected in Kiro | The tunnel is down. Run `.\scripts\launch-kiro.ps1` again (Kiro closed first). |
| Every call is 401 | Token expired (12 hours). Run the launch script again. |
| `denied: unknown_grant` | The grant id is wrong or not in DynamoDB. Check with `agentledger grant show <id>`. |
| `denied: grant_expired` | Grants last at most 4 hours. Make a new one and relaunch Kiro. |
| `denied: grant_store_unavailable` | The gateway cannot read DynamoDB. Check the instance role and `AGENTLEDGER_GRANT_STORE=dynamodb`. |
| `denied: audit_unavailable` | The gateway cannot write its audit file. Check the folder permissions on EC2. |
| `get_issue` says `github auth failed` | The GitHub App key secret or its permission on EC2 changed. |

## What not to claim

- Grants are in DynamoDB. The grant records are not signed and have no tamper-evident history.
- The gateway only controls tool calls that go through it. It cannot see a developer's local shell or files, and the demo repo cannot lock `main` on a free private plan.
- A valid agent token cannot be revoked early (12 hours). Grants are what get revoked.
- The audit file is a plain file on the server. It is not tamper-proof.
- The EC2 instance role is broad. Do not describe the setup as least-privilege.
