# Five-minute demo plan

Total: 5:00. Say one idea per slide. Never claim more than the audit shows.

Setup: fresh grants made within the last 4 hours, tunnel up, demo repo reset (`scripts/reset-demo.ps1`).
Kiro runs on workflow `wf_001`. The runtime runs on `wf_002`.

| Time | Who | What | Proof on screen |
|------|-----|------|-----------------|
| 0:00-0:20 | Anyone | The problem: agents act with no clear owner. | One sentence, no slide |
| 0:20-1:00 | Kiro (single agent) | whoami, then get_issue #1 | Agent id from the token |
| 1:00-1:30 | Kiro | Try `main`: denied. | `denied: branch_not_permitted` |
| 1:30-2:20 | Kiro | Branch, commit, test on exact SHA, PR | Commit SHA, test run id |
| 2:20-3:20 | Runtime | `agentledger run --issue 1 --workflow wf_002 --step`: Lead, Coder, Tester. At the Coder prompt, revoke the root grant in a second terminal. | `denied: parent_grant_revoked` on Coder's next call |
| 3:20-3:50 | Runtime | `agentledger probe --workflow wf_002` | Every attack refused, with its reason |
| 3:50-4:30 | Presenter | `work_chain.py --workflow wf_001`: VALIDATED, ACCEPTED | Human merge, tests passed |
| 4:30-5:00 | Presenter | Show the audit report and close in one sentence | Same events as the audit file |

## Found in the rehearsal (Nov 8)
- Measured: Kiro part 2:00, all steps worked. Revoke denied in 203 ms. Probe refused 4 of 4.
- **Reset the demo repo between the Kiro part and the runtime part.** The Kiro part merges
  `greeting.py` into `main`. Without a reset the runtime's pull request has nothing to change.
  Run `.\scripts\reset-demo.ps1` in the gap (it takes a few seconds).
- **Revoke at Coder's first prompt**, before `create_branch`, not at the end. Press Enter through
  Lead's two calls, then revoke. Copy the root grant id from the line the run prints at the start.
- **Do not refresh PATH with `$env:Path = ...` without re-activating the venv.** It removes the
  venv from the PATH and `agentledger` disappears. After that line run `.\.venv\Scripts\Activate.ps1`.
- Alice's sign-in lasts about 1 hour. Run `agentledger login` shortly before presenting, and finish
  the browser sign-in within 120 seconds with the terminal untouched.
- Grants last at most 4 hours. Make the Kiro grant right before presenting.
- Start the tunnel in its own terminal with the AWS keys pasted. Every terminal needs its own keys.
- On EC2, before presenting: `rm -f gateway-quarantine.json` and
  `mv gateway-audit.jsonl gateway-audit.old.jsonl` for a clean timeline.

## Rules
- A person merges the PR. The agent never does.
- Say "accepted" only when `work_chain.py` prints ACCEPTED.
- The audit file is the record. A CloudWatch dashboard, if set up, is a viewing copy.
- If a step fails, say so, then jump to the next row. Do not retry live twice.
- If both people share one laptop, start the second tunnel with `-LocalPort 18001`.

## Cut order if time runs short
1. Drop the probe.
2. Drop the mid-run revoke and let the run finish.
3. Keep: grant, allowed change, test on SHA, human merge, timeline.
