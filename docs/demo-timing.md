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
