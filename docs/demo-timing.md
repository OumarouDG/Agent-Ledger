# Five-minute demo plan

Total: 5:00. Say one idea per slide. Never claim more than the audit shows.

| Time | Who | What | Proof on screen |
|------|-----|------|-----------------|
| 0:00-0:20 | Anyone | The problem: agents act with no clear owner. | One sentence, no slide |
| 0:20-1:00 | Kiro (single agent) | whoami, then get_issue #1 | Agent id from the token |
| 1:00-1:30 | Kiro | Try `main`: denied. Try a model not in the grant: denied. | `denied: branch_not_permitted` |
| 1:30-2:20 | Kiro | Branch, commit, test on exact SHA, PR | Commit SHA, test run id |
| 2:20-3:20 | Josh runtime | `agentledger run --issue N`: Lead, Coder, Tester | PR opened in about 30 s |
| 3:20-3:50 | Josh runtime | Revoke mid-run, then Rogue probe | `denied: grant_revoked`, lock |
| 3:50-4:30 | Oumarou | `work_chain.py`: VALIDATED, ACCEPTED | Human merge, tests passed |
| 4:30-5:00 | Benson / Oumarou | CloudWatch screen, one sentence close | Same events as the audit |

## Rules
- A person merges the PR. The agent never does.
- Say "accepted" only when `work_chain.py` prints ACCEPTED.
- CloudWatch is the ops screen. The audit file is the record.
- If a step fails, say so, then jump to the next row. Do not retry live twice.

## Cut order if time runs short
1. Drop the model denial in 1:00-1:30.
2. Drop the Rogue probe.
3. Keep: grant, allowed change, test on SHA, human merge, timeline.
