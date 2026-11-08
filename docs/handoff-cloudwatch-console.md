# Handoff: CloudWatch and Console

Two jobs are not done yet. This page says what exists and what a person must do.

## CloudWatch (Benson)
Ready in `infra/cloudwatch/`: agent config, Logs Insights queries, dashboard, IAM policy.
Not yet run on EC2 or in AWS.

Steps: follow `infra/cloudwatch/SETUP.md` top to bottom (about 15 minutes).
Done when:
- [ ] `describe-log-streams` shows a stream in `/agentledger/gateway-audit`.
- [ ] Dashboard `AgentLedger` opens and the Timeline widget shows rows after a gateway call.
- [ ] Denial and Sentinel widgets fill after the Rogue probe.

Say in the demo: "events are shipped to CloudWatch for viewing". Do not say CloudWatch enforces anything.

## Console (unassigned, taken by Oumarou)
No Console exists yet. What we have instead:
- `scripts/audit_timeline.py`: text timeline.
- `scripts/audit_report.py`: one static HTML page from the audit file. Labelled "not the Console".
- `scripts/work_chain.py`: the human to merged-change chain for one workflow.

Pick one before judging:
1. Show the CloudWatch dashboard as the screen.
2. Show the static HTML report on the laptop.
3. Build a small live page. Only if time is left after rehearsal.

Do not call options 1 or 2 "the Console" unless the team agrees on the name.

## Make the HTML report
```
python scripts/audit_report.py gateway-audit.jsonl audit-report.html --workflow wf_001
```
On EC2 the audit file is `/home/ssm-user/Agent-Ledger/gateway-audit.jsonl`. Copy it to the laptop
or run the script on EC2, then open the HTML file in a browser.
