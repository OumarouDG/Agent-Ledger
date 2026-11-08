# CloudWatch and screen options

No CloudWatch dashboard and no Console exist yet. Nobody owns CloudWatch now. Do it only if the must-have items are done.

## What exists
- `scripts/audit_timeline.py`: text timeline from the audit file.
- `scripts/audit_report.py`: one static HTML page from the audit file. Labelled "not the Console".
- `scripts/work_chain.py`: the human to merged-change chain for one workflow.
- `infra/cloudwatch/`: agent config, Logs Insights queries, dashboard, IAM policy. Not yet run on EC2 or in AWS.

## The screen to show (safest first)
1. The static HTML report on the laptop.
2. The text timeline.
3. The CloudWatch dashboard, only if set up and checked.

Do not call any of these "the Console".

## Make the HTML report
```
python scripts/audit_report.py gateway-audit.jsonl audit-report.html --workflow wf_002
```
On EC2 the audit file is `/home/ssm-user/Agent-Ledger/gateway-audit.jsonl`. Copy it to the laptop
or run the script on EC2, then open the HTML file in a browser.

## CloudWatch (optional, about 15 minutes)
Follow `infra/cloudwatch/SETUP.md` top to bottom. Done when:
- [ ] `describe-log-streams` shows a stream in `/agentledger/gateway-audit`.
- [ ] Dashboard `AgentLedger` opens and the Timeline widget shows rows after a gateway call.

If it is not done by the freeze, cut it from the demo and say nothing about it.
Say "events are shipped to CloudWatch for viewing", never that CloudWatch enforces anything.
