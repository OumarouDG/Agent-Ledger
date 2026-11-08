# CloudWatch setup (ops screen)

CloudWatch is a viewing screen. The audit file on the gateway stays the record.
Nothing here changes the gateway. Account 330608419289, region us-east-1.

Run the steps in order. Steps 1 and 4 are on your laptop. Steps 2 and 3 are in the EC2 SSM shell.

## 1. Allow the instance to write logs
The instance role (`kiro-rdp-UbuntuDesktopInstanceRole-azU1EzlqGW0w`) is already broad.
If it ever gets narrowed, attach `iam-policy.json` from this folder.

## 2. Install the agent (EC2)
apt does not have the package on this Ubuntu (it said `Unable to locate package`). Use the direct download:
```
cd /tmp
wget https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb
```
Done once on Nov 8: status `running`, stream `i-02d94a2f0bf2a72db` in `/agentledger/gateway-audit`, dashboard `AgentLedger` created.

## 3. Start it with our config (EC2)
```
cd /home/ssm-user/Agent-Ledger
sudo cp infra/cloudwatch/agent-config.json /opt/aws/amazon-cloudwatch-agent/etc/agent-config.json
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/agent-config.json -s
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a status
```
Status should say `running`.

## 4. Check logs arrive (laptop)
Make any gateway call, then:
```
aws logs describe-log-streams --log-group-name /agentledger/gateway-audit --region us-east-1
```

## 5. Make the dashboard (laptop)
```
aws cloudwatch put-dashboard --dashboard-name AgentLedger --dashboard-body file://infra/cloudwatch/dashboard.json --region us-east-1
```
Open it in the Console: CloudWatch, Dashboards, AgentLedger. Queries to paste are in `queries.md`.

## If it does not work
- No stream: `sudo tail /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log`
- File not read: the agent runs as root, so permissions are not the cause. Check the path in `agent-config.json`.
- Audit file moved (`mv gateway-audit.jsonl ...`): the gateway makes a new one, the agent follows it.
- Fallback: `scripts/audit_timeline.py` prints the same events from the file.

## Do not claim
- CloudWatch is not the tamper-proof ledger. It is a copy for viewing.
- Say "events are shipped to CloudWatch", not "CloudWatch enforces".
