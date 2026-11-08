# Logs Insights queries

Log group: `/agentledger/gateway-audit`. Each line is one audit event (JSON), so fields are
found by name. Set the time range to "Last 1 hour" or the demo window.

## Live timeline (one workflow)
```
fields @timestamp, event, tool, decision, reason, status, agent_id, grant_id
| filter workflow_id = "wf_001"
| sort @timestamp asc
| limit 200
```

## Denials and why
```
fields @timestamp, agent_id, tool, reason, grant_id
| filter event = "decision" and decision = "deny"
| sort @timestamp desc
| limit 100
```

## Denials by reason
```
filter event = "decision" and decision = "deny"
| stats count(*) as n by reason
| sort n desc
```

## Sentinel locks
```
fields @timestamp, grant_id, agent_id, reason
| filter event = "sentinel"
| sort @timestamp desc
```

## Real changes that succeeded
```
fields @timestamp, tool, artifact.kind, artifact.sha, artifact.number, grant_id
| filter event = "outcome" and status = "succeeded"
| sort @timestamp asc
```

## Failed actions
```
fields @timestamp, tool, error, grant_id
| filter event = "outcome" and status = "failed"
| sort @timestamp desc
```

## Model usage
```
filter event = "usage"
| stats sum(resource.input_tokens) as input, sum(resource.output_tokens) as output by agent_id
```

## Calls per agent and tool
```
filter event = "decision"
| stats count(*) as calls by agent_id, tool, decision
```
