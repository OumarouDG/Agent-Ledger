# Likely judge questions

Short, true answers. If a fact is not here, check the code or say "not built yet".

**What is AgentLedger?**
A gateway between agents and real tools. An agent needs a verified identity and an active grant for each action. Every decision is written to an audit trail.

**How does an agent prove who it is?**
A Cognito token. The gateway checks it on every request and maps it to an agent id.

**What is a grant?**
A record that says which agent, which workflow, which tools, which repo and branch prefix, which models, and until when. A human owner is on it. It lasts at most 4 hours.

**What stops an agent from touching `main`?**
The grant's branch prefix. Branches outside it are denied: `branch_not_permitted`. The agent also cannot choose the repository.

**What happens when you revoke?**
The next call is denied: `grant_revoked`. Child grants die with the parent.

**What if the agent keeps trying forbidden things?**
Sentinel locks the grant after 3 violations in a row. A stranger's bad calls never count against someone else's grant.

**What if the audit log is down?**
The call is denied. No record, no action.

**Can the agent merge its own PR?**
No. The gateway has no merge tool. A person merges. The chain reads back who merged it.

**How do you know the code works?**
`get_test_result` reads the GitHub Actions run for the exact commit SHA. Not the agent's word.

**Does the agent get AWS or GitHub keys?**
No. The gateway holds the GitHub App key (Secrets Manager) and uses its own role for Bedrock.

**Where are grants stored?**
DynamoDB, table `agentledger-grants`.

**Is CloudWatch the ledger?**
No. CloudWatch is a viewing copy. The audit file is the record.

**What is not built?**
Be honest. Examples: grants are not stored with a signed history. The Sentinel lock is gateway-local. A live Console is not built if we only show the report or dashboard.

## Do not claim
- "Tamper-proof" or "immutable" audit.
- That CloudWatch enforces policy.
- That the agent was reviewed or approved if `approved_by` is empty. Say "merged by a person".
- Anything the timeline does not show.
