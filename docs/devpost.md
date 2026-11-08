# AgentLedger: Devpost text

## Tagline
Every agent action, tied to a human who allowed it.

## Inspiration
AI agents can now open branches, commit code and call models. But when one does, nobody can say who allowed it, what it was allowed to touch, or how to stop it halfway. We wanted a clear owner and a clear limit for every agent action.

## What it does
AgentLedger gives each agent a verified identity and a time-limited grant from a signed-in human. Every tool call goes through a gateway. The gateway checks the agent's token, the grant, the workflow and the resource on each call. Any doubt is a denial.

- A human creates a grant in DynamoDB: which agent, which tools, which repository and branch prefix, which models, and when it expires (4 hours at most).
- A Lead agent can pass a smaller grant to a Coder and a Tester. A rogue agent cannot delegate from a grant it does not hold.
- Revoke the root grant and the next call by its children is denied (`parent_grant_revoked`).
- Every decision is written to an audit trail before the action runs. If the record cannot be written, the call is denied.
- A Sentinel locks a grant that keeps breaking its limits.
- A run ends with a chain you can check: human, token, grant, commit SHA, passing test on that exact SHA, and a pull request merged by a person.

## How we built it
- Identity: Amazon Cognito, one app client per agent, and a CLI for human sign-in.
- Gateway: a FastMCP server on EC2, reached through an SSM tunnel.
- Grants: DynamoDB, written by a grant service with roles and limits.
- Actions: a GitHub App (the agents never hold a credential) and Amazon Bedrock for model calls.
- Runtime: `agentledger run` turns an issue into a pull request with three agents. `agentledger probe` attacks it with a fourth.
- Audit: JSON lines per decision and outcome, with a timeline, a chain report and a static HTML report.
- Kiro runs as a single agent through the same gateway, on its own workflow.

## Challenges
- Telling "allowed" from "succeeded". We write the decision and the outcome as separate lines.
- Making every failure a denial: an unreadable store, an unwritable audit file or an unreadable lock file all stop the call.
- Keeping child grants from growing: a child that leaves out a limit now inherits the parent's, not a wider default.
- Proving the code works from outside the agent: the test result comes from GitHub for the exact commit.

## Accomplishments
- A run goes from issue to pull request with passing CI in about 30 seconds.
- A revoke is applied to the next call: 165 ms measured.
- The probe is refused 7 out of 7, including the Sentinel lock.
- 974 tests pass with the live checks on (one run).

## What we learned
Agent safety is mostly boring: check every call, write the record first, and fail closed. A clear grant is easier to explain than a clever policy.

## What's next
Signed, tamper-evident audit records. A grant store with a Sentinel status instead of a local lock file. Narrower AWS roles. A live Console view.

## Limits (we say these out loud)
- The gateway only controls calls that go through it. It cannot see a developer's local shell.
- Agent tokens last 12 hours and cannot be revoked early. Grants are what get revoked.
- The audit file is a plain file. It is not tamper-proof.
- The EC2 role is broad. This is not a least-privilege setup.
- A person merges every pull request. The agents have no merge tool.

## Built with
Amazon Cognito, DynamoDB, EC2, Systems Manager, Secrets Manager, Amazon Bedrock, FastMCP, GitHub Apps and Actions, Python, Kiro.
