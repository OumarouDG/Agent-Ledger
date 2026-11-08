# Pitch script (5 minutes)

Two speakers: **A** runs Kiro and the audit. **B** runs the runtime. Swap names as you like.
Say each line in your own words. The facts must stay true. Times match `demo-timing.md`.

## 0:00 Problem (A, 20 s)
"AI agents can now change real systems. When one does, nobody can say who allowed it, what it was allowed to touch, or how to stop it halfway. AgentLedger fixes that."

## 0:20 One agent, in Kiro (A, 40 s)
Say: "This is Kiro, acting as an agent. The gateway knows who it is from a signed token, not from what it says."
Do: `agentledger_whoami`, then `get_issue` 1.
Say: "It read the issue. It did not choose the repository, and it never held a GitHub key. The grant named the repo."

## 1:00 The limit holds (A, 30 s)
Do: `create_branch` on `main`.
Say: "Denied. The grant only allows branches under its own prefix."

## 1:30 A real change, checked (A, 50 s)
Do: create the branch, commit `greeting.py`, `get_test_result` for that commit, `open_pull_request`.
Say: "The test result comes from GitHub for this exact commit. Not from the agent's word. A person merges the pull request. The agent has no merge tool."

## 2:20 Three agents, one workflow (B, 60 s)
Do: `.\scripts\run-demo.ps1 -Workflow wf_002`. At the Coder prompt, revoke the root grant in a second terminal.
Say: "Lead plans. It hands smaller grants to Coder and Tester. Now a human revokes the root grant." (Press Enter.) "Coder's next call is denied: `parent_grant_revoked`. It took 165 milliseconds in our test."

## 3:20 A rogue agent (B, 30 s)
Do: `.\scripts\run-demo.ps1 -Workflow wf_002 -Probe`
Say: "Rogue tries four attacks: another agent's grant, no grant, delegating from a grant it does not hold, and a branch it may not write. Every one is refused, with its reason."

## 3:50 The record (A, 40 s)
Do: `python scripts/work_chain.py --workflow wf_001`, then open the audit report or the CloudWatch dashboard.
Say: "Human, agent, grant, commit, passing test, merged pull request. One chain. Every allowed and denied call is on the record, written before the action ran. If the record can't be written, the call is denied."

## 4:30 Close (B, 30 s)
Say: "Events are shipped to CloudWatch for viewing. The gateway only controls calls that go through it, and the audit file is not tamper-proof. We say that out loud. Every agent action has an owner, a limit, and a record. Thank you."

## If a step fails
Say "that one failed, here is what the record shows". Move to the next row. Do not retry twice.

## Never say
- "Tamper-proof", "immutable", "least privilege", "Console".
- That CloudWatch enforces anything.
- That the agent was approved, if `approved_by` is empty. Say "merged by a person".
