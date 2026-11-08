# Ledger: provenance and lineage

Status: feature branch `feature/ledger-lineage-sprint`. Not merged. Not deployed. The gateway,
the audit writer, EC2, DynamoDB and CloudWatch are untouched. Everything here reads the audit
file and writes nothing to it.

Safe baseline: tag `demo-safe-2026-11-08` (`ed657a9`).

## What it does

It turns audit events into a graph and answers questions about it.

| Question | Command |
| --- | --- |
| What is the chain behind each pull request? | `python scripts/ledger_report.py gateway-audit.jsonl` |
| What was this commit built on? | `... --trace artifact:owner/repo:<sha>` |
| If this artifact has a defect, what depends on it? | `... --regression artifact:owner/repo:<sha>` |
| Which events back each number? | `... --ids` |
| Machine-readable output | `... --json` |
| Has the audit file been changed since it was sealed? | `python scripts/ledger_verify.py verify audit.jsonl sealed.jsonl` |
| Copy the audit from CloudWatch to this laptop | `python scripts/pull_audit_from_cloudwatch.py audit.jsonl` |

Package: `ledger/` (`build`, `models`, `evidence`, `lineage`, `chain`, `metrics`, `impact`,
`hashchain`, `sample`). Tests: `tests/ledger/` (50 tests, no AWS needed).

## What is real and what is not

| Thing | Status |
| --- | --- |
| Graph from real audit events: human, grant, agent, activity, commit, CI run, PR | Real. Same rules as `scripts/work_chain.py`; a test checks they agree. |
| Evidence chain for one accepted PR | Real, if the audit file holds it. Each link shows its evidence level and event id. |
| Cross-workflow dependency | Needs a declaration. None exists in the real audit yet. |
| `--synthetic` sample (commits A, B, C) | Invented. Every output is labelled `SYNTHETIC SAMPLE`. |
| Reuse credits | A count of accepted deliverables built on an artifact. Not a share of value. |
| Hash chain | Proof of concept. Not on the live path. See limits. |

## How a dependency becomes "confirmed"

Someone declares `B was built on A` (a JSON file for `--declarations`). The edge is confirmed
only if A was itself seen with GitHub evidence in the audit. Otherwise it stays a candidate:
listed, never followed, never counted. The ledger never guesses a dependency from timing.

Evidence levels: verified (the gateway saw it), external (GitHub confirmed it), reported (an
agent or person said so), inferred (computed, with the assumption stated).

## Metrics

Each metric shows its numerator, denominator, evidence level and the event ids behind it.
One call is counted once, even though it has a decision line, an outcome line and a usage line.
A call with no outcome is UNKNOWN, not succeeded. Token counts are not dollars.
Not computed: first-pass CI success, cost per verified outcome, any value score.
These are workflow performance numbers. They do not rank people or agents.

## Known gaps

- **Missing outcome after a real action.** The gateway writes the outcome line after the GitHub
  or Bedrock call. If that write fails, the action happened but has no outcome record. The
  ledger shows such a call as UNKNOWN. The gateway itself is unchanged, so the gap remains.
- **The hash chain proves nothing about the past.** Sealing today does not show the events were
  honest before today. Someone who can rewrite both the audit file and the sealed file can make
  them agree. Only a head hash stored where they cannot write (for example S3 Object Lock)
  catches that. That part is not built.
- **No persistence.** The graph is rebuilt from the audit file each time. There is no graph store.
- **One real workflow.** The real audit has no cross-workflow dependency. Do not present the
  synthetic sample as a real reuse record.

## If this is not ready

Leave the branch alone and use the baseline. Nothing in the demo depends on it.
