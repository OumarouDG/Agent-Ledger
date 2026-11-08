# Try AgentLedger yourself

This page is for judges, ACM members and anyone curious. No AWS account, no keys, no GitHub login needed.

## What AgentLedger does

An AI agent gets only the power a person gave it. Every action it takes, and every one it is refused, goes on a record. You can read that record afterwards.

```
person -> signed token -> grant (what is allowed) -> gateway checks every call
       -> allowed: real GitHub change -> test on that exact commit -> person merges
       -> denied: refused and written down
```

## What you need

- Python 3 (we test on 3.14)
- Git

## Steps

1. Get the code.

```bash
git clone https://github.com/OumarouDG/Agent-Ledger.git
cd Agent-Ledger
```

2. Make a virtual environment and install.

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Mac or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Run the tests. They use no network.

```bash
python -m pytest -q
```

Expect many passes and some skips. The skips need live AWS. There should be no failures.

4. Print the sample record as text.

```bash
python scripts/ledger_report.py --synthetic
```

Expect a banner saying `SYNTHETIC SAMPLE: invented events, not from the gateway`. Then, per workflow, counts such as allowed and denied decisions, verified commits, and accepted deliverables.

5. Make the picture and open it.

```bash
python scripts/ledger_graph.py --synthetic --out sample-graph.html
```

Open `sample-graph.html` in your browser. It is one offline file. It needs no server.

## How to read the picture

- Green means a test passed on that exact commit, or a person accepted it. Being "allowed" alone is never green.
- Amber means the outcome is unknown.
- Red means the gateway refused the call. Nothing ran.
- "Merged" does not mean "approved". The page shows who merged.

## Be aware

- The sample is invented. It shows what the record looks like. It is not real agent work, and it is always labelled that way.
- The live demo (real GitHub changes, real AWS gateway, real human login) cannot be run from this page. It needs the team's AWS account and demo repo. Ask us for a live run or see the video.
- The record is a file. If someone rewrites the file, the check cannot know, unless the latest hash is saved somewhere else. This is a known limit.

## Where to look next

- `README.md`: the whole design
- `docs/gateway.md`: how each call is checked
- `docs/ledger.md`: how the record and graph are built
- `docs/judge-qa.md`: hard questions, answered honestly
