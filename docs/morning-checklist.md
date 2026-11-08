# Morning checklist

Do these in order. Each is one command or one look.

## 1. Check the laptop and AWS
- [ ] Laptop awake. Workshop AWS credentials still valid: `aws sts get-caller-identity`.
- [ ] Tunnel up: `.\scripts\start-tunnel.ps1`.

## 2. Check the repos
- [ ] `git fetch` then `git status` on `main`. Note open PRs: `gh pr list`.
- [ ] Demo repo `OumarouDG/agentledger-demo`: only `main`, no open PRs.
- [ ] Issue #1 has the acceptance criteria (greeting.py at root, `Hello, <name>!`, ValueError on empty).

## 3. Update EC2 (only if PR 19 or other gateway PRs were merged)
In the SSM shell, from `/home/ssm-user/Agent-Ledger`:
```
git pull
sudo systemctl restart agentledger-gateway
sudo systemctl status agentledger-gateway --no-pager
```

## 4. Reset state
```
rm -f gateway-quarantine.json
mv gateway-audit.jsonl gateway-audit.old.jsonl
```

## 5. Fresh grants (they last at most 4 hours)
- [ ] Josh creates grants right before rehearsal and again before judging.

## 6. Rehearse
- [ ] Full run with `docs/demo-timing.md`.
- [ ] Sentinel lock once, separately. Then `rm -f gateway-quarantine.json`.
- [ ] After each run: `.\scripts\reset-demo.ps1`.

## 7. Before judging
- [ ] Confirm the official deadline and submission steps.
- [ ] Read "What not to claim" in `docs/demo.md`.
