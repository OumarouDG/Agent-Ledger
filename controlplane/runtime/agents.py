"""Lead, Coder and Tester steps for one workflow. Scripted orchestration.

The order of tool calls is fixed here. The model (llm_converse through the gateway) writes
Lead's plan text and Coder's file; nothing else it says is acted on. Model output is only
ever sent to commit_file as file content: it is never executed, and its file path must pass
`check_path` first. Tester has no model: its report is built in code from what GitHub
recorded for the exact commit.

Every call goes through one agent's own AgentSession (its own token, its own grant). A
denial stops the run (exit 1), as does a failed tool or unusable model output; a gateway we
cannot reach stops it with exit 2.
"""

from __future__ import annotations

import re
import statistics
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from controlplane.auth.agent_tokens import AwsCredentialsError
from controlplane.auth.jwt_verify import AuthError

from .gateway_client import AgentSession, Denied, GatewayError, GatewayUnavailable
from .workflow import CODER, LEAD, TESTER, Workflow, _open_default

POLL_INTERVAL_S = 10
POLL_TIMEOUT_S = 180
MAX_TITLE_CHARS = 200  # gateway.github.MAX_TITLE_CHARS
MAX_BODY_CHARS = 4_000  # gateway.github.MAX_BODY_CHARS
MAX_PLAN_CHARS = 1_500
_SHA = re.compile(r"^[0-9a-f]{40}$")

LEAD_SYSTEM = ("You lead a small coding team. Write a short plan, at most five lines, for "
               "resolving the GitHub issue. Plain text, no code.")
CODER_SYSTEM = (
    "You write exactly one source file that resolves a GitHub issue. Reply in exactly this "
    "format and nothing else:\n"
    "PATH: <repository-relative file path>\n"
    "```\n<the complete file content>\n```\n"
    "Do not write tests, CI configuration or files whose path starts with a dot. Keep the "
    "file short.")

_PATH_LINE = re.compile(r"^\s*PATH:\s*`?([^\s`]+)`?\s*$", re.M)
_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_PATH_CHARS = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$")


class RunStopped(Exception):
    """The run stopped early. `exit_code` is 1 for a denial or failure, 2 for no gateway.
    `result` holds what the run did before it stopped (set by run_agents)."""

    def __init__(self, message: str, exit_code: int = 1, *, agent: str | None = None,
                 tool: str | None = None, reason: str | None = None):
        super().__init__(message)
        self.exit_code = exit_code
        self.agent = agent
        self.tool = tool
        self.reason = reason
        self.result: RunResult | None = None


@dataclass(frozen=True)
class CallTiming:
    """Wall time of one gateway call as the runtime saw it: a new MCP session (initialize,
    then the call) through the tunnel, plus whatever the tool itself waits on."""
    agent: str
    tool: str
    ms: float
    outcome: str  # "allowed" | "denied" | "failed" | "unavailable"


# Called before each gateway call with (agent_id, tool, grant_id, what). May block (--step).
BeforeCall = Callable[[str, str, str | None, str], None]


class CoderOutputRejected(ValueError):
    """The model's reply cannot be committed as it is. Nothing was written."""


@dataclass(frozen=True)
class CiOutcome:
    verdict: str  # "passed" | "failed" | "not finished" | "no test run"
    conclusion: str | None = None
    status: str | None = None
    run_url: str | None = None
    attempts: int = 0

    @property
    def passed(self) -> bool:
        return self.verdict == "passed"


@dataclass
class RunResult:
    workflow_id: str
    run_id: str
    issue: int
    issue_title: str = ""
    plan: str = ""
    branch: str = ""
    path: str = ""
    commit_sha: str = ""
    pr_number: int | None = None
    pr_url: str = ""
    pr_state: str = ""
    pr_merged: bool = False
    test: CiOutcome | None = None
    report: str = ""
    calls: list[str] = field(default_factory=list)
    timings: list[CallTiming] = field(default_factory=list)


# --- model output -------------------------------------------------------------------------

def check_path(path: str) -> str:
    """Refuse paths a Coder must not write: hidden or CI files, tests, odd names.

    This is a runtime rule only. Coder's grant allows any path on its own branch, so the
    gateway would not stop these; they are refused here so a test result means something.
    """
    if not isinstance(path, str):
        raise CoderOutputRejected(f"file path {path!r} is not a plain repository-relative path")
    parts = path.split("/")
    if any(p.startswith(".") for p in parts) or (len(parts) > 1 and "" in parts[1:]):
        raise CoderOutputRejected(f"file path {path!r} has an empty or hidden part (e.g. .github)")
    if not _PATH_CHARS.match(path):
        raise CoderOutputRejected(f"file path {path!r} is not a plain repository-relative path")
    name = parts[-1]
    if any(p in ("test", "tests") for p in parts[:-1]) or name.startswith("test_") \
            or name.endswith("_test.py") or name == "conftest.py":
        raise CoderOutputRejected(f"file path {path!r} is a test file; Coder may not change tests")
    return path


def parse_coder_reply(reply: dict) -> tuple[str, str]:
    """(path, content) from Coder's model reply, or CoderOutputRejected."""
    if not isinstance(reply, dict) or not isinstance(reply.get("text"), str):
        raise CoderOutputRejected("model reply had no text")
    if reply.get("stop_reason") == "max_tokens":
        raise CoderOutputRejected("model reply was cut off at the grant's max_tokens")
    text = reply["text"]
    m_path, m_body = _PATH_LINE.search(text), _FENCE.search(text)
    if not m_path or not m_body:
        raise CoderOutputRejected("model reply is not in the PATH + fenced block format")
    content = m_body.group(1)
    if not content.strip():
        raise CoderOutputRejected("model reply has an empty file")
    if not content.endswith("\n"):
        content += "\n"
    return check_path(m_path.group(1)), content


# --- calls ----------------------------------------------------------------------------------

class _Caller:
    """Runs one gateway call for an agent, prints a line for it, maps errors to RunStopped."""

    def __init__(self, result: RunResult, out: Callable[[str], None] | None,
                 before_call: BeforeCall | None = None):
        self.result = result
        self.out = out
        self.before_call = before_call

    def _say(self, line: str) -> None:
        self.result.calls.append(line)
        if self.out is not None:
            self.out(line)

    def _timed(self, s: AgentSession, tool: str, started: float, outcome: str) -> str:
        ms = (time.perf_counter() - started) * 1000
        self.result.timings.append(CallTiming(s.agent_id, tool, ms, outcome))
        return f"{ms:6.0f} ms"

    def pause(self, s: AgentSession, tool: str, what: str) -> None:
        """Run before_call (the --step pause) without making a call."""
        if self.before_call is not None:
            self.before_call(s.agent_id, tool, s.grant_id, what)

    def __call__(self, s: AgentSession, tool: str, describe: Callable[[Any], str], *,
                 _pause: bool = True, **args):
        if _pause:
            self.pause(s, tool, describe_args(tool, args))
        head = f"  {s.agent_id:13} {tool:18} {s.grant_id or '(no grant)':22}"
        started = time.perf_counter()
        try:
            value = s.call(tool, **args)
        except Denied as e:
            self._say(f"{head} {self._timed(s, tool, started, 'denied')}  DENIED: {e.reason}")
            raise RunStopped(f"{s.agent_id} was denied {tool} on grant {s.grant_id}: {e.reason}",
                             1, agent=s.agent_id, tool=tool, reason=e.reason) from None
        except GatewayUnavailable as e:
            self._say(f"{head} {self._timed(s, tool, started, 'unavailable')}  GATEWAY UNAVAILABLE")
            raise RunStopped(str(e), 2, agent=s.agent_id, tool=tool) from None
        except GatewayError as e:
            self._say(f"{head} {self._timed(s, tool, started, 'failed')}  FAILED: {e}")
            raise RunStopped(str(e), 1, agent=s.agent_id, tool=tool) from None
        self._say(f"{head} {self._timed(s, tool, started, 'allowed')}  allowed  {describe(value)}")
        return value

    def fail(self, agent: str, what: str, why: str) -> RunStopped:
        self._say(f"  {agent:13} {what:18} {'':22} STOPPED: {why}")
        return RunStopped(f"{agent}: {why}", 1, agent=agent, tool=what)


def describe_args(tool: str, args: dict) -> str:
    """One line saying what a call will send. Prompts and file bodies are sized, not shown."""
    if tool == "llm_converse":
        chars = sum(len(str(m.get("content", ""))) for m in args.get("messages", []))
        return f"ask the model ({chars} chars of prompt)"
    if tool == "commit_file":
        size = len(str(args.get("content", "")).encode("utf-8"))
        return f"write {args.get('path')} ({size} bytes) on {args.get('branch')}"
    if tool == "open_pull_request":
        return f"open a PR from {args.get('branch')}: {args.get('title')}"
    return ", ".join(f"{k}={v}" for k, v in args.items()) or "(no arguments)"


def _percentile(sorted_ms: list[float], p: float) -> float:
    """Nearest-rank percentile of an already sorted list."""
    k = max(0, min(len(sorted_ms) - 1, int(round(p / 100 * len(sorted_ms) + 0.5)) - 1))
    return sorted_ms[k]


def latency_summary(timings: list[CallTiming]) -> list[str]:
    """Lines for the end summary: all calls, then per tool. Numbers only, no adjectives."""
    if not timings:
        return ["latency: no gateway calls"]
    ms = sorted(t.ms for t in timings)
    lines = [f"latency: {len(ms)} calls, median {statistics.median(ms):.0f} ms, "
             f"p95 {_percentile(ms, 95):.0f} ms, min {ms[0]:.0f} ms, max {ms[-1]:.0f} ms"]
    by_tool: dict[str, list[float]] = {}
    for t in timings:
        by_tool.setdefault(t.tool, []).append(t.ms)
    for tool, vals in by_tool.items():
        vals.sort()
        lines.append(f"  {tool:18} n={len(vals):<3} median {statistics.median(vals):6.0f} ms  "
                     f"max {vals[-1]:6.0f} ms")
    return lines


def _open(open_agent, agent_id: str, grant_id: str, workflow_id: str) -> AgentSession:
    try:
        return open_agent(agent_id, grant_id, workflow_id)
    except (GatewayError, AuthError, AwsCredentialsError) as e:
        raise RunStopped(f"could not open {agent_id}'s session: {e}", 1, agent=agent_id) from None


# --- the three agents -----------------------------------------------------------------------

def lead_step(flow: Workflow, call: _Caller) -> tuple[dict, str]:
    lead = flow.lead
    issue = call(lead, "get_issue", lambda r: f'issue #{r.get("number")} "{r.get("title")}"',
                 issue_number=flow.issue)
    ask = f"Issue #{issue.get('number')}: {issue.get('title')}\n\n{issue.get('body') or ''}"
    reply = call(lead, "llm_converse", lambda r: f"plan, {r.get('output_tokens')} tokens",
                 messages=[{"role": "user", "content": ask}], system=LEAD_SYSTEM)
    plan = (reply.get("text") or "").strip() or "(the model returned no plan text)"
    return issue, plan


def coder_step(flow: Workflow, coder: AgentSession, call: _Caller, issue: dict, plan: str,
               result: RunResult) -> None:
    ask = (f"Issue #{issue.get('number')}: {issue.get('title')}\n\n{issue.get('body') or ''}\n\n"
           f"Plan from the lead:\n{plan[:MAX_PLAN_CHARS]}")
    reply = call(coder, "llm_converse", lambda r: f"file draft, {r.get('output_tokens')} tokens",
                 messages=[{"role": "user", "content": ask}], system=CODER_SYSTEM)
    try:
        path, content = parse_coder_reply(reply)
    except CoderOutputRejected as e:
        raise call.fail(CODER, "parse model reply", str(e)) from None
    result.path = path

    title = f"Resolve #{flow.issue}: {issue.get('title') or 'issue'}"[:MAX_TITLE_CHARS]
    call(coder, "create_branch", lambda r: f"branch {r.get('branch')}", branch=flow.branch)
    result.branch = flow.branch
    commit = call(coder, "commit_file",
                  lambda r: f"{r.get('path')} commit {r.get('commit_sha')}",
                  branch=flow.branch, path=path, content=content, message=title)
    sha = commit.get("commit_sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not _SHA.match(sha):
        raise call.fail(CODER, "commit_file", f"reply had no full commit sha ({sha!r})")
    result.commit_sha = sha

    body = (f"Opened by {CODER} (grant {flow.coder.grant_id}) in workflow {flow.workflow_id}, "
            f"run {flow.run_id}, for issue #{flow.issue}. Delegated by {LEAD} "
            f"(grant {flow.root.grant_id}) on behalf of {flow.human_id}.\n\n"
            f"Plan (model output for {LEAD}):\n{plan[:MAX_PLAN_CHARS]}\n\n"
            "Scripted orchestration; model output written by llm_converse. "
            "A person must review and merge this.")[:MAX_BODY_CHARS]
    pr = call(coder, "open_pull_request", lambda r: f"PR #{r.get('number')} {r.get('url')}",
              branch=flow.branch, title=title, body=body)
    result.pr_number, result.pr_url = pr.get("number"), pr.get("url") or ""


def _outcome(r: Any, sha: str, attempts: int) -> CiOutcome | None:
    """A final outcome, or None for "not yet". Passed only if GitHub says completed + success."""
    if not isinstance(r, dict) or not r.get("found") or r.get("sha") != sha:
        return None
    status, conclusion = r.get("status"), r.get("conclusion")
    if status != "completed":
        return None
    passed = r.get("passed") is True and conclusion == "success"
    return CiOutcome("passed" if passed else "failed", conclusion, status, r.get("url"), attempts)


def _describe_test(r: Any) -> str:
    if not isinstance(r, dict) or not r.get("found"):
        return "found: false (no run yet)"
    return f"found: true, status {r.get('status')}, conclusion {r.get('conclusion')}"


def tester_step(flow: Workflow, tester: AgentSession, call: _Caller, result: RunResult, *,
                sleep: Callable[[float], None], interval_s: float, timeout_s: float) -> None:
    sha = result.commit_sha
    attempts = max(1, int(timeout_s // interval_s))
    outcome, last = None, None
    # One --step pause for the whole polling loop, not one per check.
    call.pause(tester, "get_test_result",
               f"check the test run for {sha[:12]} every {interval_s:.0f} s, "
               f"up to {attempts} times")
    for n in range(1, attempts + 1):
        sleep(interval_s)
        last = call(tester, "get_test_result", _describe_test, _pause=False, sha=sha)
        outcome = _outcome(last, sha, n)
        if outcome:
            break
    if outcome is None:  # timed out: never reported as passed
        found = isinstance(last, dict) and last.get("found") and last.get("sha") == sha
        outcome = (CiOutcome("not finished", last.get("conclusion"), last.get("status"),
                               last.get("url"), attempts) if found
                   else CiOutcome("no test run", attempts=attempts))
    result.test = outcome

    pr = call(tester, "get_pull_request",
              lambda r: f"PR #{r.get('number')} {r.get('state')}, merged {r.get('merged')}",
              number=result.pr_number)
    result.pr_state, result.pr_merged = pr.get("state") or "", bool(pr.get("merged"))
    head = pr.get("head_sha")
    result.report = tester_report(result, head_matches=(head == sha))


def tester_report(result: RunResult, *, head_matches: bool) -> str:
    """Tester's report, built in code from GitHub's records. No model is involved."""
    t = result.test
    short = result.commit_sha[:12]
    if t is None or t.verdict == "no test run":
        test = f"no test run found for {short} after {t.attempts if t else 0} checks"
    elif t.verdict == "not finished":
        test = f"test run for {short} not finished ({t.status}) after {t.attempts} checks"
    elif t.passed:
        test = f"tests passed for {short} ({t.run_url})"
    else:
        test = f"tests FAILED for {short}: {t.conclusion} ({t.run_url})"
    pr = f"PR #{result.pr_number} is {result.pr_state}, {'merged' if result.pr_merged else 'not merged'}"
    if not head_matches:
        pr += "; its head commit is NOT the tested commit"
    return f"{test}. {pr}."


def run_agents(flow: Workflow, *, open_agent=_open_default, out: Callable[[str], None] | None = print,
               sleep: Callable[[float], None] = time.sleep, poll_interval_s: float = POLL_INTERVAL_S,
               poll_timeout_s: float = POLL_TIMEOUT_S,
               before_call: BeforeCall | None = None) -> RunResult:
    """Lead, then Coder, then Tester. Raises RunStopped at the first denial or failure; the
    exception carries the partial result. `before_call` runs before every gateway call."""
    result = RunResult(flow.workflow_id, flow.run_id, flow.issue)
    call = _Caller(result, out, before_call)
    try:
        issue, plan = lead_step(flow, call)
        result.issue_title, result.plan = issue.get("title") or "", plan

        coder = _open(open_agent, CODER, flow.coder.grant_id, flow.workflow_id)
        coder_step(flow, coder, call, issue, plan, result)

        tester = _open(open_agent, TESTER, flow.tester.grant_id, flow.workflow_id)
        tester_step(flow, tester, call, result, sleep=sleep, interval_s=poll_interval_s,
                    timeout_s=poll_timeout_s)
    except RunStopped as e:
        e.result = result
        raise
    if out is not None:
        out(f"  {TESTER} report: {result.report}")
    return result
