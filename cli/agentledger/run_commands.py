"""`agentledger run --issue N`: Lead, Coder and Tester turn an issue into a pull request.

Scripted orchestration: the order of calls is fixed in code; llm_converse writes the plan
and the file. Every call goes through the gateway as one agent, under its own grant.

Exit codes: 0 tests passed; 1 denied or failed (including a refused grant or a stopped
step); 2 gateway unreachable; 3 tests failed, did not finish, or no test run was found.
Click's own usage errors (a missing --issue, a bad --workflow) also exit 2, before anything
is written.
"""

from __future__ import annotations

import time

import click

EXIT_PASSED, EXIT_FAILED, EXIT_UNREACHABLE, EXIT_TESTS = 0, 1, 2, 3
HONEST_LINE = "scripted orchestration; model output written by llm_converse"


def _open_agent():
    """open_agent for the runtime. Tests replace this."""
    from controlplane.runtime.workflow import _open_default

    return _open_default


def _sleep(seconds: float) -> None:
    """Pause between test-result checks. Tests replace this."""
    time.sleep(seconds)


def _wait(prompt: str) -> str:
    """Block until Enter for --step. Raises EOFError if stdin closes. Tests replace this."""
    return input(prompt)


def _step_hook(echo):
    """before_call for --step: say what is next, wait for Enter. Ctrl+C or closed input stops
    the run (exit 1) before that call is sent."""
    from controlplane.runtime.agents import RunStopped

    def before_call(agent_id: str, tool: str, grant_id: str | None, what: str) -> None:
        echo(f"\n[step] next: {agent_id} calls {tool} on grant {grant_id}: {what}")
        try:
            _wait("[step] press Enter to send it (Ctrl+C to stop) ")
        except (EOFError, KeyboardInterrupt):
            raise RunStopped(f"stopped at --step before {agent_id} sent {tool}", EXIT_FAILED,
                             agent=agent_id, tool=tool) from None
    return before_call


def _state(g, now: float) -> str:
    if g is None:
        return "missing"
    if g.status != "active":
        return g.status
    if g.expires_at is not None and g.expires_at <= now:
        return "expired"
    return "active"


def grant_status_line(flow, store, now: float | None = None) -> str:
    """What the grants are now, read back from the store (consistent reads), not assumed."""
    from datetime import datetime

    now = time.time() if now is None else now
    try:
        states = [_state(store.get(g.grant_id), now) for g in flow.grants]
    except Exception as e:  # noqa: BLE001 - any store failure: say so, never guess "active"
        return (f"status unknown ({type(e).__name__}); check with: "
                f"agentledger grant show {flow.root.grant_id}")
    root, coder, tester = states
    if root != "active":
        return (f"root {root}: the gateway denies all three grants "
                f"(lead {root}, coder {coder}, tester {tester}; children are denied through the root)")
    if coder == tester == "active":
        until = datetime.fromtimestamp(flow.root.expires_at).astimezone().strftime("%H:%M")
        return (f"active until {until}; revoke all with: "
                f"agentledger grant revoke {flow.root.grant_id}")
    return f"lead active, coder {coder}, tester {tester}"


def _summary(flow, result, verdict: str, exit_code: int, status: str) -> list[str]:
    from controlplane.runtime.agents import latency_summary

    lines = ["", "Summary",
             f"  workflow {flow.workflow_id}  run {flow.run_id}  issue #{flow.issue}  "
             f"repo {flow.repository}",
             f"  grants   lead {flow.root.grant_id}  coder {flow.coder.grant_id}  "
             f"tester {flow.tester.grant_id}",
             f"           {status}"]
    if result is not None:
        lines.append(f"  branch   {result.branch or '(none)'}")
        lines.append(f"  commit   {result.commit_sha or '(none)'}")
        lines.append(f"  PR       {result.pr_url or '(none)'}")
        lines.append(f"  tests    {verdict}")
        if result.report:
            lines.append(f"  tester   {result.report}")
        lines += ["  " + x for x in latency_summary(result.timings)]
    else:
        lines.append(f"  tests    {verdict}")
    lines += [f"  {HONEST_LINE}", f"  exit {exit_code}"]
    return lines


def _verdict(result) -> tuple[str, int]:
    t = result.test
    if t is None:
        return "no test run", EXIT_TESTS
    if t.passed and result.pr_head_sha != result.commit_sha:
        return (f"PR head {(result.pr_head_sha or 'unknown')[:12]} is not the tested commit "
                f"{result.commit_sha[:12]} (only that commit passed)"), EXIT_TESTS
    if t.passed:
        return f"passed ({t.run_url})", EXIT_PASSED
    if t.verdict == "failed":
        return f"FAILED: {t.conclusion} ({t.run_url})", EXIT_TESTS
    if t.verdict == "not finished":
        return f"not finished ({t.status}) after {t.attempts} checks", EXIT_TESTS
    return f"no test run found after {t.attempts} checks", EXIT_TESTS


@click.command(help="Turn a GitHub issue into a pull request with Lead, Coder and Tester agents, "
                    "every call through the gateway. Exit 0 tests passed, 1 denied or failed, "
                    "2 gateway unreachable, 3 tests failed or no test run.")
@click.option("--issue", type=int, required=True, help="Issue number in the repository.")
@click.option("--repo", "repository", default="OumarouDG/agentledger-demo", show_default=True,
              help="Repository owner/name the grants are scoped to.")
@click.option("--workflow", "workflow_id", default=None,
              help="Workflow ID (default: a new wf_<random>). wf_001 is reserved for the Kiro demo.")
@click.option("--step", is_flag=True, help="Pause before every gateway call until Enter.")
def run(issue: int, repository: str, workflow_id: str | None, step: bool) -> None:
    from controlplane.auth.agent_tokens import AwsCredentialsError
    from controlplane.auth.jwt_verify import AuthError
    from controlplane.grants.errors import GrantRefused, GrantStoreError
    from controlplane.runtime import agents, workflow

    from . import grant_commands

    try:
        if workflow_id is not None:
            workflow.check_workflow_id(workflow_id)
        workflow._check_issue(issue)
    except workflow.WorkflowError as e:
        raise click.BadParameter(str(e)) from None

    human = grant_commands._signed_in()
    open_agent = _open_agent()
    store = grant_commands._store()
    try:
        flow = workflow.start_workflow(human, issue, repository, store=store,
                                       workflow_id=workflow_id, open_agent=open_agent,
                                       out=click.echo)
    except GrantRefused as e:
        raise click.ClickException(f"Refused: {e}") from None
    except (GrantStoreError, AwsCredentialsError) as e:
        raise click.ClickException(str(e)) from None
    except agents.GatewayError as e:  # Lead's session could not be opened
        raise click.ClickException(str(e)) from None
    except AuthError as e:  # Lead's token failed local verification
        raise click.ClickException(f"agent_lead's token was refused ({e.reason}); "
                                   "nothing was run and the grants were revoked") from None

    if step:
        click.echo(f"\n[step] to revoke mid-run, in another terminal: "
                   f"agentledger grant revoke {flow.root.grant_id}")
    click.echo(f"\n  {'AGENT':13} {'TOOL':18} {'GRANT':22} {'TIME':>9}  RESULT")
    result, code, verdict, finished = None, EXIT_FAILED, "not reached", False
    try:
        result = agents.run_agents(flow, open_agent=open_agent, out=click.echo, sleep=_sleep,
                                   before_call=_step_hook(click.echo) if step else None)
        verdict, code = _verdict(result)
        finished = True
    except agents.RunStopped as e:
        result, code = e.result, e.exit_code
        click.echo(f"\nRun stopped: {e}")
    except KeyboardInterrupt:
        click.echo("\nRun interrupted.")
    finally:
        # A finished run (tests passed or not) keeps its grants for review and the probe.
        # Anything else (denial, no gateway, Ctrl+C, a crash) revokes the root, which the
        # gateway applies to both children at their next call. A crash still propagates.
        if not finished:
            click.echo(_revoke_root(flow, store, human))
    for line in _summary(flow, result, verdict, code, grant_status_line(flow, store)):
        click.echo(line)
    raise SystemExit(code)


def _revoke_root(flow, store, human) -> str:
    from controlplane.grants.service import revoke_grant

    gid = flow.root.grant_id
    try:
        r = revoke_grant(gid, store=store, human=human)
    except Exception as e:  # noqa: BLE001 - say so; never claim it was revoked
        return (f"WARNING: could not revoke root {gid} ({type(e).__name__}); "
                f"revoke it now with: agentledger grant revoke {gid}")
    if r.already_revoked:
        return f"root {gid} was already revoked"
    return f"revoked root {gid} because the run did not finish (its children are denied with it)"


@click.command(help="Run agent_rogue against a live workflow. Every attack must be refused with "
                    "its expected reason. Exit 0 all refused, 1 anything allowed, a wrong reason "
                    "or the probe could not run, 2 gateway unreachable.")
@click.option("--workflow", "workflow_id", required=True,
              help="A workflow with an active run (agentledger run --workflow ...).")
@click.option("--issue", type=int, default=1, show_default=True,
              help="Issue Rogue may read on its own grant (the baseline and Sentinel check).")
@click.option("--until-locked", is_flag=True,
              help="Keep violating on Rogue's own grant until the Sentinel locks it, then show "
                   "an allowed tool is denied too.")
def probe(workflow_id: str, issue: int, until_locked: bool) -> None:
    from controlplane.auth.agent_tokens import AwsCredentialsError
    from controlplane.auth.jwt_verify import AuthError
    from controlplane.grants.errors import GrantStoreError
    from controlplane.runtime import probe as rogue
    from controlplane.runtime import workflow
    from controlplane.runtime.gateway_client import GatewayError, GatewayUnavailable

    from . import grant_commands

    try:
        workflow.check_workflow_id(workflow_id)
    except workflow.WorkflowError as e:
        raise click.BadParameter(str(e), param_hint="--workflow") from None
    human = grant_commands._signed_in()
    try:
        result = rogue.run_probe(human, workflow_id, store=grant_commands._store(),
                                 open_agent=_open_agent(), issue=issue,
                                 until_locked=until_locked, out=click.echo)
    except GatewayUnavailable as e:
        click.echo(f"\nProbe stopped: {e}")
        click.echo("  exit 2")
        raise SystemExit(EXIT_UNREACHABLE) from None
    except (rogue.ProbeError, GrantStoreError, AwsCredentialsError, GatewayError) as e:
        raise click.ClickException(str(e)) from None
    except AuthError as e:
        raise click.ClickException(f"{rogue.ROGUE}'s token was refused ({e.reason})") from None

    attacks = [a for a in result.attempts if a.expected != rogue.ALLOWED]
    baseline_ok = all(a.ok for a in result.attempts if a.expected == rogue.ALLOWED)
    code = EXIT_PASSED if result.ok else EXIT_FAILED
    click.echo(f"\n  {sum(a.ok for a in attacks)}/{len(attacks)} refused with the expected "
               f"reason; baseline {'ok' if baseline_ok else 'FAILED'}")
    click.echo(f"  exit {code}")
    raise SystemExit(code)
