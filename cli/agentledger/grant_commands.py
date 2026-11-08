"""`agentledger grant create / revoke / list / show`. Needs a signed-in human.

`human_id` always comes from the verified session (`current_session()`); there is no flag
for it. Grants are written to the DynamoDB table (`AGENTLEDGER_GRANTS_TABLE` overrides the
name). Exit codes match the other commands: 0 done, 1 refused or failed, 2 bad usage.
"""

from __future__ import annotations

import os
import re
import time

import click

_TTL = re.compile(r"^(\d+)([smh])$")
_UNIT = {"s": 1, "m": 60, "h": 3600}


def _session():
    """Verified human session. Tests replace commands._context to fake it."""
    from . import commands, session

    cfg, store, verifier = commands._context()
    return session.current_session(cfg=cfg, store=store, verifier=verifier)


def _store():
    """Grant store the CLI writes to. Tests replace this."""
    from controlplane.grants.store import ENV_TABLE, TABLE_NAME, DynamoGrantStore

    return DynamoGrantStore(os.environ.get(ENV_TABLE) or TABLE_NAME)


def _signed_in():
    from . import session

    try:
        return _session()
    except session.SessionError as e:
        raise click.ClickException(str(e)) from None
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise click.ClickException(f"Can't load the IdP config: {e}") from None


def _run(fn):
    """Call fn(); turn grant service errors into exit 1 with a printable reason."""
    from controlplane.grants.errors import GrantNotFound, GrantRefused, GrantStoreError

    try:
        return fn()
    except GrantRefused as e:
        raise click.ClickException(f"Refused: {e}") from None
    except GrantNotFound as e:
        raise click.ClickException(str(e)) from None
    except GrantStoreError as e:
        raise click.ClickException(str(e)) from None


def parse_ttl(value: str) -> int:
    m = _TTL.match(value.strip())
    if not m or int(m.group(1)) <= 0:
        raise click.BadParameter("use a whole number with s, m or h, e.g. 60m or 2h", param_hint="--ttl")
    return int(m.group(1)) * _UNIT[m.group(2)]


def _tool_set(values: tuple[str, ...]) -> frozenset[str]:
    """`--tools a,b --tools c` -> {a, b, c}."""
    return frozenset(t.strip() for v in values for t in v.split(",") if t.strip())


def _when(expires_at: int | None) -> str:
    if expires_at is None:
        return "never"
    from datetime import datetime

    left = int((expires_at - time.time()) // 60)
    local = datetime.fromtimestamp(expires_at).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return f"{local} (in {left} min)" if left >= 0 else f"{local} (expired)"


def _names(tools: frozenset[str]) -> str:
    return ", ".join(sorted(tools)) or "(none)"


def _show(g) -> None:
    rows = [
        ("grant_id", g.grant_id),
        ("status", g.status),
        ("agent", g.agent_id),
        ("workflow", g.workflow_id),
        ("human", g.human_id or "(none)"),
        ("repository", g.resources.get("repository", "(none)")),
        ("tools", _names(g.tools)),
        ("delegable_tools", _names(g.delegable_tools)),
        ("parent", g.parent_grant_id or "(root)"),
        ("expires", _when(g.expires_at)),
    ]
    for k, v in rows:
        click.echo(f"{k + ':':17}{v}")


@click.group(help="Create, revoke and inspect delegation grants. Needs agentledger login.")
def grant() -> None:
    pass


@grant.command(help="Create a root grant for an agent, on behalf of the signed-in human.")
@click.option("--agent", "agent_id", required=True, help="Registered agent, e.g. agent_coder.")
@click.option("--workflow", "workflow_id", required=True, help="Workflow ID, e.g. wf_demo.")
@click.option("--tools", multiple=True, required=True, help="Tools the agent may EXECUTE (comma-separated or repeated).")
@click.option("--delegable", multiple=True, help="Tools it may hand on to other agents. Never implies execute.")
@click.option("--repo", "repository", required=True, help="Repository owner/name the grant is scoped to.")
@click.option("--ttl", default="60m", show_default=True, help="Lifetime: 30m, 2h (at most 4h).")
def create(agent_id: str, workflow_id: str, tools: tuple[str, ...], delegable: tuple[str, ...],
           repository: str, ttl: str) -> None:
    from controlplane.grants.service import GrantRequest, create_grant

    seconds = parse_ttl(ttl)
    human = _signed_in()
    now = time.time()
    req = GrantRequest(agent_id=agent_id, workflow_id=workflow_id, tools=_tool_set(tools),
                       delegable_tools=_tool_set(delegable), expires_at=int(now) + seconds,
                       repository=repository)
    g = _run(lambda: create_grant(req, store=_store(), human=human, now=now))
    click.echo(f"Created grant {g.grant_id} for {g.agent_id} on behalf of {g.human_id}")
    _show(g)


@grant.command(help="Revoke a grant. Its child grants are denied at their next gateway call.")
@click.argument("grant_id")
def revoke(grant_id: str) -> None:
    from controlplane.grants.service import revoke_grant

    human = _signed_in()
    r = _run(lambda: revoke_grant(grant_id, store=_store(), human=human))
    click.echo(r.message)


@grant.command(help="Show one grant.")
@click.argument("grant_id")
def show(grant_id: str) -> None:
    from controlplane.grants.service import show_grant

    human = _signed_in()
    _show(_run(lambda: show_grant(grant_id, store=_store(), human=human)))


@grant.command(name="list", help="List your grants (all grants for security-admin).")
@click.option("--workflow", "workflow_id", default=None, help="Only this workflow.")
def list_(workflow_id: str | None) -> None:
    from controlplane.grants.service import list_grants

    human = _signed_in()
    rows = _run(lambda: list_grants(store=_store(), human=human, workflow_id=workflow_id))
    if not rows:
        click.echo("No grants." if not workflow_id else f"No grants in {workflow_id}.")
        return
    click.echo(f"{'GRANT':22} {'STATUS':9} {'AGENT':14} {'WORKFLOW':16} {'TOOLS':24} EXPIRES")
    for g in rows:
        click.echo(f"{g.grant_id:22} {g.status:9} {g.agent_id:14} {g.workflow_id:16} "
                   f"{_names(g.tools):24} {_when(g.expires_at)}")
    if workflow_id:
        click.echo("(list --workflow reads an index that can lag a revoke by a moment; "
                   "`grant show` is up to date)")
