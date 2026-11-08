"""`agentledger` click group. Entry point for the console script."""

from __future__ import annotations

import click

from . import __version__, commands, grant_commands, run_commands


@click.group(help="AgentLedger: sign in as a human; agents act under your delegation grant.")
@click.version_option(__version__, prog_name="agentledger")
def cli() -> None:
    pass


for _cmd in commands.ALL:
    cli.add_command(_cmd)
cli.add_command(grant_commands.grant)
cli.add_command(run_commands.run)
