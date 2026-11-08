"""CLI commands. CLI-0: stubs that fail loudly, so a stub can't pass for a real sign-in."""

from __future__ import annotations

import click


def _not_implemented(name: str, phase: str) -> None:
    raise click.ClickException(f"`agentledger {name}` is not implemented yet (phase {phase}).")


@click.command(help="Sign in in the browser (authorization code + PKCE).")
def login() -> None:
    _not_implemented("login", "CLI-1")


@click.command(help="Show who is signed in, from the verified ID token.")
def whoami() -> None:
    _not_implemented("whoami", "CLI-2")


@click.command(help="Show signed in or out, expiry, pool and region.")
def status() -> None:
    _not_implemented("status", "CLI-2")


@click.command(help="Revoke the refresh token and delete stored tokens.")
def logout() -> None:
    _not_implemented("logout", "CLI-2")


ALL = (login, whoami, status, logout)
