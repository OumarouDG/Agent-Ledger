"""CLI commands. Commands not built yet are stubs that fail loudly, so a stub can't
pass for a real sign-in."""

from __future__ import annotations

import click


def _not_implemented(name: str, phase: str) -> None:
    raise click.ClickException(f"`agentledger {name}` is not implemented yet (phase {phase}).")


@click.command(help="Sign in in the browser (authorization code + PKCE).")
def login() -> None:
    # Imported here so `agentledger --help` works without controlplane or a config file.
    from controlplane.auth.config import load_config

    from . import login as flow
    from .storage import StorageError, TokenStore

    try:
        cfg = load_config()
        store = TokenStore.for_config(cfg)
        res = flow.authenticate()
    except KeyboardInterrupt:
        raise click.ClickException("Login cancelled") from None
    except (flow.LoginError, FileNotFoundError, ValueError) as e:
        raise click.ClickException(str(e)) from None
    try:
        store.save(res.tokens)
    except StorageError as e:
        raise click.ClickException(f"Browser sign-in worked but tokens were not saved, "
                                   f"so you are not signed in. {e}") from None
    click.echo(f"Signed in as {res.username} ({', '.join(res.groups) or 'no groups'})")


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
