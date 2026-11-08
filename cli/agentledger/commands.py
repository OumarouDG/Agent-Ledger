"""CLI commands: login, whoami, status, logout. Token values are never printed.

Imports of controlplane and the session modules happen inside each command, so
`agentledger --help` works without a config file."""

from __future__ import annotations

import click


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


def _context():
    """(cfg, store, verifier) for the session commands. Tests replace this."""
    from controlplane.auth.config import load_config
    from controlplane.auth.jwt_verify import Verifier

    from .storage import TokenStore

    cfg = load_config()
    return cfg, TokenStore.for_config(cfg), Verifier(issuer=cfg["issuer"], jwks_url=cfg["jwks_url"])


def _when(expires_at: int) -> str:
    from datetime import datetime

    from .session import minutes_left

    local = datetime.fromtimestamp(expires_at).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return f"{local} (in {minutes_left(expires_at)} min)"


@click.command(help="Show who is signed in, from the verified ID token. Refreshes once if expired.")
def whoami() -> None:
    from . import session

    try:
        cfg, store, verifier = _context()
        s = session.current_session(cfg=cfg, store=store, verifier=verifier)
    except session.SessionError as e:
        raise click.ClickException(str(e)) from None
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise click.ClickException(f"Can't load the IdP config: {e}") from None
    if s.refreshed:
        click.echo("Session refreshed.")
    click.echo(f"Signed in as {s.username}")
    click.echo(f"Groups:  {', '.join(s.groups) or 'none'}")
    click.echo(f"Expires: {_when(s.expires_at)}")


@click.command(help="Show signed in or out, expiry, pool and region. Never errors.")
def status() -> None:
    for line in status_lines():
        click.echo(line)


def status_lines() -> list[str]:
    """Never raises. Verifies the stored ID token but does not refresh it."""
    from controlplane.auth.jwt_verify import AuthError

    from .session import jwks_unreachable, jwks_unreachable_text
    from .storage import StorageError

    try:
        cfg, store, verifier = _context()
    except Exception as e:  # noqa: BLE001 - status must not fail
        return [f"Status unknown: can't load the IdP config ({type(e).__name__}). "
                "Run `python infra/cognito_setup.py` or check shared/cognito.json."]
    where = [f"Pool:    {cfg.get('user_pool_id', 'unknown')}", f"Region:  {cfg.get('region', 'unknown')}"]
    try:
        bundle = store.load()
        if bundle is None:
            return ["Not signed in."] + where
        claims = verifier.verify_human(bundle["id_token"], cfg["cli"]["client_id"])
    except StorageError as e:
        return [str(e)] + where
    except AuthError as e:
        if jwks_unreachable(e):
            return [f"Status unknown: {jwks_unreachable_text(verifier, e)} Session not checked; "
                    "check the network."] + where
        if e.reason == "token_expired":
            hint = ("agentledger whoami refreshes it, or run agentledger login" if bundle.get("refresh_token")
                    else "run agentledger login")
            return [f"Session expired; {hint}."] + where
        return [f"Stored sign-in failed verification ({e.reason}); run agentledger login."] + where
    except Exception as e:  # noqa: BLE001 - status must not fail; type name only, never the message
        return [f"Status unknown ({type(e).__name__})."] + where
    groups = ", ".join(claims.get("cognito:groups", [])) or "no groups"
    return [f"Signed in as {claims.get('cognito:username')} ({groups})",
            f"Expires: {_when(int(claims['exp']))}"] + where


@click.command(help="Revoke the refresh token at Cognito and delete stored tokens.")
def logout() -> None:
    from . import session
    from .storage import StorageError, StoredSessionCorrupt

    try:
        cfg, store, _ = _context()
    except Exception as e:  # noqa: BLE001
        raise click.ClickException(f"Can't load the IdP config ({type(e).__name__}); nothing was deleted.") from None

    revoke_failed = False
    try:
        bundle = store.load()
    except StoredSessionCorrupt:
        bundle = {}
        click.echo("Stored sign-in was unreadable, so nothing could be revoked.")
    except StorageError as e:
        raise click.ClickException(f"{e} Nothing was revoked or deleted.") from None

    if bundle is None:
        click.echo("Not signed in; nothing to revoke.")
    elif bundle.get("refresh_token"):
        try:
            session.revoke(cfg, bundle["refresh_token"])
            click.echo("Refresh token revoke accepted by Cognito.")
        except session.RevokeFailed as e:
            revoke_failed = True
            click.echo(f"Revoke failed: {e}. The refresh token stays valid at Cognito until it expires.")
    elif bundle:
        click.echo("No refresh token stored; nothing to revoke.")

    try:
        deleted = store.delete()
    except StorageError as e:
        raise click.ClickException(f"Could not delete stored tokens: {e}") from None
    click.echo(f"Signed out: deleted {deleted} stored entries." if deleted else "No stored tokens to delete.")
    if revoke_failed:
        click.get_current_context().exit(1)


ALL = (login, whoami, status, logout)
