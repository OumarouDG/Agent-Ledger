"""GitHub access for the gateway, using a GitHub App installation.

The App private key and the installation token stay inside the gateway process. Tools
return only the fields an agent needs; no token is ever returned or logged.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable

import jwt
import requests

API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TIMEOUT = 10


class GitHubError(RuntimeError):
    """A GitHub call failed. The message is safe to show an agent (no secrets)."""


class GitHubApp:
    def __init__(self, app_id: str, installation_id: str, key_provider: Callable[[], str],
                 http=requests):
        self._app_id = str(app_id)
        self._installation_id = str(installation_id)
        self._key_provider = key_provider
        self._http = http
        self._lock = threading.Lock()
        self._token: str | None = None
        self._token_exp = 0.0

    def _app_jwt(self) -> str:
        now = int(time.time())
        claims = {"iat": now - 60, "exp": now + 9 * 60, "iss": self._app_id}
        return jwt.encode(claims, self._key_provider(), algorithm="RS256")

    def _installation_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_exp - 60:
                return self._token
            try:
                r = self._http.post(
                    f"{API}/app/installations/{self._installation_id}/access_tokens",
                    headers={"Authorization": f"Bearer {self._app_jwt()}",
                             "Accept": "application/vnd.github+json"},
                    timeout=_TIMEOUT,
                )
            except Exception as e:  # network or key problem
                raise GitHubError(f"github auth failed: {type(e).__name__}") from e
            if r.status_code != 201:
                raise GitHubError(f"github auth failed: HTTP {r.status_code}")
            body = r.json()
            self._token = body["token"]
            # GitHub installation tokens last 1 hour; refresh a minute early.
            self._token_exp = time.time() + 3600
            return self._token

    def get_issue(self, repo: str, number: int) -> dict:
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not isinstance(number, int) or number < 1:
            raise GitHubError("invalid issue number")
        try:
            r = self._http.get(
                f"{API}/repos/{repo}/issues/{number}",
                headers={"Authorization": f"Bearer {self._installation_token()}",
                         "Accept": "application/vnd.github+json"},
                timeout=_TIMEOUT,
            )
        except GitHubError:
            raise
        except Exception as e:
            raise GitHubError(f"github request failed: {type(e).__name__}") from e
        if r.status_code == 404:
            raise GitHubError("issue not found")
        if r.status_code != 200:
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        d = r.json()
        if "pull_request" in d:  # the issues API also returns PRs
            raise GitHubError("issue not found")
        return {
            "repository": repo,
            "number": d["number"],
            "title": d["title"],
            "state": d["state"],
            "body": d.get("body") or "",
            "labels": [x["name"] for x in d.get("labels", [])],
            "url": d["html_url"],
        }


def secrets_manager_key(secret_id: str, region: str | None = None) -> Callable[[], str]:
    """Read the App private key from AWS Secrets Manager on each token refresh."""
    def provider() -> str:
        import boto3
        client = boto3.client("secretsmanager", region_name=region)
        return client.get_secret_value(SecretId=secret_id)["SecretString"]
    return provider


def from_env(env) -> GitHubApp | None:
    """Build the App from environment settings, or None when GitHub is not configured."""
    app_id = env.get("AGENTLEDGER_GITHUB_APP_ID")
    inst = env.get("AGENTLEDGER_GITHUB_INSTALLATION_ID")
    secret = env.get("AGENTLEDGER_GITHUB_KEY_SECRET")
    if not (app_id and inst and secret):
        return None
    return GitHubApp(app_id, inst, secrets_manager_key(secret, env.get("AWS_REGION", "us-east-1")))
