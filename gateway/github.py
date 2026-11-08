"""GitHub access for the gateway, using a GitHub App installation.

The App private key and the installation token stay inside the gateway process. Tools
return only the fields an agent needs; no token is ever returned or logged.
"""

from __future__ import annotations

import base64
import re
import threading
import time
from collections.abc import Callable

import jwt
import requests

API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_TIMEOUT = 10
_BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
MAX_CONTENT_BYTES = 100_000
_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_TITLE_CHARS = 200
MAX_BODY_CHARS = 4_000


class GitHubError(RuntimeError):
    """A GitHub call failed. The message is safe to show an agent (no secrets)."""


def valid_branch(name) -> bool:
    """A branch name safe to send to GitHub. Rejects traversal, odd endings and empty parts."""
    if not isinstance(name, str) or not _BRANCH.match(name):
        return False
    parts = name.split("/")
    return (all(p and p not in (".", "..") for p in parts)
            and not name.endswith(".lock") and ".." not in name)


def valid_path(path) -> bool:
    """A repo-relative file path: no leading slash, no '..', nothing inside .git."""
    if not isinstance(path, str) or not _PATH.match(path):
        return False
    parts = path.split("/")
    return all(p and p not in (".", "..") and p.lower() != ".git" for p in parts)

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

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._installation_token()}",
                "Accept": "application/vnd.github+json"}

    def _call(self, method: str, url: str, **kw):
        try:
            return getattr(self._http, method)(url, headers=self._headers(), timeout=_TIMEOUT, **kw)
        except GitHubError:
            raise
        except Exception as e:
            raise GitHubError(f"github request failed: {type(e).__name__}") from e

    def create_branch(self, repo: str, branch: str, base: str) -> dict:
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not valid_branch(branch) or not valid_branch(base):
            raise GitHubError("invalid branch name")
        r = self._call("get", f"{API}/repos/{repo}/git/ref/heads/{base}")
        if r.status_code != 200:
            raise GitHubError("base branch not found")
        sha = r.json()["object"]["sha"]
        r = self._call("post", f"{API}/repos/{repo}/git/refs",
                       json={"ref": f"refs/heads/{branch}", "sha": sha})
        if r.status_code == 422:
            raise GitHubError("branch already exists")
        if r.status_code != 201:
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        return {"repository": repo, "branch": branch, "base": base, "sha": sha}

    def commit_file(self, repo: str, branch: str, path: str, content: str, message: str) -> dict:
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not valid_branch(branch):
            raise GitHubError("invalid branch name")
        if not valid_path(path):
            raise GitHubError("invalid path")
        if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_CONTENT_BYTES:
            raise GitHubError("content missing or too large")
        if not isinstance(message, str) or not message.strip() or len(message) > 200:
            raise GitHubError("invalid commit message")
        url = f"{API}/repos/{repo}/contents/{path}"
        existing = self._call("get", url, params={"ref": branch})
        body = {"message": message, "branch": branch,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii")}
        if existing.status_code == 200:
            body["sha"] = existing.json()["sha"]
        elif existing.status_code != 404:
            raise GitHubError(f"github request failed: HTTP {existing.status_code}")
        r = self._call("put", url, json=body)
        if r.status_code not in (200, 201):
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        d = r.json()
        return {"repository": repo, "branch": branch, "path": path,
                "commit_sha": d["commit"]["sha"], "url": d["commit"].get("html_url", "")}
    def get_test_result(self, repo: str, sha: str, branch_prefix: str) -> dict:
        """The latest workflow run for exactly this commit, only if it ran on a branch under
        the prefix. GitHub reports it; the agent cannot influence it."""
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not isinstance(sha, str) or not _SHA.match(sha):
            raise GitHubError("sha must be a full 40-character commit id")
        r = self._call("get", f"{API}/repos/{repo}/actions/runs",
                       params={"head_sha": sha, "per_page": 10})
        if r.status_code != 200:
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        runs = [x for x in r.json().get("workflow_runs", [])
                if x.get("head_sha") == sha and isinstance(x.get("head_branch"), str)
                and x["head_branch"].startswith(branch_prefix)]
        if not runs:
            return {"repository": repo, "sha": sha, "found": False, "status": "none",
                    "conclusion": None, "passed": False}
        run = max(runs, key=lambda x: (x.get("created_at") or "", x.get("run_attempt") or 0))
        return {"repository": repo, "sha": sha, "found": True, "run_id": run["id"],
                "run_attempt": run.get("run_attempt"), "workflow": run.get("name"),
                "status": run.get("status"), "conclusion": run.get("conclusion"),
                "passed": run.get("status") == "completed" and run.get("conclusion") == "success",
                "branch": run.get("head_branch"), "url": run.get("html_url")}

    def open_pull_request(self, repo: str, head: str, base: str, title: str, body: str) -> dict:
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not valid_branch(head) or not valid_branch(base):
            raise GitHubError("invalid branch name")
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
            raise GitHubError("invalid title")
        if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
            raise GitHubError("invalid body")
        r = self._call("post", f"{API}/repos/{repo}/pulls",
                       json={"title": title, "head": head, "base": base, "body": body})
        if r.status_code == 422:
            raise GitHubError("pull request not created (one may already exist, or there is nothing to merge)")
        if r.status_code != 201:
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        d = r.json()
        return {"repository": repo, "number": d["number"], "url": d["html_url"],
                "head_branch": head, "head_sha": d["head"]["sha"], "base": base,
                "state": d["state"], "merged": False}

    def get_pull_request(self, repo: str, number: int, branch_prefix: str) -> dict:
        """State of a pull request whose head branch is under the prefix: merged, by whom,
        and which logins approved the current head commit."""
        if not _REPO.match(repo or ""):
            raise GitHubError("invalid repository")
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise GitHubError("invalid pull request number")
        r = self._call("get", f"{API}/repos/{repo}/pulls/{number}")
        if r.status_code in (403, 404):
            raise GitHubError("pull request not found" if r.status_code == 404
                              else "github request failed: HTTP 403")
        if r.status_code != 200:
            raise GitHubError(f"github request failed: HTTP {r.status_code}")
        d = r.json()
        head_ref = (d.get("head") or {}).get("ref") or ""
        if not head_ref.startswith(branch_prefix):
            raise GitHubError("pull request not found")
        head_sha = d["head"]["sha"]
        approvals = None
        rv = self._call("get", f"{API}/repos/{repo}/pulls/{number}/reviews")
        if rv.status_code == 200:
            approvals = sorted({x["user"]["login"] for x in rv.json()
                                if x.get("state") == "APPROVED" and x.get("commit_id") == head_sha
                                and x.get("user")})
        return {"repository": repo, "number": number, "title": d.get("title"),
                "state": d.get("state"), "merged": bool(d.get("merged")),
                "merged_by": (d.get("merged_by") or {}).get("login"),
                "merge_commit_sha": d.get("merge_commit_sha") if d.get("merged") else None,
                "head_branch": head_ref, "head_sha": head_sha,
                "base": (d.get("base") or {}).get("ref"), "approved_by": approvals,
                "url": d.get("html_url")}

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
