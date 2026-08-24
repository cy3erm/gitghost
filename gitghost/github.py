import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass

API = "https://api.github.com"


class GitHubError(Exception):
    """A GitHub API failure with a message meant for the user."""


@dataclass
class Repo:
    name: str
    full_name: str
    clone_url: str
    pushed_at: str
    html_url: str = ""


def _headers(accept: str = "application/vnd.github+json") -> dict[str, str]:
    headers = {"Accept": accept, "User-Agent": "gitghost"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(url: str) -> list | dict:
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise GitHubError(f"not found on GitHub: {url.split('/repos')[0].rsplit('/', 1)[-1]!r} "
                              "(does the user/org exist, and are its repos public?)") from None
        if e.code in (403, 429):
            raise GitHubError("GitHub API rate limit reached "
                              "(set GITHUB_TOKEN to any token — no scopes needed — to raise it)") from None
        raise GitHubError(f"GitHub API returned HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise GitHubError(f"could not reach GitHub: {e.reason}") from None


def _repo_from(d: dict) -> Repo:
    return Repo(
        name=d["name"], full_name=d["full_name"],
        clone_url=d["clone_url"], pushed_at=d.get("pushed_at", ""),
        html_url=d.get("html_url", ""),
    )


def _list_repos(endpoint: str, limit: int) -> list[Repo]:
    repos: list[Repo] = []
    page = 1
    while len(repos) < limit:
        data = _get(f"{endpoint}?per_page=100&page={page}&sort=pushed")
        if not isinstance(data, list) or not data:
            break
        for d in data:
            if d.get("fork"):
                continue
            repos.append(_repo_from(d))
            if len(repos) >= limit:
                break
        page += 1
    return repos


def list_public_repos(identity: str, limit: int = 30) -> list[Repo]:
    return _list_repos(f"{API}/users/{identity}/repos", limit)


def list_org_repos(org: str, limit: int = 30) -> list[Repo]:
    return _list_repos(f"{API}/orgs/{org}/repos", limit)


def _paginate(endpoint: str) -> list[dict]:
    items: list[dict] = []
    page = 1
    while True:
        data = _get(f"{endpoint}?per_page=100&page={page}")
        if not isinstance(data, list) or not data:
            return items
        items += data
        page += 1


def list_public_members(org: str) -> list[str]:
    """Public members of an org (only those who opted in)."""
    return [d["login"] for d in _paginate(f"{API}/orgs/{org}/members")]


def list_network(identity: str) -> list[str]:
    """Followers + following of a user — their first-degree graph."""
    logins: list[str] = []
    seen: set[str] = set()
    for rel in ("followers", "following"):
        for d in _paginate(f"{API}/users/{identity}/{rel}"):
            login = d["login"]
            if login.lower() != identity.lower() and login not in seen:
                seen.add(login)
                logins.append(login)
    return logins


@dataclass
class Gist:
    id: str
    description: str
    html_url: str
    files: dict  # name -> {raw_url, ...}


def list_public_gists(identity: str, limit: int = 100) -> list[Gist]:
    gists: list[Gist] = []
    for d in _paginate(f"{API}/users/{identity}/gists"):
        gists.append(Gist(
            id=d["id"], description=d.get("description") or "",
            html_url=d.get("html_url", ""), files=d.get("files", {}),
        ))
        if len(gists) >= limit:
            break
    return gists


def fetch_gist_file(raw_url: str) -> str | None:
    try:
        req = urllib.request.Request(raw_url, headers=_headers("application/vnd.github.raw"))
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def repo_from_url(url: str) -> Repo:
    u = url.strip().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]

    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:", "github.com/"):
        if u.startswith(prefix):
            u = u[len(prefix):]
            break
    parts = u.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"not a valid repo reference: {url!r} (expected owner/name or a GitHub URL)")
    owner, name = parts[0], parts[1]
    full = f"{owner}/{name}"
    return Repo(name=name, full_name=full,
                clone_url=f"https://github.com/{full}.git",
                pushed_at="", html_url=f"https://github.com/{full}")


def clone(repo: Repo, dest_parent: str) -> str | None:
    dest = os.path.join(dest_parent, repo.name)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # never hang asking for credentials
    try:
        r = subprocess.run(
            ["git", "clone", "--quiet", repo.clone_url, dest],
            capture_output=True, text=True, timeout=600, env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return dest if r.returncode == 0 else None
