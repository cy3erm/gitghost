import json
import os
import subprocess

import urllib.request
from dataclasses import dataclass


API = "https://api.github.com"


@dataclass
class Repo:
    name: str
    full_name: str
    clone_url: str
    pushed_at: str
    html_url: str = ""


def _get(url: str) -> list | dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "gitghost",
    })
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def list_public_repos(identity: str, limit: int = 30) -> list[Repo]:
    repos: list[Repo] = []
    page = 1
    while len(repos) < limit:

        data = _get(f"{API}/users/{identity}/repos?per_page=100&page={page}&sort=pushed")
        if not isinstance(data, list) or not data:
            break
        for d in data:
            if d.get("fork"):
                continue
            repos.append(Repo(
                name=d["name"], full_name=d["full_name"],
                clone_url=d["clone_url"], pushed_at=d.get("pushed_at", ""),
                html_url=d.get("html_url", ""),
            ))
            if len(repos) >= limit:
                break
        page += 1
    return repos


def list_org_repos(org: str, limit: int = 30) -> list[Repo]:
    """Public repos of an organization."""
    repos: list[Repo] = []
    page = 1
    while len(repos) < limit:
        data = _get(f"{API}/orgs/{org}/repos?per_page=100&page={page}")
        if not isinstance(data, list) or not data:
            break
        for d in data:
            if d.get("fork"):
                continue
            repos.append(Repo(
                name=d["name"], full_name=d["full_name"],
                clone_url=d["clone_url"], pushed_at=d.get("pushed_at", ""),
                html_url=d.get("html_url", ""),
            ))
            if len(repos) >= limit:
                break
        page += 1
    return repos


def list_public_members(org: str) -> list[str]:
    """Public members of an org (only those who opted in)."""
    members: list[str] = []
    page = 1
    while True:
        data = _get(f"{API}/orgs/{org}/members?per_page=100&page={page}")
        if not isinstance(data, list) or not data:
            break
        members += [d["login"] for d in data]
        page += 1
    return members


def list_network(identity: str) -> list[str]:
    """Followers + following of a user — their first-degree graph."""
    logins: list[str] = []
    seen: set[str] = set()
    for rel in ("followers", "following"):
        page = 1
        while True:
            data = _get(f"{API}/users/{identity}/{rel}?per_page=100&page={page}")
            if not isinstance(data, list) or not data:
                break
            for d in data:
                login = d["login"]
                if login.lower() != identity.lower() and login not in seen:
                    seen.add(login)
                    logins.append(login)
            page += 1
    return logins


@dataclass
class Gist:
    id: str
    description: str
    html_url: str
    files: dict  # name -> {raw_url, ...}


def list_public_gists(identity: str, limit: int = 100) -> list[Gist]:
    gists: list[Gist] = []
    page = 1
    while len(gists) < limit:
        data = _get(f"{API}/users/{identity}/gists?per_page=100&page={page}")
        if not isinstance(data, list) or not data:
            break
        for d in data:
            gists.append(Gist(
                id=d["id"], description=d.get("description") or "",
                html_url=d.get("html_url", ""), files=d.get("files", {}),
            ))
            if len(gists) >= limit:
                break
        page += 1
    return gists


def fetch_gist_file(raw_url: str) -> str | None:
    try:
        req = urllib.request.Request(raw_url, headers={
            "User-Agent": "gitghost",
            "Accept": "application/vnd.github.raw",
        })
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
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
    if len(parts) < 2:
        raise ValueError(f"not a valid repo reference: {url!r} (expected owner/name or a GitHub URL)")
    owner, name = parts[0], parts[1]
    full = f"{owner}/{name}"
    return Repo(name=name, full_name=full,
                clone_url=f"https://github.com/{full}.git",
                pushed_at="", html_url=f"https://github.com/{full}")


def clone(repo: Repo, dest_parent: str) -> str | None:
    dest = os.path.join(dest_parent, repo.name)
    r = subprocess.run(
        ["git", "clone", "--quiet", repo.clone_url, dest],
        capture_output=True, text=True,
    )
    return dest if r.returncode == 0 else None
