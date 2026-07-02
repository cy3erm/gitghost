"""
GitHub side: list a username/org's public repos and clone them shallowly-but-
with-history (we need history for ghost recovery, so no --depth=1).

Auth: reads GITHUB_TOKEN from the environment if present (raises the rate limit
from 60/hr to 5000/hr). Unauthenticated still works for small targets.

Scope note lives here on purpose: this fetches PUBLIC repositories only. That is
data the owner already chose to publish. gitghost surfaces and scores it; it
does not touch private repos, and it never authenticates against any secret it
finds.
"""

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
        # works for both users and orgs
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


def clone(repo: Repo, dest_parent: str) -> str | None:
    dest = os.path.join(dest_parent, repo.name)
    r = subprocess.run(
        ["git", "clone", "--quiet", repo.clone_url, dest],
        capture_output=True, text=True,
    )
    return dest if r.returncode == 0 else None
