"""
Ghost recovery — the signature capability.

When someone commits a secret, panics, deletes the line (or force-pushes), the
blob almost always survives:
  * still reachable in an old commit on some branch/tag, or
  * orphaned but not yet garbage-collected (a "dangling" object).

We diff every historical blob against what's actually in HEAD. Anything holding
a secret that is NOT in the current tree is a GHOST: the owner believes it's
gone, and it is not. That gap is the whole point of the tool.

This operates only on a repository already present on disk. It reads git
objects; it never contacts any secret's provider.
"""

import re
import subprocess
from dataclasses import dataclass

from .rules import Finding, scan_text


def _git(root: str, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True, text=True, errors="ignore",
    ).stdout


def _head_blobs(root: str) -> set[str]:
    """Blob hashes currently present in the working tree of HEAD."""
    out = _git(root, "ls-tree", "-r", "HEAD")
    blobs = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "blob":
            blobs.add(parts[2])
    return blobs


def _all_historical_blobs(root: str) -> list[tuple[str, str]]:
    """Every blob reachable in history (with its path), plus orphaned ones.

    Returns (blob_hash, path) so we can skip vendored dependency code — the
    single biggest source of junk findings in real repos.
    """
    seen: dict[str, str] = {}
    for line in _git(root, "rev-list", "--all", "--objects").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and len(parts[0]) == 40:
            seen.setdefault(parts[0], parts[1])
    # unreachable (post force-push / amend / rebase, pre-GC) — no path available
    for line in _git(root, "fsck", "--unreachable", "--no-reflogs").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            seen.setdefault(parts[2], "")
    return list(seen.items())


# dependency / build output / lockfiles — not the user's own code
_VENDOR = re.compile(r"(^|/)(node_modules|vendor|dist|build|\.next|bower_components|"
                     r"third_party|site-packages|\.venv|venv)/|"
                     r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
                     r"\.min\.js|\.min\.css|\.map)$", re.I)


def _introducing_commit(root: str, blob: str) -> tuple[str, str]:
    """Best-effort: which commit first carried this blob, and when."""
    out = _git(root, "log", "--all", "--format=%H|%ci", "--find-object", blob, "--reverse")
    for line in out.splitlines():
        if "|" in line:
            h, date = line.split("|", 1)
            return h[:10], date.strip()[:10]
    return "dangling", "unknown"


def recover_ghosts(root: str, repo_name: str, max_blobs: int = 4000) -> list[Finding]:
    head = _head_blobs(root)
    ghosts: list[Finding] = []
    seen_fp: set[tuple] = set()
    checked = 0
    for blob, path in _all_historical_blobs(root):
        if blob in head:
            continue                       # still live — handled by the tree scan
        if path and _VENDOR.search(path):  # vendored dependency, not their leak
            continue
        if checked >= max_blobs:
            break
        checked += 1
        content = _git(root, "cat-file", "-p", blob)
        if not content:
            continue
        for f in scan_text(content):
            key = (f.rule_id, f.redacted)  # collapse the same secret repeated across history
            if key in seen_fp:
                continue
            seen_fp.add(key)
            commit, date = _introducing_commit(root, blob)
            f.repo = repo_name
            f.is_ghost = True
            f.commit = commit
            f.path = f"(history) entered {date}"
            ghosts.append(f)
    return ghosts
