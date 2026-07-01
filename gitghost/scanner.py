"""Scan a checked-out repository's working tree for findings."""

import os
from dataclasses import dataclass, field

from .rules import Finding, scan_text

# Directories and extensions that are noise, not signal.
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv",
             "venv", "__pycache__", ".next", "target", ".gradle"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
            ".gz", ".tar", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".lock",
            ".min.js", ".map", ".so", ".dll", ".class", ".pyc"}
MAX_BYTES = 2_000_000


@dataclass
class RepoScan:
    repo: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0


def _readable(path: str) -> str | None:
    _, ext = os.path.splitext(path)
    if ext.lower() in SKIP_EXT:
        return None
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except (OSError, ValueError):
        return None


def scan_repo(root: str, repo_name: str) -> RepoScan:
    result = RepoScan(repo=repo_name)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            text = _readable(full)
            if text is None:
                continue
            result.files_scanned += 1
            rel = os.path.relpath(full, root)
            for f in scan_text(text):
                f.repo = repo_name
                f.path = rel
                # a committed .env is its own red flag regardless of contents
                if os.path.basename(rel).startswith(".env") and f.kind == "secret":
                    f.severity = min(10, f.severity + 1)
                result.findings.append(f)
    return result
