import re
import subprocess
from datetime import datetime, timezone

from .rules import Finding, scan_text


MAX_BLOB_BYTES = 2_000_000


def _git(root: str, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", root, *args],
        capture_output=True, text=True, errors="ignore",
    ).stdout


def _head_blobs(root: str) -> set[str]:
    out = _git(root, "ls-tree", "-r", "HEAD")
    blobs = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "blob":
            blobs.add(parts[2])
    return blobs


def _all_historical_blobs(root: str) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for line in _git(root, "rev-list", "--all", "--objects").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and len(parts[0]) == 40:
            seen.setdefault(parts[0], parts[1])

    for line in _git(root, "fsck", "--unreachable", "--no-reflogs").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            seen.setdefault(parts[2], "")
    return list(seen.items())


class _BatchReader:
    """Streaming reader for `git cat-file --batch`.

    One long-lived git process serves every blob request instead of paying
    fork/exec per blob (the old code spawned one `cat-file -p` each — that
    dominated runtime on repos with lots of history).
    """

    def __init__(self, root: str):
        self.proc = subprocess.Popen(
            ["git", "-C", root, "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def _drain(self, n: int) -> None:
        remaining = n
        while remaining > 0:
            chunk = self.proc.stdout.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)

    def get(self, oid: str) -> bytes | None:
        try:
            self.proc.stdin.write(f"{oid}\n".encode())
            self.proc.stdin.flush()
            # rev-list also lists trees/commits; their bodies must be drained
            # to keep the batch protocol in sync.
            header = self.proc.stdout.readline().decode(errors="ignore").split()
            if len(header) != 3:
                return None  # "<oid> missing" or similar
            try:
                size = int(header[2])
            except ValueError:
                return None
            if header[1] != "blob":
                self._drain(size + 1)
                return None
            if size > MAX_BLOB_BYTES:
                self._drain(size + 1)
                return None
            body = self.proc.stdout.read(size)
            self.proc.stdout.read(1)  # trailing newline
            return body
        except (OSError, ValueError):
            return None

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.proc.wait()


_VENDOR = re.compile(r"(^|/)(node_modules|vendor|dist|build|\.next|bower_components|"
                     r"third_party|site-packages|\.venv|venv)/|"
                     r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
                     r"\.min\.js|\.min\.css|\.map)$", re.I)


# Git's %ci looks like "2024-01-01 12:00:00 -0700" — an offset without a
# colon, which datetime.fromisoformat rejects before Python 3.11. Parse it
# explicitly so exposure age works on every supported version.
_GIT_TIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\s*([+-]\d{2}):?(\d{2})$")


def _parse_git_time(raw: str) -> datetime | None:
    m = _GIT_TIME.match(raw.strip())
    if not m:
        return None
    try:
        return datetime.fromisoformat(f"{m[1]}T{m[2]}{m[3]}:{m[4]}")
    except ValueError:
        return None


def _introducing_commit(root: str, blob: str) -> dict | None:
    out = _git(root, "log", "--all", "--reverse",
               "--format=%H|%ci|%an|%s", "--find-object", blob)
    for line in out.splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4 and len(parts[0]) == 40:
            when = _parse_git_time(parts[1])
            days = None
            if when is not None:
                days = max(0, (datetime.now(timezone.utc) - when).days)
            return {
                "sha": parts[0][:10],
                "sha_full": parts[0],
                "date": parts[1].strip()[:10],
                "author": parts[2].strip(),
                "subject": parts[3].strip(),
                "days_exposed": days,
            }
    return None


def _commit_meta(root: str, sha: str) -> dict:
    out = _git(root, "show", "-s", "--format=%H|%ci|%s", sha)
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3 and len(parts[0]) == 40:
            when = _parse_git_time(parts[1])
            days = None
            if when is not None:
                days = max(0, (datetime.now(timezone.utc) - when).days)
            return {
                "sha": parts[0][:10], "sha_full": parts[0],
                "date": parts[1].strip()[:10],
                "subject": parts[2].strip(), "days_exposed": days,
            }
    return {"sha": sha[:10], "sha_full": sha, "date": "", "subject": "",
            "days_exposed": None}


def recover_force_pushed(root: str, shas: list[str], repo_name: str,
                         max_commits: int = 30) -> list[Finding]:
    """Scan commits that are no longer reachable from any ref.

    Force-push a secret away and no clone contains it — but if we know the
    commit SHA (e.g. from the Events API), GitHub still serves the object.
    Fetch each SHA into the clone, then scan its tree for blobs that are not
    in HEAD, i.e. exactly the files the force-push tried to bury.
    """
    ghosts: list[Finding] = []
    seen_fp: set[tuple] = set()

    head = _head_blobs(root)
    batch = None
    try:
        for sha in shas[:max_commits]:
            # object already in the clone? if not, ask GitHub for it by SHA
            if not _commit_exists(root, sha):
                _git(root, "fetch", "--quiet", "--force", "origin", sha)
            if not _commit_exists(root, sha):
                continue  # gone from the server too (GC'd or never public)

            meta = _commit_meta(root, sha)
            tree: list[tuple[str, str]] = []
            for line in _git(root, "ls-tree", "-r", meta["sha_full"]).splitlines():
                parts = line.split(maxsplit=3)
                if len(parts) == 4 and parts[1] == "blob":
                    path = parts[3].strip()
                    if _VENDOR.search(path):
                        continue
                    tree.append((parts[2], path))

            if batch is None:
                batch = _BatchReader(root)
            for blob, path in tree:
                if blob in head:
                    continue  # live in HEAD; already covered by the file scan
                raw = batch.get(blob)
                if not raw:
                    continue
                for f in scan_text(raw.decode("utf-8", errors="ignore")):
                    key = (f.rule_id, f.fingerprint)
                    if key in seen_fp:
                        continue
                    seen_fp.add(key)
                    f.repo = repo_name
                    f.path = path
                    f.is_ghost = True
                    f.force_pushed = True
                    f.commit = meta["sha"]
                    f.commit_full = meta["sha_full"]
                    f.commit_message = meta["subject"]
                    f.entered_date = meta["date"]
                    f.exposed_days = meta["days_exposed"]
                    ghosts.append(f)
    finally:
        if batch is not None:
            batch.close()
    return ghosts


def _commit_exists(root: str, sha: str) -> bool:
    return bool(_git(root, "cat-file", "-t", sha).strip())


def recover_ghosts(root: str, repo_name: str, max_blobs: int = 4000) -> list[Finding]:
    head = _head_blobs(root)
    ghosts: list[Finding] = []
    seen_fp: set[tuple] = set()
    candidates: list[tuple[str, str]] = []

    for blob, path in _all_historical_blobs(root):
        if blob in head:
            continue
        if path and _VENDOR.search(path):
            continue
        if len(candidates) >= max_blobs:
            break
        candidates.append((blob, path))

    batch = _BatchReader(root)
    try:
        for blob, path in candidates:
            raw = batch.get(blob)
            if not raw:
                continue
            content = raw.decode("utf-8", errors="ignore")
            for f in scan_text(content):
                key = (f.rule_id, f.fingerprint)
                if key in seen_fp:
                    continue
                seen_fp.add(key)
                info = _introducing_commit(root, blob)
                f.repo = repo_name
                f.is_ghost = True
                if info:
                    f.commit = info["sha"]
                    f.commit_full = info["sha_full"]
                    f.commit_author = info["author"]
                    f.commit_message = info["subject"]
                    f.exposed_days = info["days_exposed"]
                    f.entered_date = info["date"]
                else:
                    f.commit = "dangling"
                # real path inside the historical tree (first-seen name), so
                # findings carry exact file+line even though the file is gone
                f.path = path or "(history)"
                ghosts.append(f)
    finally:
        batch.close()
    return ghosts
