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


def _introducing_commit(root: str, blob: str) -> dict | None:
    out = _git(root, "log", "--all", "--reverse",
               "--format=%H|%ci|%an|%s", "--find-object", blob)
    for line in out.splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4 and len(parts[0]) == 40:
            try:
                when = datetime.fromisoformat(parts[1].strip())
                days = max(0, (datetime.now(timezone.utc) - when).days)
            except ValueError:
                days = None
            return {
                "sha": parts[0][:10],
                "sha_full": parts[0],
                "date": parts[1].strip()[:10],
                "author": parts[2].strip(),
                "subject": parts[3].strip(),
                "days_exposed": days,
            }
    return None


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
