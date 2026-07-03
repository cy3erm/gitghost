import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class MetadataReport:
    emails: list[str] = field(default_factory=list)
    noreply_emails: list[str] = field(default_factory=list)
    dominant_utc_offset: str | None = None
    likely_active_hours: str | None = None
    commit_count: int = 0


_NOREPLY = re.compile(r"noreply|users\.noreply\.github\.com", re.I)


def analyze_metadata(root: str) -> MetadataReport:
    out = subprocess.run(
        ["git", "-C", root, "log", "--all", "--format=%ae|%ai"],
        capture_output=True, text=True, errors="ignore",
    ).stdout

    emails: Counter[str] = Counter()
    offsets: Counter[str] = Counter()
    hours: Counter[int] = Counter()
    count = 0

    for line in out.splitlines():
        if "|" not in line:
            continue
        email, ts = line.split("|", 1)
        count += 1
        emails[email.strip()] += 1

        m = re.search(r"(\d{2}):\d{2}:\d{2}\s([+-]\d{4})", ts)
        if m:
            hours[int(m.group(1))] += 1
            offsets[m.group(2)] += 1

    report = MetadataReport(commit_count=count)
    for email, _ in emails.most_common():
        (report.noreply_emails if _NOREPLY.search(email) else report.emails).append(email)

    if offsets:
        report.dominant_utc_offset = offsets.most_common(1)[0][0]
    if hours:
        top = [h for h, _ in hours.most_common(6)]
        lo, hi = min(top), max(top)
        report.likely_active_hours = f"{lo:02d}:00–{hi:02d}:00 (local)"
    return report
