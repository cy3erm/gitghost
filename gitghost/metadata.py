import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class MetadataReport:
    emails: list[str] = field(default_factory=list)
    noreply_emails: list[str] = field(default_factory=list)
    other_emails: list[str] = field(default_factory=list)  # co-authors', not the subject's
    email_authors: dict[str, set[str]] = field(default_factory=dict)
    email_repos: dict[str, int] = field(default_factory=dict)
    dominant_utc_offset: str | None = None
    likely_active_hours: str | None = None
    commit_count: int = 0


_NOREPLY = re.compile(r"noreply|users\.noreply\.github\.com", re.I)
# GitHub privacy email embeds the login: "123456+octocat@users.noreply.github.com"
_NOREPLY_LOGIN = re.compile(r"^(?:\d+\+)?([^@]+)@users\.noreply\.github\.com$", re.I)


def analyze_metadata(root: str) -> MetadataReport:
    out = subprocess.run(
        ["git", "-C", root, "log", "--all", "--format=%an|%ae|%ai"],
        capture_output=True, text=True, errors="ignore",
    ).stdout

    emails: Counter[str] = Counter()
    offsets: Counter[str] = Counter()
    hours: Counter[int] = Counter()
    authors: dict[str, set[str]] = {}
    count = 0

    for line in out.splitlines():
        if line.count("|") < 2:
            continue
        name, email, ts = line.split("|", 2)
        count += 1
        email = email.strip()
        emails[email] += 1
        authors.setdefault(email, set()).add(name.strip())

        m = re.search(r"(\d{2}):\d{2}:\d{2}\s([+-]\d{4})", ts)
        if m:
            hours[int(m.group(1))] += 1
            offsets[m.group(2)] += 1

    report = MetadataReport(commit_count=count, email_authors=authors,
                            email_repos={e: 1 for e in emails})
    for email, _ in emails.most_common():
        (report.noreply_emails if _NOREPLY.search(email) else report.emails).append(email)

    if offsets:
        report.dominant_utc_offset = offsets.most_common(1)[0][0]
    if hours:
        top = [h for h, _ in hours.most_common(6)]
        lo, hi = min(top), max(top)
        report.likely_active_hours = f"{lo:02d}:00–{hi:02d}:00 (local)"
    return report


def _looks_mine(email: str, meta: MetadataReport,
                profile=None, login: str = "") -> bool:
    """Does this commit email actually belong to the scanned identity?

    A repo owner's commits are not the only commits in their repos —
    contributors push with their own identities. Flagging every author
    address as the subject's email produced false attributions.
    """
    e = email.casefold()
    if profile and profile.email and e == profile.email.casefold():
        return True
    m = _NOREPLY_LOGIN.match(email)
    if m and login and m.group(1).casefold() == login.casefold():
        return True  # github's privacy email literally contains the login
    names = {n.casefold() for n in meta.email_authors.get(email, ())}
    targets = set()
    if profile:
        targets |= {profile.name.casefold(), profile.login.casefold()}
    if login:
        targets.add(login.casefold())
    if names & targets:
        return True
    # strong signal without any name match: the same address spans several
    # of the subject's repos — one-off contributors rarely do that
    return meta.email_repos.get(email, 0) >= 2


def attribute_emails(meta: MetadataReport,
                     profile=None, login: str = "") -> None:
    """Re-sort meta.emails into the subject's vs co-authors', in place.

    With no identity signals (no profile, no login — e.g. --local) there is
    nothing to attribute against, so everything stays as before.
    """
    if not profile and not login:
        return
    mine: list[str] = []
    others: list[str] = []
    for email in meta.emails:
        if _looks_mine(email, meta, profile, login):
            mine.append(email)
        else:
            others.append(email)
    meta.emails = mine
    meta.other_emails = others
