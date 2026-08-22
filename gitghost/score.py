import math
from collections import defaultdict
from dataclasses import dataclass, field

from .metadata import MetadataReport
from .rules import Finding

BANDS = [
    (80, "CRITICAL", "F"),
    (60, "HIGH", "D"),
    (40, "MODERATE", "C"),
    (20, "LOW", "B"),
    (0, "MINIMAL", "A"),
]

# Ghost secrets start slightly discounted (0.9) because they're not in HEAD,
# but age raises the weight: a leak recoverable for years is worse than one
# from last week. +0.25/yr, capped at 1.4.
_AGE_WEIGHT_CAP = 1.4
_AGE_WEIGHT_PER_YEAR = 0.25


@dataclass
class ScoreCard:
    score: int
    band: str
    grade: str
    live_secrets: int = 0
    ghost_secrets: int = 0
    pii_hits: int = 0
    infra_hits: int = 0
    worst: str = ""
    drivers: list[str] = field(default_factory=list)
    oldest_exposed_days: int | None = None
    reused_secrets: int = 0
    leaked_reused: int = 0


def _band(score: int) -> tuple[str, str]:
    for threshold, band, grade in BANDS:
        if score >= threshold:
            return band, grade
    return "MINIMAL", "A"


def _ghost_weight(days_exposed: int | None) -> float:
    if days_exposed is None:
        return 0.9
    return min(_AGE_WEIGHT_CAP,
               0.9 + days_exposed / 365 * _AGE_WEIGHT_PER_YEAR)


def correlate(findings: list[Finding]) -> list[Finding]:
    """Link identical secrets across repos and across live/history.

    Same fingerprint in several repos means a credential was copied around;
    a ghost whose fingerprint also matches a *live* finding means the secret
    was "deleted" from history but is still in use somewhere — both are worth
    surfacing separately in the score.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.kind == "secret" and f.fingerprint:
            groups[f.fingerprint].append(f)

    for members in groups.values():
        if len(members) < 2:
            continue
        repos = {f.repo for f in members}
        has_ghost = any(f.is_ghost for f in members)
        has_live = any(not f.is_ghost for f in members)
        for f in members:
            f.reused_in = sorted(repos - {f.repo})
            f.leaked_then_reused = has_ghost and has_live
    return findings


def compute_score(findings: list[Finding], meta: MetadataReport) -> ScoreCard:
    meta = meta or MetadataReport()
    correlate(findings)
    secrets = [f for f in findings if f.kind == "secret"]
    infra = [f for f in findings if f.kind == "infra"]
    live = [f for f in secrets if not f.is_ghost]
    ghost = [f for f in secrets if f.is_ghost]
    reused = [f for f in secrets if f.reused_in]
    leaked_reused = [f for f in secrets if f.leaked_then_reused]


    raw = 0.0
    for f in secrets:
        raw += f.severity * (_ghost_weight(f.exposed_days) if f.is_ghost else 1.0)
    for f in infra:
        raw += f.severity * 0.5
    # reuse bonuses: shared credential across repos, and the nasty case of a
    # secret that was "removed" but still matches something live elsewhere
    raw += len(reused) * 3
    raw += len(leaked_reused) * 6
    pii = 0
    if meta.emails:
        raw += 6
        pii += 1
    if meta.dominant_utc_offset:
        raw += 3
        pii += 1
    aggregate = 100 * (1 - math.exp(-raw / 26))


    floor = 0.0
    worst_label = "—"
    if secrets:
        worst = max(secrets, key=lambda f: f.severity)
        worst_label = worst.label + (" (ghost)" if worst.is_ghost else " (live)")
        floor = worst.severity * 8 * (_ghost_weight(worst.exposed_days)
                                      if worst.is_ghost else 1.0)

    score = int(round(min(100, max(floor, aggregate))))
    band, grade = _band(score)

    exposed_days = [f.exposed_days for f in ghost if f.exposed_days is not None]
    oldest = max(exposed_days) if exposed_days else None

    drivers: list[str] = []
    if live:
        drivers.append(f"{len(live)} live secret{'s' if len(live) != 1 else ''} in current code")
    if ghost:
        drivers.append(f"{len(ghost)} 'deleted' secret{'s' if len(ghost) != 1 else ''} still recoverable from history")
    if leaked_reused:
        drivers.append("a 'deleted' secret still matches one live in current code")
    if reused:
        drivers.append(f"{len(reused)} secret{'s' if len(reused) != 1 else ''} reused across repos")
    if oldest is not None and oldest >= 90:
        years = oldest / 365
        span = f"{years:.1f} yr" if years >= 2 else f"{oldest} days"
        drivers.append(f"oldest leak still recoverable after {span}")
    if meta.emails:
        drivers.append(f"real author email exposed ({meta.emails[0]})")
    if meta.dominant_utc_offset:
        drivers.append(f"timezone inferable from commit times (UTC{meta.dominant_utc_offset})")
    if infra:
        drivers.append(f"{len(infra)} internal infrastructure breadcrumb{'s' if len(infra) != 1 else ''}")

    return ScoreCard(
        score=score, band=band, grade=grade,
        live_secrets=len(live), ghost_secrets=len(ghost),
        pii_hits=pii, infra_hits=len(infra),
        worst=worst_label, drivers=drivers,
        oldest_exposed_days=oldest,
        reused_secrets=len(reused),
        leaked_reused=len(leaked_reused),
    )
