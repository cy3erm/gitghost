"""
Exposure Score: one 0–100 number, higher = more exposed. It is the hook — a
credit-score-for-how-much-you-leak that a non-security person understands at a
glance and instinctively wants to compare.

Design goals:
  * A single live cloud/root secret should read as Critical on its own.
    (Intuition: "you leaked a live AWS secret key" is not a 30/100 situation.)
  * Volume should still push the number up — 40 leaks are worse than one.
  * It must saturate, never overflow, and degrade gracefully to Minimal on a
    clean identity.

So the score is max(worst-single-finding floor, saturating aggregate).
"""

import math
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


def _band(score: int) -> tuple[str, str]:
    for threshold, band, grade in BANDS:
        if score >= threshold:
            return band, grade
    return "MINIMAL", "A"


def compute_score(findings: list[Finding], meta: MetadataReport) -> ScoreCard:
    secrets = [f for f in findings if f.kind == "secret"]
    infra = [f for f in findings if f.kind == "infra"]
    live = [f for f in secrets if not f.is_ghost]
    ghost = [f for f in secrets if f.is_ghost]

    # ---- saturating aggregate ----
    raw = 0.0
    for f in secrets:
        raw += f.severity * (0.9 if f.is_ghost else 1.0)
    for f in infra:
        raw += f.severity * 0.5
    pii = 0
    if meta.emails:                         # real (non-noreply) address exposed
        raw += 6
        pii += 1
    if meta.dominant_utc_offset:            # timezone / rhythm inferable
        raw += 3
        pii += 1
    aggregate = 100 * (1 - math.exp(-raw / 26))

    # ---- worst-single-finding floor ----
    floor = 0.0
    worst_label = "—"
    if secrets:
        worst = max(secrets, key=lambda f: f.severity)
        worst_label = worst.label + (" (ghost)" if worst.is_ghost else " (live)")
        floor = worst.severity * 8 * (0.9 if worst.is_ghost else 1.0)

    score = int(round(min(100, max(floor, aggregate))))
    band, grade = _band(score)

    drivers: list[str] = []
    if live:
        drivers.append(f"{len(live)} live secret{'s' if len(live) != 1 else ''} in current code")
    if ghost:
        drivers.append(f"{len(ghost)} 'deleted' secret{'s' if len(ghost) != 1 else ''} still recoverable from history")
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
    )
