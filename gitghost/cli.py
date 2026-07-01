#!/usr/bin/env python3
"""
gitghost — GitHub exposure dossier.

    gitghost <github-username>                 scan a public identity
    gitghost --local <path> --name <label>     scan a repo already on disk

Output: a scored HTML dossier. Detection-only; public repos only.
"""

import argparse
import os
import sys
import tempfile
import webbrowser

from . import github
from .ghost import recover_ghosts
from .metadata import analyze_metadata
from .report import render_report
from .rules import Finding
from .scanner import scan_repo
from .score import compute_score


def _scan_one(root: str, name: str) -> tuple[list[Finding], object]:
    findings = list(scan_repo(root, name).findings)
    findings += recover_ghosts(root, name)
    meta = analyze_metadata(root)
    return findings, meta


def run_local(path: str, name: str, out: str) -> None:
    print(f"[*] scanning local repo: {name}")
    findings, meta = _scan_one(path, name)
    card = compute_score(findings, meta)
    _emit(name, card, findings, meta, 1, out)


def run_identity(identity: str, limit: int, out: str) -> None:
    print(f"[*] enumerating public repos for @{identity} ...")
    try:
        repos = github.list_public_repos(identity, limit=limit)
    except Exception as e:
        sys.exit(f"[!] could not reach GitHub API: {e}\n    (set GITHUB_TOKEN to raise rate limits)")
    if not repos:
        sys.exit(f"[!] no public repos found for @{identity}")
    print(f"[*] {len(repos)} repos. cloning + scanning (history included for ghost recovery)...")

    all_findings: list[Finding] = []
    merged_meta = None
    with tempfile.TemporaryDirectory() as tmp:
        for r in repos:
            dest = github.clone(r, tmp)
            if not dest:
                print(f"    - skip {r.name} (clone failed)")
                continue
            f, m = _scan_one(dest, r.name)
            all_findings += f
            merged_meta = _merge_meta(merged_meta, m)
            tag = f"{len([x for x in f if x.kind=='secret' and not x.is_ghost])} live / {len([x for x in f if x.is_ghost])} ghost"
            print(f"    - {r.name:<32} {tag}")

    card = compute_score(all_findings, merged_meta)
    _emit(identity, card, all_findings, merged_meta, len(repos), out)


def _merge_meta(a, b):
    if a is None:
        return b
    for e in b.emails:
        if e not in a.emails:
            a.emails.append(e)
    a.commit_count += b.commit_count
    a.dominant_utc_offset = a.dominant_utc_offset or b.dominant_utc_offset
    a.likely_active_hours = a.likely_active_hours or b.likely_active_hours
    return a


def _emit(identity, card, findings, meta, repos_scanned, out):
    html = render_report(identity, card, findings, meta, repos_scanned)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n[=] EXPOSURE SCORE: {card.score}/100  [{card.band}]  grade {card.grade}")
    for d in card.drivers:
        print(f"    · {d}")
    print(f"[=] dossier written to: {out}")


def main() -> None:
    p = argparse.ArgumentParser(prog="gitghost", description="GitHub exposure dossier (detection-only).")
    p.add_argument("identity", nargs="?", help="GitHub username or org")
    p.add_argument("--local", help="scan a repo already on disk instead of GitHub")
    p.add_argument("--name", default="local-repo", help="label for --local scans")
    p.add_argument("--limit", type=int, default=30, help="max repos to scan")
    p.add_argument("--out", default="gitghost-dossier.html", help="output HTML path")
    args = p.parse_args()

    if args.local:
        run_local(args.local, args.name, args.out)
    elif args.identity:
        run_identity(args.identity, args.limit, args.out)
    else:
        p.error("provide a GitHub username, or --local <path>")


if __name__ == "__main__":
    main()
