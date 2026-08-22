import argparse
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

from . import github
from .ghost import recover_ghosts
from .metadata import MetadataReport, analyze_metadata
from .report import render_report
from .rules import Finding, scan_text
from .scanner import HOT_FILES, scan_repo
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


def run_repo(url: str, out: str) -> None:
    try:
        repo = github.repo_from_url(url)
    except ValueError as e:
        sys.exit(f"[!] {e}")
    print(f"[*] scanning single repo: {repo.full_name}")
    with tempfile.TemporaryDirectory() as tmp:
        dest = github.clone(repo, tmp)
        if not dest:
            sys.exit(f"[!] could not clone {repo.clone_url} (private, renamed, or network issue)")
        findings, meta = _scan_one(dest, repo.name)
        for finding in findings:
            finding.repo_url = repo.html_url
        card = compute_score(findings, meta)
        _emit(repo.full_name, card, findings, meta, 1, out)


def _scan_repos(repos: list, jobs: int) -> tuple[list[Finding], list]:
    """Clone + scan a batch of repos in parallel; returns findings and metas."""
    all_findings: list[Finding] = []
    metas: list = []

    def _work(repo):
        dest = github.clone(repo, tmp)
        if not dest:
            return repo, None
        f, m = _scan_one(dest, repo.name)
        for finding in f:
            finding.repo_url = repo.html_url
        return repo, (f, m)

    with tempfile.TemporaryDirectory() as tmp:
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            for repo, res in pool.map(_work, repos):
                if res is None:
                    print(f"    - skip {repo.name} (clone failed)")
                    continue
                f, m = res
                all_findings += f
                metas.append(m)
                tag = f"{len([x for x in f if x.kind=='secret' and not x.is_ghost])} live / {len([x for x in f if x.is_ghost])} ghost"
                print(f"    - {repo.name:<32} {tag}")
    return all_findings, metas


def _scan_gists(identity: str) -> list[Finding]:
    """Pull every public gist of an identity and scan the raw file contents."""
    try:
        gists = github.list_public_gists(identity)
    except Exception:
        return []
    findings: list[Finding] = []
    for g in gists:
        for fname, meta in g.files.items():
            raw_url = (meta or {}).get("raw_url")
            if not raw_url:
                continue
            text = github.fetch_gist_file(raw_url)
            if not text:
                continue
            for f in scan_text(text):
                f.repo = f"gist:{g.id}"
                f.path = fname
                f.repo_url = g.html_url
                if fname.startswith(".env") or fname in HOT_FILES:
                    f.severity = min(10, f.severity + 1)
                findings.append(f)
    return findings


def run_identity(identity: str, limit: int, out: str, jobs: int = 4,
                 gists: bool = True, network: bool = False) -> None:
    print(f"[*] enumerating public repos for @{identity} ...")
    try:
        repos = github.list_public_repos(identity, limit=limit)
        # cap the crawl so one popular account doesn't turn into a 10k-repo scan
        graph = github.list_network(identity)[:50] if network else []
    except Exception as e:
        sys.exit(f"[!] could not reach GitHub API: {e}\n    (set GITHUB_TOKEN to raise rate limits)")
    if not repos and not gists and not graph:
        sys.exit(f"[!] no public repos found for @{identity}")
    print(f"[*] {len(repos)} repos. cloning + scanning in parallel (history included for ghost recovery)...")

    all_findings, metas = _scan_repos(repos, jobs)
    repos_scanned = len(repos)

    if network:
        print(f"[*] expanding network: {len(graph)} followers/following to crawl ...")
        nf, nm, _ = _scan_identities(graph, limit, jobs, gists)
        all_findings += nf
        metas += nm
        repos_scanned += ncount

    if gists:
        print(f"[*] crawling public gists of @{identity} ...")
        gist_findings = _scan_gists(identity)
        if gist_findings:
            print(f"    - {len(gist_findings)} finding(s) recovered from gists")
        all_findings += gist_findings

    merged_meta = None
    for m in metas:
        merged_meta = _merge_meta(merged_meta, m)
    card = compute_score(all_findings, merged_meta)
    _emit(identity, card, all_findings, merged_meta, repos_scanned, out)


def _scan_identities(logins: list[str], limit: int, jobs: int,
                     gists: bool) -> tuple[list[Finding], list, int]:
    """Repos (+gists) of every login in the list; prints progress per identity."""
    all_findings: list[Finding] = []
    metas: list = []
    repo_count = 0
    for login in logins:
        try:
            repos = github.list_public_repos(login, limit=limit)
        except Exception:
            continue
        if not repos:
            continue
        print(f"[*] crawling @{login}: {len(repos)} public repo{'s' if len(repos)!=1 else ''} ...")
        repo_count += len(repos)
        mf, mm = _scan_repos(repos, jobs)
        all_findings += mf
        metas += mm
        if gists:
            gf = _scan_gists(login)
            if gf:
                print(f"    - {len(gf)} finding(s) recovered from gists")
            all_findings += gf
    return all_findings, metas, repo_count


def run_org(org: str, limit: int, out: str, jobs: int = 4,
            members: bool = False, gists: bool = False) -> None:
    print(f"[*] enumerating public repos of org '{org}' ...")
    try:
        repos = github.list_org_repos(org, limit=limit)
        member_logins = github.list_public_members(org) if members else []
    except Exception as e:
        sys.exit(f"[!] could not reach GitHub API: {e}\n    (set GITHUB_TOKEN to raise rate limits)")
    print(f"[*] {len(repos)} org repos"
          + (f", {len(member_logins)} public members to crawl" if members else "")
          + ".")

    all_findings, metas = _scan_repos(repos, jobs)

    if members:
        mf, mm, _ = _scan_identities(member_logins, limit, jobs, gists)
        all_findings += mf
        metas += mm

    merged_meta = None
    for m in metas:
        merged_meta = _merge_meta(merged_meta, m)
    card = compute_score(all_findings, merged_meta)
    _emit(f"org:{org}", card, all_findings, merged_meta, len(repos), out)


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
    from . import __version__
    p.add_argument("--version", action="version", version=f"gitghost {__version__}")
    p.add_argument("identity", nargs="?", help="GitHub username or org")
    p.add_argument("--repo", help="scan a single repo by URL or owner/name")
    p.add_argument("--local", help="scan a repo already on disk instead of GitHub")
    p.add_argument("--name", default="local-repo", help="label for --local scans")
    p.add_argument("--org", metavar="ORG", help="scan an organization's public repos")
    p.add_argument("--members", action="store_true",
                   help="with --org: also crawl every public member's repos (and gists with --gists)")
    p.add_argument("--network", action="store_true",
                   help="with a username: crawl every follower/following account's public repos")
    p.add_argument("--gists", action="store_true", default=True,
                   help="also scan public gists (default: on for identity scans)")
    p.add_argument("--no-gists", dest="gists", action="store_false",
                   help="skip gist scanning")
    p.add_argument("--limit", type=int, default=30, help="max repos to scan per identity")
    p.add_argument("--jobs", type=int, default=4, help="parallel clones/scans")
    p.add_argument("--out", default="gitghost-dossier.html", help="output HTML path")
    args = p.parse_args()

    from .banner import print_banner
    print_banner()

    if args.local:
        run_local(args.local, args.name, args.out)
    elif args.repo:
        run_repo(args.repo, args.out)
    elif args.org:
        run_org(args.org, args.limit, args.out, jobs=args.jobs,
                members=args.members, gists=args.gists)
    elif args.identity:
        run_identity(args.identity, args.limit, args.out, jobs=args.jobs,
                     gists=args.gists, network=args.network)
    else:
        p.error("provide a GitHub username, --org <name>, --repo <url>, or --local <path>")


if __name__ == "__main__":
    main()
