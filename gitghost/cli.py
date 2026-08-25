import argparse
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

from . import __version__, github
from .banner import print_banner
from .ghost import recover_force_pushed, recover_ghosts
from .metadata import MetadataReport, analyze_metadata
from .report import render_report
from .rules import Finding, scan_text
from .scanner import HOT_FILES, scan_repo
from .score import ScoreCard, compute_score
from .ui import detail, die, err, info, ok, warn


def _scan_one(root: str, name: str) -> tuple[list[Finding], MetadataReport]:
    findings = list(scan_repo(root, name).findings)
    findings += recover_ghosts(root, name)
    return findings, analyze_metadata(root)


def _write_report(identity: str, card: ScoreCard, findings: list[Finding],
                  meta: MetadataReport | None, repos_scanned: int, out: str,
                  profile: github.Profile | None = None) -> None:
    html = render_report(identity, card, findings, meta, repos_scanned, profile=profile)
    try:
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
    except OSError as e:
        die(f"could not write report to {out!r}: {e.strerror}",
            "check that the directory exists and is writable (or pass a different --out)")


def _finish(identity: str, card: ScoreCard, findings: list[Finding],
            meta: MetadataReport | None, repos_scanned: int, out: str,
            profile: github.Profile | None = None) -> None:
    _write_report(identity, card, findings, meta, repos_scanned, out, profile=profile)
    print()
    ok(f"exposure score: {card.score}/100  [{card.band}, grade {card.grade}]")
    for d in card.drivers:
        detail(d)
    ok(f"dossier written to {out}")


def run_local(path: str, name: str, out: str) -> None:
    if not os.path.isdir(path):
        die(f"no such directory: {path!r}",
            "pass the path to a checkout on disk (or use --repo/--org for GitHub repos)")
    info(f"scanning local repo: {name}")
    findings, meta = _scan_one(path, name)
    card = compute_score(findings, meta)
    _finish(name, card, findings, meta, 1, out)


def run_repo(url: str, out: str) -> None:
    try:
        repo = github.repo_from_url(url)
    except ValueError as e:
        die(str(e))
    info(f"cloning + scanning single repo: {repo.full_name}")
    with tempfile.TemporaryDirectory() as tmp:
        dest = github.clone(repo, tmp)
        if not dest:
            die(f"could not clone {repo.clone_url}",
                "the repo may be private, renamed/deleted, or unreachable from here")
        findings, meta = _scan_one(dest, repo.name)
        for finding in findings:
            finding.repo_url = repo.html_url
        card = compute_score(findings, meta)
        _finish(repo.full_name, card, findings, meta, 1, out)


def _scan_repos(repos: list[github.Repo], jobs: int,
                push_shas: dict[str, list[tuple[str, str]]] | None = None,
                ) -> tuple[list[Finding], list[MetadataReport]]:
    """Clone + scan a batch of repos in parallel; returns findings and metas.

    `push_shas` maps owner/repo -> [(commit_sha, pushed_at), ...] from the
    user's recent PushEvents; those SHAs are fetched and scanned even when
    a force-push removed them from the branch history.
    """
    all_findings: list[Finding] = []
    metas: list[MetadataReport] = []
    push_shas = push_shas or {}

    def work(repo: github.Repo):
        dest = github.clone(repo, tmp)
        if not dest:
            return repo, None
        f, m = _scan_one(dest, repo.name)
        orphans = push_shas.get(repo.full_name)
        if orphans:
            f += recover_force_pushed(dest, [s for s, _ in orphans], repo.name)
        for finding in f:
            finding.repo_url = repo.html_url
        return repo, (f, m)

    with tempfile.TemporaryDirectory() as tmp:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for repo, res in pool.map(work, repos):
                if res is None:
                    warn(f"clone failed for {repo.full_name}, skipping "
                         "(private, deleted, or network issue)")
                    continue
                f, m = res
                all_findings += f
                metas.append(m)
                live = len([x for x in f if x.kind == "secret" and not x.is_ghost])
                ghost = len([x for x in f if x.is_ghost])
                forced = len([x for x in f if x.force_pushed])
                tag = f"{live} live / {ghost} ghost"
                if forced:
                    tag += f" / {forced} force-pushed"
                detail(f"{repo.name:<32} {tag}")
    return all_findings, metas


def _scan_gists(identity: str) -> list[Finding]:
    """Pull every public gist of an identity and scan the raw file contents.

    Also walks each gist's revision history: secrets that were edited out of
    a gist stay readable at their old revision URLs — gist ghosts.
    """
    try:
        gists = github.list_public_gists(identity)
    except github.GitHubError as e:
        warn(f"gist scan skipped: {e}")
        return []
    findings: list[Finding] = []
    for g in gists:
        current_fps = _scan_gist_files(g.files, g, findings)
        # revisions older than the current version may hold deleted secrets
        revs = [h for h in (g.history or [])
                if isinstance(h, dict) and h.get("version")]
        if not revs and g.history == [] and g.files:
            try:  # list endpoint omitted history — fetch the full gist once
                revs = [h for h in (github.get_gist(g.id).history or [])
                        if isinstance(h, dict) and h.get("version")]
            except github.GitHubError:
                revs = []
        for h in revs[1:]:  # history is newest-first; [0] is the current version
            try:
                rev = github.get_gist_revision(g.id, h["version"])
            except github.GitHubError:
                continue
            when = (h.get("committed_at") or "")[:10]
            for f in _scan_gist_files(rev.get("files", {}), g, findings,
                                      revision=h["version"], when=when):
                if f.fingerprint in current_fps:
                    continue  # never actually deleted
                f.is_ghost = True
                f.entered_date = f.entered_date or when
                findings.append(f)
    return findings


def _scan_gist_files(files: dict, g: github.Gist, findings: list[Finding],
                     revision: str = "", when: str = "") -> set[str]:
    """Scan one gist file-map; returns fingerprints found (for dedupe)."""
    seen: set[str] = set()
    label = f"gist:{g.id}" + (f"/{revision[:7]}" if revision else "")
    for fname, meta in files.items():
        raw_url = (meta or {}).get("raw_url")
        if not raw_url:
            continue
        text = github.fetch_gist_file(raw_url)
        if not text:
            continue
        for f in scan_text(text):
            f.repo = label
            f.path = fname
            f.repo_url = g.html_url
            f.entered_date = when
            if fname.startswith(".env") or fname in HOT_FILES:
                f.severity = min(10, f.severity + 1)
            seen.add(f.fingerprint)
            findings.append(f)
    return seen


def run_identity(identity: str, limit: int, out: str, jobs: int = 4,
                 gists: bool = True, network: bool = False) -> None:
    profile = None
    try:
        profile = github.get_user(identity)
        _show_profile(profile)
    except github.GitHubError:
        pass  # profile is enrichment; never block the scan on it

    info(f"enumerating public repos for @{identity} ...")
    try:
        repos = github.list_public_repos(identity, limit=limit)
        # cap the crawl so one popular account doesn't turn into a 10k-repo scan
        graph = github.list_network(identity)[:50] if network else []
    except github.GitHubError as e:
        die(f"GitHub API error: {e}")

    info("checking recent push events for force-pushed-away commits ...")
    push_shas = github.collect_pushed_commits(identity)
    if push_shas:
        total = sum(len(v) for v in push_shas.values())
        info(f"{total} recent commit(s) across {len(push_shas)} repo(s) "
             "will be checked for force-pushed secrets")

    if not repos:
        if not gists and not graph:
            die(f"no public repos found for @{identity}",
                "the account may not exist, have no public repos, or only private ones")
        warn("no public repos found; falling back to gists"
             + (" / network" if graph else ""))

    if repos:
        info(f"{len(repos)} repos. cloning + scanning in parallel "
             "(history included for ghost recovery) ...")
        all_findings, metas = _scan_repos(repos, jobs, push_shas=push_shas)
    else:
        all_findings, metas = [], []
    repos_scanned = len(repos)

    if network:
        info(f"expanding network: crawling {len(graph)} followers/following ...")
        nf, nm, ncrawled = _scan_identities(graph, limit, jobs, gists)
        all_findings += nf
        metas += nm
        repos_scanned += ncrawled

    if gists:
        info(f"crawling public gists of @{identity} (including revision history) ...")
        gist_findings = _scan_gists(identity)
        if gist_findings:
            ok(f"{len(gist_findings)} finding(s) recovered from gists")
        all_findings += gist_findings

    merged = merge_metas(metas)
    card = compute_score(all_findings, merged)
    merged = merge_metas(metas)
    card = compute_score(all_findings, merged)
    _finish(identity, card, all_findings, merged, repos_scanned, out,
            profile=profile)


def _show_profile(p: github.Profile) -> None:
    bits = [b for b in (p.name, p.company, p.location) if b]
    if bits:
        detail("profile: " + " · ".join(bits))
    for label, val in (("blog", p.blog), ("profile email", p.email),
                       ("twitter", "@" + p.twitter if p.twitter else "")):
        if val:
            detail(f"{label}: {val}")
    if p.created_at:
        detail(f"on GitHub since {p.created_at} · {p.followers} followers · "
               f"{p.public_repos} public repos")


def _scan_identities(logins: list[str], limit: int, jobs: int,
                     gists: bool) -> tuple[list[Finding], list[MetadataReport], int]:
    """Repos (+gists) of every login in the list; returns findings, metas, repo count."""
    all_findings: list[Finding] = []
    metas: list[MetadataReport] = []
    repo_count = 0
    for login in logins:
        try:
            repos = github.list_public_repos(login, limit=limit)
        except github.GitHubError:
            continue
        if not repos:
            continue
        info(f"crawling @{login}: {len(repos)} public repo{'s' if len(repos) != 1 else ''}")
        repo_count += len(repos)
        mf, mm = _scan_repos(repos, jobs)
        all_findings += mf
        metas += mm
        if gists:
            gf = _scan_gists(login)
            if gf:
                ok(f"{len(gf)} finding(s) recovered from @{login}'s gists")
            all_findings += gf
    return all_findings, metas, repo_count


def run_org(org: str, limit: int, out: str, jobs: int = 4,
            members: bool = False, gists: bool = False) -> None:
    info(f"enumerating public repos of org '{org}' ...")
    try:
        repos = github.list_org_repos(org, limit=limit)
        member_logins = github.list_public_members(org) if members else []
    except github.GitHubError as e:
        die(f"GitHub API error: {e}")
    info(f"{len(repos)} org repos"
         + (f", {len(member_logins)} public members to crawl" if members else "")
         + ".")

    all_findings, metas = _scan_repos(repos, jobs)

    if members:
        mf, mm, _ = _scan_identities(member_logins, limit, jobs, gists)
        all_findings += mf
        metas += mm

    merged = merge_metas(metas)
    card = compute_score(all_findings, merged)
    _finish(f"org:{org}", card, all_findings, merged, len(repos), out)


def merge_metas(metas: list[MetadataReport]) -> MetadataReport:
    """Fold per-repo metadata reports into one."""
    merged = MetadataReport()
    for m in metas:
        merged.emails += [e for e in m.emails if e not in merged.emails]
        merged.noreply_emails += [e for e in m.noreply_emails if e not in merged.noreply_emails]
        merged.commit_count += m.commit_count
        merged.dominant_utc_offset = merged.dominant_utc_offset or m.dominant_utc_offset
        merged.likely_active_hours = merged.likely_active_hours or m.likely_active_hours
    return merged


# ---------------------------------------------------------------- argparse

EPILOG = """\
examples:
  gitghost <username>                 scan a user's public repos (+ gists)
  gitghost <username> --network       also crawl followers/following
  gitghost --org acme --members       scan an org and its public members
  gitghost --repo owner/name          scan one repo (URL or owner/name)
  gitghost --local ./some-repo        scan a checkout already on disk
"""


def positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gitghost",
        description="GitHub exposure dossier: finds secrets in a GitHub account's public "
                    "repos — including ones 'deleted' but still recoverable from git history.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"gitghost {__version__}")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="guided mode: pick a target and go (also default when run with no arguments)")
    p.add_argument("identity", nargs="?", metavar="USER",
                   help="GitHub username to audit")
    p.add_argument("--repo", metavar="REPO", help="scan a single repo by URL or owner/name")
    p.add_argument("--local", metavar="PATH", help="scan a repo already on disk instead of GitHub")
    p.add_argument("--name", default="local-repo", help="label for --local scans (default: %(default)s)")
    p.add_argument("--org", metavar="ORG", help="scan an organization's public repos")
    p.add_argument("--members", action="store_true",
                   help="with --org: also crawl every public member's repos (and gists with --gists)")
    p.add_argument("--network", action="store_true",
                   help="with USER: also crawl every follower/following account's public repos")
    p.add_argument("--gists", action="store_true", default=True,
                   help="also scan public gists (default: on)")
    p.add_argument("--no-gists", dest="gists", action="store_false",
                   help="skip gist scanning")
    p.add_argument("--limit", type=positive_int, default=30,
                   help="max repos to scan per identity (default: %(default)s)")
    p.add_argument("--jobs", type=positive_int, default=4,
                   help="parallel clones/scans (default: %(default)s)")
    p.add_argument("--out", default="gitghost-dossier.html",
                   help="output HTML path (default: %(default)s)")
    p.add_argument("--debug", action="store_true",
                   help="show full tracebacks on unexpected errors")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # bare launch (or -i) on a terminal opens the interactive console
    if args.interactive or (len(sys.argv) == 1 and sys.stdin.isatty()
                            and sys.stdout.isatty()):
        try:
            from .console import run_console
            print_banner()
            run_console(debug=args.debug)
        except KeyboardInterrupt:
            err("interrupted")
            raise SystemExit(130) from None
        return

    try:
        _run(args)
    except KeyboardInterrupt:
        err("interrupted — partial results were discarded, no report written")
        raise SystemExit(130) from None
    except Exception as e:  # unexpected: keep the traceback behind --debug
        if args.debug:
            raise
        err(f"unexpected failure: {type(e).__name__}: {e}")
        hint = "re-run with --debug for the full traceback, or open an issue at " \
               "https://github.com/cy3erm/gitghost/issues"
        print(f"    {hint}", file=sys.stderr)
        raise SystemExit(1) from None


def _run(args: argparse.Namespace) -> None:
    modes = sum(bool(m) for m in (args.identity, args.repo, args.local, args.org))
    if modes > 1:
        die("pick exactly one target: USER, --repo, --org, or --local")
    if not modes:
        err("nothing to scan")
        print("    start the interactive console by running gitghost with no "
              "arguments, or pass a target:\n", file=sys.stderr)
        build_parser().print_usage(file=sys.stderr)
        raise SystemExit(2)

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


if __name__ == "__main__":
    main()
