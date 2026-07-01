# gitghost 👻

**An exposure dossier for any GitHub identity — including the secrets they thought they deleted.**

Point it at a username. It clones every public repo *with full history*, scans for
leaked credentials, recovers secrets that were "removed" but still live in git history,
reads what your commit metadata quietly reveals about you, and scores the whole thing
as one number: your **Exposure Score**, 0–100.

```
$ gitghost dana-rivera

[=] EXPOSURE SCORE: 96/100  [CRITICAL]  grade F
    · 7 live secrets in current code
    · 3 'deleted' secrets still recoverable from history
    · real author email exposed (dana.rivera@gmail.com)
    · timezone inferable from commit times (UTC+0530)
[=] dossier written to: gitghost-dossier.html
```

The output is a shareable HTML dossier, not terminal noise.

---

## Why this is different

Secret scanners like TruffleHog and gitleaks grep your *current* files. Two things
almost nobody does, and they're the whole point of gitghost:

**1. It recovers the "deleted" ones.** When you commit a secret, panic, and remove
the line (or force-push), the blob usually survives — reachable in an old commit, or
orphaned but not yet garbage-collected. gitghost diffs every historical blob against
your current tree. Anything holding a secret that's *gone from HEAD but still in
history* is a **ghost**: you think it's gone, and to anyone who clones the repo, it's
one command away.

**2. It gives you one number.** The Exposure Score turns a pile of findings into a
credit-score-for-how-much-you-leak that a non-security person understands instantly —
and instinctively wants to compare.

## Install

```bash
git clone https://github.com/<you>/gitghost && cd gitghost
python3 -m gitghost <github-username>
```

Zero runtime dependencies — standard library only. Set `GITHUB_TOKEN` to raise the API
rate limit from 60/hr to 5000/hr.

```bash
python3 -m gitghost torvalds                 # scan a public identity
python3 -m gitghost --local ./my-repo        # scan a repo already on disk
python3 -m gitghost yourname --limit 50 --out report.html
```

Try it on the built-in demo:

```bash
bash demo/make_demo_repo.sh /tmp/demo
python3 -m gitghost --local /tmp/demo --name billing-service
```

## What it surfaces

| | |
|---|---|
| **Live secrets** | AWS / GCP / Stripe / GitHub / OpenAI / Slack keys, private keys, DB connection strings, high-entropy assignments |
| **Ghost secrets** | the same, recovered from history after being "deleted" |
| **Metadata leaks** | real author email, timezone + active hours inferred from commit times |
| **Infra breadcrumbs** | internal hostnames, hardcoded private IPs, committed `.env` files |

## Scope & ethics — read this

gitghost is built to be the impressive version *and* the defensible one. That's a
design choice baked into the code, not a disclaimer:

- **Detection-only.** It reports that a string matches a credential format and stops.
  It **never** authenticates a discovered secret against its provider to check if it's
  "live" — confirming someone else's key by using it is unauthorized access.
- **Public repos only.** It reads data the owner already chose to publish. It never
  touches private repositories.
- **Redacted output.** Findings are shown as `abcd••••••••wxyz`, never in full.
- **Meant for auditing yourself, your org, or a target you're authorized to assess.**

Run it on your own identity first. You'll probably find a stale token, and that's the
point.

## The launch (if you're posting this)

A tool launch gets stars; a tool launch *with original research* gets the front page.
Run gitghost across a set of well-known **public** orgs, aggregate the numbers, and
publish a short "State of GitHub Exposure" writeup: average Exposure Score, how many
"deleted" secrets are still recoverable, how far back leaks persist. Everything you
report is already public by definition, and the framing — *"here's how much leaks from
one identity, and I never touched anyone's systems to prove it"* — is what makes it land.

## Architecture

```
gitghost/
  github.py     enumerate + clone public repos (history included)
  scanner.py    walk the working tree, scan files
  ghost.py      recover secrets from history that are gone from HEAD  ← signature
  rules.py      provider signatures + entropy engine (detection-only)
  metadata.py   author email + timezone/activity inference
  score.py      the Exposure Score model
  report.py     the shareable HTML dossier
  cli.py        pipeline
```

## Roadmap

- **Watch mode** — monitor your own identity and alert the instant new exposure appears, fast enough to rotate before anyone finds it.
- **Time Machine view** — animated timeline of when each secret entered and was "deleted."
- **Remediation bundle** — generate the exact `git filter-repo` purge + rotation steps per finding.

## License

MIT.
