# gitghost
![gitghost exposure dossier](<img width="1060" height="502" alt="image" src="https://github.com/user-attachments/assets/483e855b-6273-4aa9-9972-6cde3778daa4" />
)
Finds secrets in a GitHub account's public repos — including the ones that got committed, then "deleted," but are still sitting in the git history where anyone can read them.

I built this after noticing how often the real leak isn't in someone's current code — it's in a commit from eight months ago that they thought they'd cleaned up. You paste an API key, catch it, delete the line, and move on. The latest version looks fine. But the old commit still has the key, and `git log` hands it to anyone who clones the repo. Most scanners only look at your current files and miss this entirely. gitghost goes digging through history for exactly those, and then rolls everything up into a single exposure score so you can actually tell how bad things are at a glance.

```
$ gitghost cy3erm

EXPOSURE SCORE: 96/100  [CRITICAL]  grade F
  · 7 live secrets in current code
  · 3 "deleted" secrets still recoverable from history
  · author email exposed in commit metadata
  · timezone inferable from commit times (UTC+0530)

dossier written to gitghost-dossier.html
```

You get an HTML report you can open in a browser, not just a wall of terminal text. Every finding links straight to the spot — the exact file and line for live secrets, or the commit for the ones recovered from history — so you're not hunting for where the key actually is. And the report ends with a short how-to-fix guide, because the instinct when you see a leaked key (delete the file, nuke the repo) doesn't actually fix anything: the key's already been cloned. The real fix is to rotate it, then purge it from history, and the report walks you through both.

## Running it

You'll need Python 3.10+ and git. There are no runtime dependencies — it's all standard library.

Install it as a command:

```bash
pipx install gitghost-scanner
gitghost <username>
```

Or just clone and run it without installing:

```bash
git clone https://github.com/cy3erm/gitghost
cd gitghost
python3 -m gitghost <username>
```

If you'd rather not point it at a real person first, there's a demo. It builds a little repo with fake credentials — including one that gets "deleted" a few commits in — so you can watch the history recovery dig it back out:

```bash
bash demo/make_demo_repo.sh /tmp/demo
python3 -m gitghost --local /tmp/demo --name demo
```

A few other flags:

```bash
python3 -m gitghost <username> --limit 50        # cap how many repos
python3 -m gitghost <username> --out report.html # where to write the report
python3 -m gitghost --local ./some-repo          # scan a checkout you have locally
python3 -m gitghost --repo owner/name            # scan just one repo (URL or owner/name)
```

Scanning more than a couple of accounts? Set `GITHUB_TOKEN` (any token works, it doesn't need any scopes) so you don't run into GitHub's 60-requests-an-hour limit for anonymous calls.

## What it looks for

- Cloud and service keys — AWS, GCP, Stripe, GitHub, OpenAI, Slack, private keys, database URLs
- The same keys pulled back out of history after they were removed from the current code
- Metadata you might not realize you're sharing — the email in your commits, and a rough guess at your timezone and working hours from commit timestamps
- Committed `.env` files, internal hostnames, hardcoded private IPs

The score is deliberately one number so you can watch it move — run it, clean things up, run it again. A single live cloud key is enough to put an account in the red by itself; a pile of smaller stuff pushes it up from there.

## Where it draws the line

It only ever reads public repositories — things the account already chose to publish — and it's detection-only. It'll tell you a string *looks like* a credential and leave it at that. It won't try the key against the actual service to see if it still works, because quietly logging into someone else's account isn't the tool's job, and honestly it's not yours either. Findings in the report are shown as fingerprints, not the raw values, so you can share a report without leaking anything.

Point it at yourself first. Most people turn up at least one thing they'd completely forgotten about — I did. (The first time I pushed this repo, GitHub's own secret scanner blocked me because the demo's fake keys looked real enough to trip it. Which is about the best proof of the premise I could ask for.)

## Adding your own detections

The patterns live in `gitghost/rules.py`. Each one is just a name, a regex, a severity, and a line of advice for fixing it — easy to add. If you write a good one, send a PR.

## License

MIT
