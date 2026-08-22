"""
Tests for gitghost's detection engine.

The point of these is regression safety: the false-positive flood and the ReDoS
bug both slipped in during tuning because nothing checked the behavior. These
lock in what we tuned — real secrets get caught, code does not, and history
recovery works.

Run with:  python -m pytest
"""

import subprocess
import tempfile
import time
from pathlib import Path

from gitghost.rules import scan_text, _looks_like_secret_value
from gitghost.ghost import recover_ghosts
from gitghost.score import compute_score
from gitghost.metadata import MetadataReport


# ---- provider detection: these MUST be caught ----

def test_aws_access_key_detected():
    hits = [f.label for f in scan_text('key = "AKIAIOSFODNN7EXAMPLE"')]
    assert "AWS Access Key ID" in hits


def test_private_key_detected():
    hits = [f.label for f in scan_text("-----BEGIN RSA PRIVATE KEY-----")]
    assert "Private Key Block" in hits


def test_db_connection_detected():
    hits = [f.label for f in scan_text('url = "postgres://u:p@db.host:5432/x"')]
    assert "Database Connection String" in hits


def test_high_entropy_hex_detected():
    hits = [f.label for f in scan_text('api_key = "1abe763d6413b23a104322a3e8c9e0a8"')]
    assert any("High-Entropy" in h for h in hits)


def test_new_provider_keys_detected():
    cases = {
        "Anthropic API Key": 'key = "sk-ant-api03-abcdefghij0123456789ABCDE"',
        "npm Publish Token": 'token = "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
        "Telegram Bot Token": 'tok = "1234567890:AAEabcdefghij0123456789_ABCDEFGHIJK"',
        "SendGrid API Key": 'SG.aBcDeFgHiJkLmNoP012345.aBcDeFgHiJkLmNoP0123456789AbCdEfGhIjKlMnOp',
    }
    for label, line in cases.items():
        hits = [f.label for f in scan_text(line)]
        assert label in hits, f"missed {label}: {line}"


# ---- false positives: these MUST NOT be flagged as secrets ----

FALSE_POSITIVES = [
    "crypto.randomUUID",
    "this.currentToken",
    "process.env.AZURE_OPENAI_API_KEY",
    "models.ForeignKey",
    "document.getElementById",
    "simulated-acs-token",
    "django-insecure-nhri2",
    "self.authorization_header",
    "tlist.token_next_by",
    "ReactDOM.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
]


def test_code_is_not_flagged_as_secret():
    for s in FALSE_POSITIVES:
        assert not _looks_like_secret_value(s), f"false positive on: {s}"


def test_code_lines_produce_no_secret_findings():
    for s in FALSE_POSITIVES:
        secrets = [f for f in scan_text(f'x = {s}') if f.kind == "secret"]
        assert not secrets, f"line produced a secret finding: {s}"


# ---- ReDoS guard: pathological input must return fast ----

def test_no_redos_on_long_input():
    evil = 'api_key = "' + "Aa1" * 500 + '"'
    start = time.time()
    scan_text(evil)
    assert time.time() - start < 2.0, "scan_text is pathologically slow (possible ReDoS)"


# ---- ghost recovery: a deleted secret is still found in history ----

def _run(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


def test_ghost_recovers_deleted_secret():
    with tempfile.TemporaryDirectory() as d:
        _run(["git", "init", "-q"], d)
        _run(["git", "config", "user.email", "a@b.c"], d)
        _run(["git", "config", "user.name", "t"], d)
        secret_file = Path(d) / "config.py"
        secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        _run(["git", "add", "-A"], d)
        _run(["git", "commit", "-qm", "add secret"], d)
        # "delete" it in a later commit
        secret_file.write_text("AWS_KEY = os.environ['AWS_KEY']\n")
        _run(["git", "add", "-A"], d)
        _run(["git", "commit", "-qm", "remove secret"], d)

        ghosts = recover_ghosts(d, "t")
        labels = [g.label for g in ghosts]
        assert "AWS Access Key ID" in labels, "did not recover the deleted key from history"
        assert all(g.is_ghost for g in ghosts)


def test_ghost_carries_commit_context():
    with tempfile.TemporaryDirectory() as d:
        _run(["git", "init", "-q"], d)
        _run(["git", "config", "user.email", "a@b.c"], d)
        _run(["git", "config", "user.name", "t"], d)
        f = Path(d) / "c.py"
        f.write_text('TOKEN = "ghp_' + "A" * 36 + '"\n')
        _run(["git", "add", "-A"], d)
        _run(["git", "commit", "-qm", "oops add token"], d)
        f.write_text("TOKEN = ''\n")
        _run(["git", "add", "-A"], d)
        _run(["git", "commit", "-qm", "remove"], d)

        ghost = next(g for g in recover_ghosts(d, "t") if g.label == "GitHub Personal Access Token")
        assert len(ghost.commit) == 10 and ghost.commit != "dangling"
        assert len(ghost.commit_full) == 40
        assert ghost.commit_author == "t"
        assert ghost.commit_message == "oops add token"
        assert ghost.exposed_days is not None and ghost.exposed_days >= 0
        # deep attribution: real historical path survives, line number kept
        assert ghost.path == "c.py" and ghost.line_no == 1
        assert ghost.entered_date


# ---- cross-repo reuse correlation ----

def test_correlate_flags_reuse_and_leaked_reused():
    from gitghost.rules import scan_text
    from gitghost.score import correlate
    secret_line = 'api_key = "1abe763d6413b23a104322a3e8c9e0a8"\n'
    repo_a, repo_b = [], []
    for i in range(1, 4):
        repo_a += scan_text(secret_line)
        repo_b += scan_text(secret_line)
    repo_b[0].is_ghost = True
    for f in repo_a:
        f.repo = "a"
    for f in repo_b:
        f.repo = "b"
    findings = repo_a + repo_b
    correlate(findings)
    live = [f for f in findings if not f.is_ghost]
    ghosts = [f for f in findings if f.is_ghost]
    assert all(f.reused_in for f in live), "live findings should be marked reused"
    assert all(f.reused_in for f in ghosts)
    assert all(f.leaked_then_reused for f in findings), \
        "ghost + live sharing one fingerprint means the secret is still in use"


# ---- exposure-age weighting ----

def test_old_ghost_scores_higher_than_fresh_one():
    from gitghost.rules import Finding
    from gitghost.metadata import MetadataReport
    fresh = Finding(rule_id="x", label="L", kind="secret", severity=9,
                    line_no=1, redacted="r", fingerprint="fp1", is_ghost=True,
                    exposed_days=5)
    old = Finding(rule_id="x", label="L", kind="secret", severity=9,
                  line_no=1, redacted="r", fingerprint="fp2", is_ghost=True,
                  exposed_days=1200)
    s_fresh = compute_score([fresh], MetadataReport()).score
    s_old = compute_score([old], MetadataReport()).score
    assert s_old > s_fresh, "a leak exposed for years must outweigh a fresh one"


# ---- score sanity ----

def test_score_within_bounds_and_empty_is_minimal():
    empty = compute_score([], MetadataReport())
    assert empty.score == 0 and empty.band == "MINIMAL"


def test_score_handles_none_meta():
    card = compute_score([], None)   # the all-clones-failed path
    assert 0 <= card.score <= 100
