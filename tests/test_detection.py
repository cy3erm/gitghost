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


# ---- score sanity ----

def test_score_within_bounds_and_empty_is_minimal():
    empty = compute_score([], MetadataReport())
    assert empty.score == 0 and empty.band == "MINIMAL"


def test_score_handles_none_meta():
    card = compute_score([], None)   # the all-clones-failed path
    assert 0 <= card.score <= 100
