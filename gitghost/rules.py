"""
Detection rules for gitghost.

Two layers:
  1. High-confidence provider signatures (regex) — a leaked AWS key looks like
     nothing else, so these are near-zero false positive.
  2. Generic high-entropy strings assigned to secret-ish variable names — this
     catches the long tail (custom tokens, DB passwords) that no signature covers.

IMPORTANT: gitghost is DETECTION-ONLY. Nothing in this file, or anywhere in the
tool, ever transmits a discovered secret to its provider to check if it is
"live". Confirming someone else's key by authenticating with it is unauthorized
access. We report format + entropy confidence and stop there.
"""

import hashlib
import math
import re
from dataclasses import dataclass, field


# severity is 1-10; it feeds the Exposure Score. A cloud root credential is a
# categorically worse leak than a Slack webhook, and the score should say so.
@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    pattern: re.Pattern
    severity: int
    kind: str = "secret"          # secret | pii | infra
    remediation: str = ""


PROVIDER_RULES: list[Rule] = [
    Rule("aws-access-key-id", "AWS Access Key ID",
         re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 9,
         remediation="Deactivate the key in IAM immediately, then rotate. Assume it is compromised the moment it touched a public commit."),
    Rule("aws-secret-key", "AWS Secret Access Key",
         re.compile(r"(?i)aws.{0,20}?(secret|sk).{0,30}?['\"=:\s]([A-Za-z0-9/+=]{40})\b"), 10,
         remediation="Rotate the secret key and audit CloudTrail for use since the commit date."),
    Rule("gcp-service-account", "GCP Service Account Key",
         re.compile(r"\"type\":\s*\"service_account\""), 9,
         remediation="Delete and regenerate the service-account key in GCP IAM."),
    Rule("github-pat", "GitHub Personal Access Token",
         re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), 8,
         remediation="Revoke the token under GitHub Settings > Developer settings > Tokens."),
    Rule("github-oauth", "GitHub OAuth / App Token",
         re.compile(r"\b(gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"), 8,
         remediation="Revoke the token and rotate the associated OAuth app secret."),
    Rule("stripe-secret", "Stripe Secret Key",
         re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), 9,
         remediation="Roll the key in the Stripe dashboard; check for unexpected charges."),
    Rule("slack-token", "Slack Token",
         re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 6,
         remediation="Revoke the token in the Slack admin console."),
    Rule("slack-webhook", "Slack Incoming Webhook",
         re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]+"), 4,
         remediation="Delete the webhook; anyone with the URL can post to the channel."),
    Rule("google-api-key", "Google API Key",
         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 6,
         remediation="Restrict or regenerate the key in the Google Cloud console."),
    Rule("openai-key", "OpenAI API Key",
         re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"), 7,
         remediation="Revoke the key at platform.openai.com; you are billed for its usage."),
    Rule("private-key", "Private Key Block",
         re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), 9,
         remediation="Treat the key pair as burned. Generate a new pair and rotate every place the public key was trusted."),
    Rule("jwt", "JSON Web Token",
         re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 5,
         remediation="If this is a signing secret or long-lived token, rotate it. Decode (don't trust) to confirm scope."),
    Rule("db-connection", "Database Connection String",
         re.compile(r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"), 8,
         remediation="Rotate the database password; the credential and host are both exposed."),
]

# infra breadcrumbs — individually dull, collectively a map of someone's setup
INFRA_RULES: list[Rule] = [
    Rule("internal-host", "Internal Hostname", kind="infra", severity=2,
         pattern=re.compile(r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(internal|corp|intranet|lan)\b"),
         remediation="Scrub internal DNS names from committed config; they reveal network topology."),
    Rule("private-ip", "Hardcoded Private IP", kind="infra", severity=1,
         pattern=re.compile(r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
         remediation="Move host addresses to environment config rather than source."),
]

SECRETISH_ASSIGN = re.compile(
    r"""(?ix)
    (?P<name>\w*(secret|token|passwd|password|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth)\w*)
    \s*[:=]\s*
    ['"]?(?P<val>[A-Za-z0-9/+_=.\-]{16,})['"]?
    """
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass
class Finding:
    rule_id: str
    label: str
    kind: str
    severity: int
    line_no: int
    redacted: str           # what we show — never the raw secret in reports
    entropy: float = 0.0
    remediation: str = ""
    # provenance is filled in by the scanner/ghost layer
    repo: str = ""
    path: str = ""
    commit: str = ""
    is_ghost: bool = False   # True == recovered from history, gone from HEAD


# Non-secret format prefixes. AKIA / ghp_ / sk_live_ etc. are identifiers, not
# secret material — they appear in every key of that type — so showing them is
# safe and helps you recognize your own leak. The entropy *after* the prefix is
# the actual secret, and we never show that.
_SAFE_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
                  "sk_live_", "sk-", "AIza", "xoxb-", "xoxp-", "eyJ")


def _fingerprint(value: str) -> str:
    """
    A one-way summary of a finding: a safe prefix (if any), a length, and the
    first bytes of a SHA-256. It is NOT reversible — the report never carries
    recoverable key material, so it's safe to screenshot or paste into a PR.

    To confirm a finding is a key you recognize, hash your copy and compare:
        python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:10])" 'YOUR_KEY'
    """
    v = value.strip().strip("'\"")
    if not v:
        return ""
    digest = hashlib.sha256(v.encode("utf-8", "ignore")).hexdigest()[:10]
    prefix = ""
    for p in _SAFE_PREFIXES:
        if v.startswith(p):
            prefix = f"{p}… "
            break
    return f"{prefix}{len(v)} chars · fp:{digest}"


def scan_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if len(line) > 4000:            # skip minified blobs / lockfiles
            continue
        matched_spans: list[tuple[int, int]] = []
        for rule in (*PROVIDER_RULES, *INFRA_RULES):
            for m in rule.pattern.finditer(line):
                raw = m.group(0)
                matched_spans.append(m.span())
                findings.append(Finding(
                    rule_id=rule.id, label=rule.label, kind=rule.kind,
                    severity=rule.severity, line_no=i, redacted=_fingerprint(raw),
                    entropy=round(shannon_entropy(raw), 2),
                    remediation=rule.remediation,
                ))
        # generic entropy pass — only fires when the VALUE actually looks like a
        # credential (dense, high-entropy), not just any code assigned to a
        # secret-ish variable name. Skips anything a specific rule already caught.
        for m in SECRETISH_ASSIGN.finditer(line):
            val = m.group("val")
            vstart = m.start("val")
            already = any(s <= vstart < e for s, e in matched_spans)
            if not already and _looks_like_secret_value(val):
                findings.append(Finding(
                    rule_id="generic-high-entropy",
                    label="High-Entropy Secret (generic)", kind="secret",
                    severity=5, line_no=i, redacted=_fingerprint(val),
                    entropy=round(shannon_entropy(val), 2),
                    remediation="Confirm whether this is a real credential; if so rotate and move it to a secret manager.",
                ))
    return findings


_PLACEHOLDER = re.compile(r"(?i)(xxx|placeholder|example|changeme|your[_-]?|dummy|sample|<.*>|\.\.\.|test1234|000000|insecure)")


def _looks_like_placeholder(v: str) -> bool:
    return bool(_PLACEHOLDER.search(v)) or len(set(v)) <= 4


# A code identifier / expression, not a secret: dotted access, camelCase,
# function calls, env lookups, file paths. Real credentials don't look like this.
_CODE_PUNCT = re.compile(r"[\s.()\[\]{}<>/\\:;,]")
_KEYISH = re.compile(r"^[A-Za-z0-9_\-+=]+$")


def _looks_like_secret_value(val: str) -> bool:
    v = val.strip().strip("'\"")
    if len(v) < 20 or _looks_like_placeholder(v):
        return False
    if _CODE_PUNCT.search(v):            # has code punctuation/paths → it's code
        return False
    if not _KEYISH.fullmatch(v):         # keys are a compact token, not an expression
        return False
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    if not (has_digit and has_alpha):    # real keys mix letters and digits
        return False
    return shannon_entropy(v) >= 3.5
