import hashlib
import math
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    pattern: re.Pattern
    severity: int
    kind: str = "secret"
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
    Rule("anthropic-key", "Anthropic API Key",
         re.compile(r"\bsk-ant-[A-Za-z0-9_-]{24,}\b"), 8,
         remediation="Revoke the key in the Anthropic console; you are billed for its usage."),
    Rule("npm-token", "npm Publish Token",
         re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 8,
         remediation="Revoke the token at npmjs.com > Access Tokens; it can publish packages as you."),
    Rule("pypi-token", "PyPI Upload Token",
         re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b"), 7,
         remediation="Revoke the token on pypi.org; it can upload packages under your project."),
    Rule("telegram-bot", "Telegram Bot Token",
         re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), 6,
         remediation="Revoke the token via @BotFather (/revoke); anyone holding it controls the bot."),
    Rule("discord-webhook", "Discord Webhook URL",
         re.compile(r"https://discord(app)?\.com/api/webhooks/\d{15,}/[A-Za-z0-9_-]+"), 5,
         remediation="Delete the webhook; anyone with the URL can post to the channel."),
    Rule("discord-bot", "Discord Bot Token",
         re.compile(r"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b"), 7,
         remediation="Reset the token in the Discord developer portal and redeploy the bot."),
    Rule("sendgrid-key", "SendGrid API Key",
         re.compile(r"\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b"), 7,
         remediation="Delete the key in SendGrid settings; leaked keys are used for phishing spam."),
    Rule("mailgun-key", "Mailgun API Key",
         re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), 5,
         remediation="Rotate the key in the Mailgun control panel."),
    Rule("twilio-key", "Twilio API Key",
         re.compile(r"\bSK[0-9a-f]{32}\b"), 4,
         remediation="Rotate the key in the Twilio console and check usage for anomalies."),
    Rule("azure-storage", "Azure Storage Account Key",
         re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}"), 8,
         remediation="Regenerate the storage account key and move to SAS tokens or managed identity."),
    Rule("huggingface-token", "Hugging Face Token",
         re.compile(r"\bhf_[A-Za-z0-9]{34}\b"), 6,
         remediation="Revoke the token at huggingface.co/settings/tokens."),
]


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
    redacted: str
    entropy: float = 0.0
    remediation: str = ""

    repo: str = ""
    path: str = ""
    commit: str = ""
    is_ghost: bool = False
    repo_url: str = ""

    fingerprint: str = ""
    commit_author: str = ""
    commit_message: str = ""
    commit_full: str = ""
    entered_date: str = ""
    exposed_days: int | None = None
    reused_in: list[str] = field(default_factory=list)
    leaked_then_reused: bool = False


_SAFE_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
                  "sk_live_", "sk-ant-", "sk-", "AIza", "xoxb-", "xoxp-",
                  "npm_", "pypi-", "SG.", "hf_", "shpat_", "dop_v1_", "eyJ")


def _digest(value: str) -> str:
    v = value.strip().strip("'\"")
    if not v:
        return ""
    return hashlib.sha256(v.encode("utf-8", "ignore")).hexdigest()[:10]


def _fingerprint(value: str) -> str:
    v = value.strip().strip("'\"")
    if not v:
        return ""
    digest = _digest(value)
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
        if len(line) > 4000:
            continue
        matched_spans: list[tuple[int, int]] = []
        for rule in (*PROVIDER_RULES, *INFRA_RULES):
            for m in rule.pattern.finditer(line):
                raw = m.group(0)
                matched_spans.append(m.span())
                findings.append(Finding(
                    rule_id=rule.id, label=rule.label, kind=rule.kind,
                    severity=rule.severity, line_no=i, redacted=_fingerprint(raw),
                    fingerprint=_digest(raw),
                    entropy=round(shannon_entropy(raw), 2),
                    remediation=rule.remediation,
                ))


        for m in SECRETISH_ASSIGN.finditer(line):
            val = m.group("val")
            vstart = m.start("val")
            already = any(s <= vstart < e for s, e in matched_spans)
            if not already and _looks_like_secret_value(val):
                findings.append(Finding(
                    rule_id="generic-high-entropy",
                    label="High-Entropy Secret (generic)", kind="secret",
                    severity=5, line_no=i, redacted=_fingerprint(val),
                    fingerprint=_digest(val),
                    entropy=round(shannon_entropy(val), 2),
                    remediation="Confirm whether this is a real credential; if so rotate and move it to a secret manager.",
                ))
    return findings


_PLACEHOLDER = re.compile(r"(?i)(xxx|placeholder|example|changeme|your[_-]?|dummy|sample|<.*>|\.\.\.|test1234|000000|insecure)")


def _looks_like_placeholder(v: str) -> bool:
    return bool(_PLACEHOLDER.search(v)) or len(set(v)) <= 4


_CODE_PUNCT = re.compile(r"[\s.()\[\]{}<>/\\:;,]")
_KEYISH = re.compile(r"^[A-Za-z0-9_\-+=]+$")


def _looks_like_secret_value(val: str) -> bool:
    v = val.strip().strip("'\"")
    if len(v) < 20 or _looks_like_placeholder(v):
        return False
    if _CODE_PUNCT.search(v):
        return False
    if not _KEYISH.fullmatch(v):
        return False
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    if not (has_digit and has_alpha):
        return False
    return shannon_entropy(v) >= 3.5
