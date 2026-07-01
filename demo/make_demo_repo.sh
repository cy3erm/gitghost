#!/usr/bin/env bash
# Builds a throwaway git repo seeded with FAKE, well-known-example secrets so we
# can demonstrate gitghost end-to-end without touching any real person's data.
# Every value below is a documented placeholder or randomly generated — none are
# live credentials.
set -e

DIR="${1:-/tmp/ghost-demo}"
rm -rf "$DIR"; mkdir -p "$DIR"; cd "$DIR"
git init -q
git config user.name "Dana Rivera"
git config user.email "dana.rivera@gmail.com"     # <- fake, but a "real" (non-noreply) address

commit () {  # commit <msg> with a fixed +0530 timezone to make tz inference work
  export GIT_AUTHOR_DATE="2024-0$2-1$3 21:$4:00 +0530"
  export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"
  git add -A && git commit -q -m "$1"
}

# --- commit 1: the original sin — a config with a live-looking AWS key ---
cat > config_prod.py <<'PY'
# early prototype config (should have used env vars...)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgres://admin:s3cr3tP4ssw0rd@db.internal:5432/prod"
PY
commit "initial prototype config" 3 2 03

# --- commit 2: normal work ---
echo "print('hello')" > app.py
cat > README.md <<'MD'
# billing-service
Internal billing microservice. Talks to db.internal (10.0.4.12).
MD
commit "add app + readme" 3 4 12

# --- commit 3: 'oops, remove the secrets' — but git remembers (GHOST) ---
cat > config_prod.py <<'PY'
import os
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
aws_secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
PY
commit "SECURITY: move creds to env vars" 3 6 40

# --- commit 4: a NEW live leak sneaks in elsewhere ---
mkdir -p deploy
cat > deploy/ci.sh <<'SH'
#!/usr/bin/env bash
export STRIPE_KEY="sk_live_$(printf %s 4eC39HqLyjWDarjtT1zdp7dc)"
export GH_TOKEN="ghp_1234567890abcdefghijklmnopqrstuvwx12"
curl -s "https://hooks.slack.com/services/T00000000/$(printf %s B00000000)/XXXXXXXXXXXXXXXXXXXXXXXX"
SH
commit "add CI deploy script" 3 8 15

# --- commit 5: a committed .env (classic) + a private key ---
cat > .env <<'ENV'
API_TOKEN=aGVsbG9Xb3JsZFRoaXNJc0FTZWNyZXRLZXkxMjM0NQ==
SESSION_SECRET=f4a9c2e8b7d1063a5e9f2c4b8a7d6e1f0c3b5a9d
ENV
cat > id_rsa <<'KEY'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAexampleFAKEkeymaterialdoNOTuseThisIsForDemoOnly1234
-----END RSA PRIVATE KEY-----
KEY
commit "add local env + deploy key" 3 9 55

echo "demo repo built at $DIR"
git --no-pager log --oneline
