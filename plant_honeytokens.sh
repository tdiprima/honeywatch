#!/usr/bin/env bash
# Stage 1: plant fake credential files that nobody should ever touch.
#
# Usage:
#   sudo ./plant_honeytokens.sh            # installs under /
#   HONEY_ROOT=/tmp/test ./plant_honeytokens.sh   # for local testing
#
# Safe to run more than once.

set -euo pipefail

ROOT="${HONEY_ROOT:-}"
TOKEN_DIR="$ROOT/opt/honeytokens"
ENV_DIR="$ROOT/opt/internal-api"

# write_file PATH CONTENT
# Creates the file, fills it, and makes it world-readable so the bait is tempting.
write_file() {
    local path="$1"
    local content="$2"
    printf '%s\n' "$content" > "$path"
    chmod 644 "$path"
    echo "planted: $path"
}

mkdir -p "$TOKEN_DIR" "$ENV_DIR"

write_file "$TOKEN_DIR/AWS_PRODUCTION_KEYS.txt" \
"AWS_ACCESS_KEY_ID=AKIATHISISAHONEYTOKEN
AWS_SECRET_ACCESS_KEY=TOTALLY_FAKE_DO_NOT_USE
AWS_DEFAULT_REGION=us-east-1"

write_file "$TOKEN_DIR/payroll_passwords.csv" \
"employee,system,password
jsmith,ADP,Winter2024!
mjones,Workday,Payroll#99
admin,PayrollDB,P@ssw0rd123"

write_file "$TOKEN_DIR/database-backup-credentials.txt" \
"host=db-backup-01.internal
user=backup_admin
password=B4ckup!Fake!Password
port=5432"

write_file "$TOKEN_DIR/DO_NOT_DELETE_PROD.key" \
"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAfakefakefakefakefakefakefakefakefakefakefakefake
THISISNOTAREALKEYITISAHONEYTOKENTHISISNOTAREALKEYITISAHONEYTOKEN
-----END RSA PRIVATE KEY-----"

write_file "$ENV_DIR/.env" \
"DATABASE_URL=postgres://api_user:FakePassword123@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_THISISAHONEYTOKEN
JWT_SECRET=not-a-real-secret-honeytoken
DEBUG=false"

echo "done. honeytokens live in $TOKEN_DIR and $ENV_DIR"
