#!/usr/bin/env bash
# Stage 2: install the auditd rules that watch the honeytokens.
#
# Usage: sudo ./install_audit_rules.sh
#
# Verify afterwards with:
#   sudo auditctl -l                 # rules are loaded
#   cat /opt/internal-api/.env       # trip the wire
#   sudo ausearch -k honeytoken      # see the event

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run this with sudo" >&2
    exit 1
fi

if ! command -v auditctl >/dev/null; then
    echo "auditd not found, installing..."
    apt-get update -qq
    apt-get install -y -qq auditd audispd-plugins
fi

RULES_SRC="$(dirname "$0")/honeywatch.rules"
RULES_DST="/etc/audit/rules.d/honeywatch.rules"

cp "$RULES_SRC" "$RULES_DST"
chmod 640 "$RULES_DST"
echo "copied rules to $RULES_DST"

# augenrules merges every file in /etc/audit/rules.d/ and loads the result.
augenrules --load
systemctl enable --now auditd

echo
echo "loaded rules:"
auditctl -l | grep honeytoken
