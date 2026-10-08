#!/usr/bin/env bash
# Stage 5: install honeywatch as a command and run it as a background service.
#
# Usage: sudo ./install_service.sh
#
# Afterwards:
#   systemctl status honeywatch
#   journalctl -u honeywatch -f          # live alerts
#   grep honeywatch /var/log/syslog      # syslog copies

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "run this with sudo" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

install -m 755 "$HERE/honeywatch.py" /usr/local/lib/honeywatch.py
printf '#!/usr/bin/env bash\nexec python3 /usr/local/lib/honeywatch.py "$@"\n' > /usr/local/bin/honeywatch
chmod 755 /usr/local/bin/honeywatch
echo "installed /usr/local/bin/honeywatch"

install -m 644 "$HERE/honeywatch.service" /etc/systemd/system/honeywatch.service
systemctl daemon-reload
systemctl enable --now honeywatch
echo "service started"
systemctl --no-pager status honeywatch | head -5
