# honeywatch — build plan

Target: Ubuntu box with `auditd`. Everything lives in this repo; install scripts copy to the right places.

## Stage 1 — Plant the bait
- `plant_honeytokens.sh`: creates `/opt/honeytokens/` with the four fake files and `/opt/internal-api/.env`.
- Contents are obviously fake. Script is idempotent (safe to re-run).
- `HONEY_ROOT` env var overrides `/` so it can be tested locally without root.

## Stage 2 — Watch the bait with auditd
- `honeywatch.rules`: one `-w` rule per file, `-p rwxa`, key `honeytoken`.
- `install_audit_rules.sh`: copies rules to `/etc/audit/rules.d/`, reloads with `augenrules`.
- Verify with `ausearch -k honeytoken`.

## Stage 3 — `honeywatch` (the parser)
- `honeywatch.py`: runs `ausearch -k honeytoken --format raw` (or reads a file / stdin), groups records by event id, prints the human alert block (file, user, process, pid, time, severity).
- `honeywatch` shell wrapper so it runs as a plain command.

## Stage 4 — Level 2: smarter alerts
- Classify the action by process name (cat/vim/cp/grep/python...) and syscall (read vs write vs attr change vs exec).
- Resolve uid/auid to usernames.
- `--syslog` flag: send each alert to syslog via `logger`.
- `--report` flag: write a Markdown incident report.

## Stage 5 — Run it forever
- `--follow` mode: tail `/var/log/audit/audit.log` and alert in real time.
- `honeywatch.service` systemd unit + install script.

<br>
