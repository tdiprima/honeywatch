# honeywatch

Honeytoken intrusion detector for Linux using auditd and Python that turns raw audit logs into readable alerts.

Plant fake credential files that nobody should ever touch. Watch them with `auditd`. When something reads, writes, or executes one, `honeywatch` tells you who, what, and when:

```text
🚨 HONEYTOKEN TRIGGERED

File:     /opt/internal-api/.env
User:     user (running as root)
Process:  vim (/usr/bin/vim.basic)
Action:   open via editor
PID:      19530
Time:     2025-10-08 07:48:21
Success:  yes

Severity: HIGH
```

This is not a vulnerable service exposed to the internet. It is a tripwire: the files are bait, the contents are fake, and any access at all is suspicious.

## Requirements

- Ubuntu (or any systemd Linux with `auditd`)
- Python 3 (standard library only)
- root for installing audit rules and reading the audit log

## Quick start

```bash
git clone <this repo> && cd honeywatch

sudo ./plant_honeytokens.sh      # 1. create the bait files
sudo ./install_audit_rules.sh    # 2. load the auditd rules
sudo ./install_service.sh        # 3. run honeywatch as a background service

cat /opt/internal-api/.env       # 💥 trip the wire
journalctl -u honeywatch -f      # watch the alert arrive
```

## What gets planted

```text
/opt/honeytokens/
├── AWS_PRODUCTION_KEYS.txt
├── payroll_passwords.csv
├── database-backup-credentials.txt
└── DO_NOT_DELETE_PROD.key
/opt/internal-api/.env
```

Every value inside is obviously fake (`TOTALLY_FAKE_DO_NOT_USE`, `sk_live_THISISAHONEYTOKEN`, ...).

## How it works

1. **`honeywatch.rules`** tells auditd to log every read, write, execute, and attribute change (`-p rwxa`) on each bait file, tagged with the key `honeytoken`.
2. **`honeywatch.py`** reads those events, either from `ausearch -k honeytoken` or by tailing `/var/log/audit/audit.log`, and groups the multi-line records into one event each.
3. For each event it pulls out the file, the user who logged in (`auid`, which survives `sudo`), the effective user, the process, and the syscall, then prints an alert.

## Usage

```bash
sudo honeywatch                        # show all past honeytoken events
sudo honeywatch --follow               # live mode: alert as it happens
sudo honeywatch --syslog               # also send each alert to syslog (auth.crit, tag "honeywatch")
sudo honeywatch --report incident.md   # also write a Markdown incident report
honeywatch --file samples/audit.log    # parse a saved log (no root needed)
```

Flags combine, e.g. `--follow --syslog` is what the systemd service runs.

### Severity

| Severity | When |
|----------|------|
| HIGH     | the file was opened, read, or stat'd |
| CRITICAL | it was written, renamed, deleted, chmod/chown'd, executed, or touched by a copy/exfil tool (`cp`, `scp`, `curl`, `base64`, ...) |

### Process classification

The alert names the kind of tool involved: viewer (`cat`, `less`), editor (`vim`, `nano`), copy (`cp`, `rsync`), search (`grep`, `find`), script (`python3`, `bash`), or exfil (`curl`, `wget`, `nc`). Edit `TOOL_KINDS` in `honeywatch.py` to add more.

## Files

| File | Purpose |
|------|---------|
| `plant_honeytokens.sh` | creates the bait files (`HONEY_ROOT=/tmp/x` to test without root) |
| `honeywatch.rules` | auditd watch rules |
| `install_audit_rules.sh` | installs auditd if needed and loads the rules |
| `honeywatch.py` | the detector |
| `honeywatch` | wrapper so you can run it from the repo |
| `honeywatch.service` | systemd unit |
| `install_service.sh` | installs the command and enables the service |
| `samples/audit.log` | fake audit events for testing the parser |
| `PLAN.md` | how the project was built, stage by stage |

## Testing without auditd

```bash
./honeywatch --file samples/audit.log --report /tmp/incident.md
```

## Caveats

- Syscall-to-action mapping assumes x86_64. On arm64 the numbers differ and actions will show as `other`.
- The honeytoken directory watch (`-w /opt/honeytokens -p wa`) also fires when you re-run `plant_honeytokens.sh`. That is expected.
- `auditd` must be running or nothing is logged. Check with `sudo auditctl -l`.

<!--
sudo ./plant_honeytokens.sh
sudo ./install_audit_rules.sh
sudo ./install_service.sh
cat /opt/internal-api/.env  # 💥
journalctl -u honeywatch -f
-->

<br>
