#!/usr/bin/env python3
"""
honeywatch — turn raw auditd honeytoken events into readable alerts.

Usage:
    sudo honeywatch                 # query auditd for events tagged "honeytoken"
    honeywatch --file audit.log     # read raw audit records from a file
    cat audit.log | honeywatch -    # read from stdin

An audit *event* is several *records* that share the same id, e.g.
    type=SYSCALL msg=audit(1696780042.123:456): ... comm="cat" ... key="honeytoken"
    type=PATH    msg=audit(1696780042.123:456): ... name="/opt/honeytokens/x" ...
We group records by that id, then pull the interesting fields out of each.
"""

import argparse
import pwd
import re
import subprocess
import sys
from datetime import datetime

AUDIT_KEY = "honeytoken"

# Matches: type=SYSCALL msg=audit(1696780042.123:456): rest of line
RECORD_RE = re.compile(r"type=(\w+) msg=audit\(([\d.]+):(\d+)\):\s*(.*)")

# Matches key=value pairs where value may be quoted: pid=123 or comm="cat"
FIELD_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


# ---------------------------------------------------------------------------
# Reading input
# ---------------------------------------------------------------------------

def read_from_auditd():
    """Ask ausearch for every raw record tagged with our key."""
    cmd = ["ausearch", "-k", AUDIT_KEY, "--raw"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("ausearch not found. Is auditd installed? (sudo apt install auditd)")
    if result.returncode != 0 and "no matches" not in result.stderr.lower():
        sys.exit(f"ausearch failed: {result.stderr.strip()}")
    return result.stdout.splitlines()


def read_from_file(path):
    if path == "-":
        return sys.stdin.read().splitlines()
    with open(path) as f:
        return f.read().splitlines()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_fields(text):
    """Turn 'pid=123 comm="cat"' into {'pid': '123', 'comm': 'cat'}."""
    fields = {}
    for key, value in FIELD_RE.findall(text):
        fields[key] = value.strip('"')
    return fields


def group_into_events(lines):
    """
    Return a list of events. Each event is a dict:
        {"id": "456", "time": datetime, "records": [(type, fields), ...]}
    """
    events = {}
    for line in lines:
        match = RECORD_RE.match(line.strip())
        if not match:
            continue
        rec_type, timestamp, event_id, rest = match.groups()
        event = events.setdefault(event_id, {
            "id": event_id,
            "time": datetime.fromtimestamp(float(timestamp)),
            "records": [],
        })
        event["records"].append((rec_type, parse_fields(rest)))
    return list(events.values())


def summarize(event):
    """Pull the fields a human cares about out of one event."""
    syscall = {}
    paths = []
    for rec_type, fields in event["records"]:
        if rec_type == "SYSCALL":
            syscall = fields
        elif rec_type == "PATH" and "name" in fields:
            paths.append(fields["name"])

    # Only alert on events that touched one of our bait paths.
    bait = [p for p in paths if p.startswith("/opt/")]
    if not bait:
        return None

    # auid = the user who originally logged in, even if they ran sudo.
    return {
        "time": event["time"],
        "file": bait[-1],
        "user": username(syscall.get("auid")),
        "process": syscall.get("comm", "?"),
        "exe": syscall.get("exe", "?"),
        "pid": syscall.get("pid", "?"),
        "success": syscall.get("success", "?"),
    }


def username(uid):
    """Turn '1000' into 'tdiprima'. Falls back to the raw number."""
    if uid is None or uid == "4294967295":   # 4294967295 = unset auid
        return "unknown"
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return f"uid {uid}"


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_alert(alert):
    return (
        "🚨 HONEYTOKEN TRIGGERED\n"
        "\n"
        f"File:     {alert['file']}\n"
        f"User:     {alert['user']}\n"
        f"Process:  {alert['process']} ({alert['exe']})\n"
        f"PID:      {alert['pid']}\n"
        f"Time:     {alert['time']:%Y-%m-%d %H:%M:%S}\n"
        f"Success:  {alert['success']}\n"
        "\n"
        "Severity: CRITICAL\n"
    )


def main():
    parser = argparse.ArgumentParser(description="Readable alerts from auditd honeytoken events.")
    parser.add_argument("--file", "-f", metavar="PATH",
                        help="read raw audit records from PATH ('-' for stdin) instead of ausearch")
    args = parser.parse_args()

    lines = read_from_file(args.file) if args.file else read_from_auditd()
    events = group_into_events(lines)
    alerts = [a for a in (summarize(e) for e in events) if a]

    if not alerts:
        print("No honeytoken activity. All quiet.")
        return

    for alert in sorted(alerts, key=lambda a: a["time"]):
        print(format_alert(alert))
    print(f"{len(alerts)} alert(s).")


if __name__ == "__main__":
    main()
