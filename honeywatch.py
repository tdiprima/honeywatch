#!/usr/bin/env python3
"""
honeywatch — turn raw auditd honeytoken events into readable alerts.

Usage:
    sudo honeywatch                 # query auditd for events tagged "honeytoken"
    honeywatch --file audit.log     # read raw audit records from a file
    cat audit.log | honeywatch -    # read from stdin
    honeywatch --syslog             # also send each alert to syslog via logger
    honeywatch --report incident.md # also write a Markdown incident report

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
import time
from datetime import datetime

AUDIT_KEY = "honeytoken"

# What kind of tool touched the file? Keyed by the process name (comm=).
TOOL_KINDS = {
    "cat": "viewer", "less": "viewer", "more": "viewer", "head": "viewer", "tail": "viewer",
    "grep": "search", "rg": "search", "find": "search", "strings": "search",
    "vim": "editor", "vi": "editor", "nano": "editor", "vim.basic": "editor",
    "cp": "copy", "scp": "copy", "rsync": "copy", "tar": "copy", "zip": "copy",
    "python": "script", "python3": "script", "perl": "script", "bash": "script", "sh": "script",
    "curl": "exfil", "wget": "exfil", "nc": "exfil", "base64": "exfil",
}

# x86_64 syscall numbers -> what the action was. Anything else is "other".
SYSCALL_ACTIONS = {
    "0": "read", "2": "open", "257": "open", "4": "stat", "6": "stat", "262": "stat",
    "1": "write", "82": "rename", "87": "delete", "263": "delete",
    "90": "chmod", "268": "chmod", "92": "chown", "260": "chown", "188": "setxattr",
    "59": "execute", "322": "execute",
}

# Which actions are worse than a plain read.
HIGH_RISK_ACTIONS = {"write", "rename", "delete", "chmod", "chown", "setxattr", "execute"}

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

    process = syscall.get("comm", "?")
    action = SYSCALL_ACTIONS.get(syscall.get("syscall"), "other")
    kind = TOOL_KINDS.get(process, "unknown")

    # auid = the user who originally logged in, even if they ran sudo.
    return {
        "time": event["time"],
        "file": bait[-1],
        "user": username(syscall.get("auid")),
        "effective_user": username(syscall.get("uid")),
        "process": process,
        "exe": syscall.get("exe", "?"),
        "pid": syscall.get("pid", "?"),
        "action": action,
        "kind": kind,
        "success": syscall.get("success", "?"),
        "severity": severity(action, kind),
    }


def severity(action, kind):
    """Every hit is bad. Modifying, executing, or exfiltrating the bait is worse."""
    if action in HIGH_RISK_ACTIONS or kind in ("exfil", "copy"):
        return "CRITICAL"
    return "HIGH"


def username(uid):
    """Turn '1000' into 'user'. Falls back to the raw number."""
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
        f"User:     {alert['user']} (running as {alert['effective_user']})\n"
        f"Process:  {alert['process']} ({alert['exe']})\n"
        f"Action:   {alert['action']} via {alert['kind']}\n"
        f"PID:      {alert['pid']}\n"
        f"Time:     {alert['time']:%Y-%m-%d %H:%M:%S}\n"
        f"Success:  {alert['success']}\n"
        "\n"
        f"Severity: {alert['severity']}\n"
    )


def send_to_syslog(alert):
    """One line per alert, tagged 'honeywatch', priority auth.crit. Uses the logger command."""
    message = (
        f"HONEYTOKEN {alert['severity']} file={alert['file']} user={alert['user']} "
        f"process={alert['process']} action={alert['action']} pid={alert['pid']} "
        f"time={alert['time']:%Y-%m-%dT%H:%M:%S}"
    )
    subprocess.run(["logger", "-t", "honeywatch", "-p", "auth.crit", message])


def write_report(alerts, path):
    """Write a short Markdown incident report."""
    first, last = alerts[0]["time"], alerts[-1]["time"]
    files = sorted({a["file"] for a in alerts})
    users = sorted({a["user"] for a in alerts})
    worst = "CRITICAL" if any(a["severity"] == "CRITICAL" for a in alerts) else "HIGH"

    lines = [
        "# Honeytoken Incident Report",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- Alerts: {len(alerts)}",
        f"- Highest severity: {worst}",
        f"- Window: {first:%Y-%m-%d %H:%M:%S} to {last:%Y-%m-%d %H:%M:%S}",
        f"- Users involved: {', '.join(users)}",
        f"- Files touched: {', '.join(files)}",
        "",
        "## Timeline",
        "",
        "| Time | User | Process | Action | File | Severity |",
        "|------|------|---------|--------|------|----------|",
    ]
    for a in alerts:
        lines.append(
            f"| {a['time']:%Y-%m-%d %H:%M:%S} | {a['user']} | {a['process']} "
            f"| {a['action']} | {a['file']} | {a['severity']} |"
        )
    lines += [
        "",
        "## Recommended actions",
        "",
        "1. Confirm with each listed user whether the access was expected.",
        "2. Review that user's shell history and other auditd events around the window above.",
        "3. If unexplained, treat the host as compromised and rotate any real credentials it can reach.",
        "",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Readable alerts from auditd honeytoken events.")
    parser.add_argument("--file", "-f", metavar="PATH",
                        help="read raw audit records from PATH ('-' for stdin) instead of ausearch")
    parser.add_argument("--syslog", action="store_true",
                        help="also send each alert to syslog with logger")
    parser.add_argument("--report", metavar="PATH",
                        help="also write a Markdown incident report to PATH")
    args = parser.parse_args()

    lines = read_from_file(args.file) if args.file else read_from_auditd()
    events = group_into_events(lines)
    alerts = [a for a in (summarize(e) for e in events) if a]

    if not alerts:
        print("No honeytoken activity. All quiet.")
        return

    alerts.sort(key=lambda a: a["time"])
    for alert in alerts:
        print(format_alert(alert))
        if args.syslog:
            send_to_syslog(alert)
    print(f"{len(alerts)} alert(s).")

    if args.report:
        write_report(alerts, args.report)
        print(f"incident report written to {args.report}")


if __name__ == "__main__":
    main()
