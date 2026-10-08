### 🧪 Project: Build a Linux "Tripwire" Honeypot

Not an actual vulnerable honeypot exposed to the internet. Instead, build a **honeytoken-based intrusion detector** on an Ubuntu box.

Plant files that **nobody should ever legitimately touch**, then detect when something accesses them.

For example:

```text
/opt/honeytokens/
├── AWS_PRODUCTION_KEYS.txt
├── payroll_passwords.csv
├── database-backup-credentials.txt
└── DO_NOT_DELETE_PROD.key
```

The contents are fake. Something like:

```text
AWS_ACCESS_KEY_ID=THIS_IS_A_HONEYTOKEN
AWS_SECRET_ACCESS_KEY=TOTALLY_FAKE_DO_NOT_USE
```

Then use Linux auditing (`auditd`) to watch them.

The fun part is making your detector answer:

```text
🚨 HONEYTOKEN TRIGGERED

File: /opt/honeytokens/AWS_PRODUCTION_KEYS.txt
User: tdiprima
Process: cat
PID: 19482
Time: 13:47:22

Severity: CRITICAL
```

Your challenge is to figure out how to configure an `auditd` rule that detects **reads, writes, attribute changes, and/or execution** involving the bait.

Then write a little Bash or Python program:

```bash
honeywatch
```

that parses those audit events and turns the horrible raw audit log into something a human would actually want to read.

**Extra evil:** plant one fake `.env` somewhere believable:

```text
/opt/internal-api/.env
```

Then test:

```bash
cat /opt/internal-api/.env
```

💥 **ALERT.**

And if you finish early, Level 2 is where it gets fun: make `honeywatch` distinguish between `cat`, `vim`, `cp`, `grep`, Python, etc.; record who touched the file; send events to syslog with `logger`; create a systemd service for the detector; and generate a little incident report.

That gives you an actual **blue-team/detection-engineering lab**, rather than another "write a Bash script that counts failed SSH logins" exercise.

And it connects directly to that Security+ **honeytoken vs. honeyfile** stuff you've been studying: now you'd actually build one instead of memorizing the definition.

<br>
