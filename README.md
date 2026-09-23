# SOC Alert Engine

A lightweight detection engine that parses real SSH authentication logs, flags suspicious behavior, maps every alert to a **MITRE ATT&CK** technique, and correlates multiple weak signals into a single high-confidence alert — the same core logic behind commercial SIEM detection rules, built from scratch in pure Python.

```
$ python main.py data/OpenSSH_2k.log

=== SOC Alert Engine Report ===
Log source: data/OpenSSH_2k.log
Total lines analyzed: 2000

[ALERT] User Enumeration Detected  (MITRE ATT&CK: T1087.001 - Account Discovery)
  IP: 187.141.143.180
    Distinct usernames tried: 28
    Sample: www, ted, ghost, nagios, butter, vnc (+22 more)
  ...

[ALERT] Brute Force Detected  (MITRE ATT&CK: T1110.001 - Password Guessing)
  IP: 183.62.140.253
    Failed attempts: 286
    Window: 2026-12-10 10:54:29 -> 2026-12-10 10:54:33 (4s)
  ...

[HIGH SEVERITY] Correlated Activity
  The following IPs triggered BOTH brute force AND user enumeration alerts,
  indicating a coordinated, automated multi-stage attack:

  187.141.143.180
  103.99.0.122
  5.188.10.180
  183.62.140.253

=== Summary ===
  Brute force alerts: 11
  User enumeration alerts: 4
  Total unique suspicious IPs: 11
```

## Why this exists

Real attacks against SSH servers rarely stop at one behavior. An attacker typically **enumerates** valid usernames first (T1087.001 – Account Discovery), then pivots to **brute-forcing** the accounts that look real (T1110.001 – Password Guessing). A SOC analyst who only has isolated "failed login" alerts has to manually connect those dots under time pressure. This engine does that correlation automatically — an IP that trips *both* detection rules is surfaced as a single high-severity finding instead of two disconnected low-priority ones.

## How it works

```
raw log file
     │
     ▼
┌─────────────┐     regex-based extraction: IP, timestamp,
│  parser.py  │     PID, event type, username
└─────────────┘
     │  list[dict]
     ▼
┌────────────────┐   sliding time-window analysis (brute force)
│ rules_engine.py│   distinct-value counting (user enumeration)
└────────────────┘
     │  list[alert]
     ▼
┌─────────────┐     MITRE ATT&CK-labeled, color-coded report +
│  report.py  │     cross-rule correlation
└─────────────┘
```

- **`parser.py`** turns each raw syslog line into a structured record (`ip`, `event_type`, `timestamp`, `pid`, `username`) using regular expressions — no external log-parsing library, to keep the extraction logic transparent and auditable.
- **`rules_engine.py`** implements two independent detections:
  - **Brute force** — groups failed-password events by source IP, then checks whether `threshold` or more attempts fall inside a `window_seconds` sliding window (defaults: 3 attempts / 60s).
  - **User enumeration** — groups attempted usernames by source IP using a `set()`, and flags IPs that tried `distinct_threshold` or more *distinct* usernames (default: 5).
- **`report.py`** renders both alert types plus a correlation pass that intersects the two IP sets to surface coordinated attacks.

## MITRE ATT&CK mapping

| Detection            | Technique | Tactic              | Logic                                                    |
|-----------------------|-----------|----------------------|-----------------------------------------------------------|
| Brute force            | T1110.001 | Credential Access     | N+ failed logins from one IP inside a time window          |
| User enumeration        | T1087.001 | Discovery              | N+ distinct usernames attempted from one IP                |
| Correlated activity      | —         | —                      | An IP triggering both of the above simultaneously           |

## Dataset

Detection logic is validated against the **OpenSSH log set from [LogHub](https://github.com/logpai/loghub)** — real authentication logs collected from a lab SSH server, containing genuine brute-force and username-enumeration traffic (not synthetic data). `data/OpenSSH_2k.log` is a 2,000-line sample from that set.

## Installation & usage

```bash
git clone https://github.com/Chabiiia/soc-alert-engine.git
cd soc-alert-engine
python main.py data/OpenSSH_2k.log
```

No external dependencies — pure Python standard library (`re`, `argparse`, `datetime`, `collections`).

Run it against any other syslog-formatted SSH log by pointing it at a different file:

```bash
python main.py /var/log/auth.log
```

## Project structure

```
soc-alert-engine/
├── data/
│   └── OpenSSH_2k.log        # sample dataset (LogHub)
├── soc_engine/
│   ├── parser.py              # log line -> structured record
│   ├── rules_engine.py        # detection logic
│   └── report.py               # MITRE-labeled CLI report
├── main.py                     # CLI entry point
└── README.md
```

## Design decisions

- **Sliding window over a fixed count, not a fixed count over the whole file** — a raw "N failures total" counter would flag a legitimate user who mistypes their password a few times over a whole day. Requiring those failures to cluster inside a short window is what actually distinguishes automated brute-forcing from human error.
- **Enumeration counted separately from brute force** — counting `invalid_user` and `failed_password` events together double-counts a single login attempt against a nonexistent account (both a `"Invalid user X"` and a `"Failed password for invalid user X"` line get logged for the same attempt). Keeping brute force scoped to `failed_password` only avoids that skew, and lets user enumeration exist as its own, earlier-stage signal.
- **Correlation as a first-class output, not an afterthought** — two independent low/medium alerts on the same IP are a materially different finding than either alert alone, and the report treats it that way instead of leaving the analyst to notice the overlap manually.

## Possible extensions

- Move detection thresholds into declarative, [Sigma](https://github.com/SigmaHQ/sigma)-style YAML rule files instead of Python constants, so new detections don't require code changes
- Auto-enrich flagged IPs via a threat intelligence lookup (VirusTotal / AbuseIPDB) to check for prior abuse reports
- Add a third detection: a successful login immediately following a burst of failures (T1078 – Valid Accounts), which can indicate a successful compromise rather than just an attempt
