# 🛡️ Login Log Analyser

A small, dependency-free Python tool that reads login logs and flags suspicious activity: **brute-force attacks**, **logins at unusual hours**, and **possible account compromise**. It prints a colour-coded summary report in the terminal.

Built as a beginner cybersecurity portfolio project to practise log analysis, the same core skill SOC analysts use every day.

## Features

- Parses **SSH auth logs** (ISO or real `/var/log/auth.log` syslog timestamps, `invalid user` and public-key logins) and **Windows Security event logs** (CSV export)
- Sliding-window brute-force detection (configurable threshold and window)
- Unusual-hour login detection, either fixed night hours or **learned per-user normal hours** (`--learn`)
- Correlates events: flags a successful login that follows a brute-force burst from the same IP
- **Password-spraying detection**: one IP failing against many different accounts
- **Most-targeted accounts** ranking and an **hourly histogram** of failed logins
- **Allow-list** (`--allow`), **date filters** (`--since`/`--until`) and a **CI-friendly exit code** (`--fail-on-alert`)
- **Privileged-login detection**: root/admin logins from an IP that had already failed (`--privileged`)
- **Noisiest source IPs** ranking, including IPs below the brute-force threshold
- Optional **GeoIP lookup** of attacking IPs (`--geoip`)
- **JSON, CSV, Markdown and self-contained HTML export** of all alerts, plus `--top N` to focus on the worst offenders
- Severity labels, a mini bar chart and a final summary with recommended actions
- Pure Python 3 standard library, with nothing to install

## Project structure

```
log-analyser/
├── log_analyser.py          # the analyser (main tool)
├── test_log_analyser.py     # unit tests (python -m unittest)
├── generate_sample_logs.py  # creates realistic fake logs for testing
├── sample_logs/auth.log              # generated SSH sample data
├── sample_logs/windows_security.csv  # generated Windows sample data
└── README.md
```

## Usage

Requires Python 3.8 or newer.

```bash
# 1. (Optional) regenerate the sample log
python generate_sample_logs.py

# 2. Analyse a log file
python log_analyser.py sample_logs/auth.log
```

### Options

| Option | Default | Meaning |
|---|---|---|
| `--threshold` | `5` | Failed logins from one IP needed to flag a brute-force attempt |
| `--window` | `5` | Time window in minutes for counting those failures |
| `--night-start` | `0` | First hour (0-23) considered unusual |
| `--night-end` | `6` | Hour at which the unusual period ends (exclusive) |
| `--learn` | off | Learn each user's normal hours instead of using fixed night hours |
| `--top N` | all | Only show the N worst brute-force sources |
| `--geoip` | off | Look up country/city/ISP of attacking IPs (see privacy note below) |
| `--spray-users N` | `4` | Distinct accounts from one IP (within `--window`) needed to flag password spraying |
| `--allow IP/CIDR` | none | Ignore events from this IP or network; repeatable (e.g. `--allow 10.0.0.0/8`) |
| `--since DATE` / `--until DATE` | none | Only analyse events in this `YYYY-MM-DD` range (`--until` is inclusive) |
| `--fail-on-alert` | off | Exit code 1 if any alert, 2 if a possible compromise (for scripts/CI) |
| `--json FILE` | none | Also save all alerts to a JSON file |
| `--csv FILE` | none | Also save all alerts to a CSV file |
| `--markdown FILE` | none | Also save a Markdown report (alerts table, top accounts and IPs) |
| `--html FILE` | none | Also save a self-contained HTML report with a colour-coded alerts table |
| `--year YYYY` | this year | Year to assume for syslog timestamps (`Oct  3 02:14:05`), which carry none |
| `--privileged NAMES` | `root,admin,administrator` | Comma-separated privileged accounts to watch for logins from IPs that failed first |
| `--format` | `auto` | `ssh` or `windows`; `auto` treats `.csv` files as Windows |

Examples:

```bash
# Stricter rules
python log_analyser.py sample_logs/auth.log --threshold 3 --window 2 --night-start 22 --night-end 6

# Windows Security log
python log_analyser.py sample_logs/windows_security.csv

# Learned hours, top 3 attackers, save results
python log_analyser.py sample_logs/auth.log --learn --top 3 --json alerts.json --csv alerts.csv
```

### `--learn` vs fixed night hours
Fixed hours flag *anyone* who logs in at night, including legitimate night-shift staff. With `--learn`, the tool builds each user's normal hours from their own successful logins and only flags logins far from that pattern (more than 3 hours from all their other logins; users with fewer than 3 logins are skipped). On the sample log, the fixed rule raises 3 false alarms about night-shift user `frank`, and `--learn` doesn't.

### GeoIP privacy note
`--geoip` sends public attacker IPs to the free service [ip-api.com](https://ip-api.com) over HTTP. Private/reserved addresses are never sent, and it is off by default. Don't use it on logs where even the IPs are sensitive. The sample logs only contain reserved addresses, so they show "private/reserved address".

### Expected log formats

**SSH-style text log:**

```
2026-10-01 03:12:44 sshd[1234]: Failed password for admin from 203.0.113.45 port 51234
2026-10-01 09:02:10 sshd[2001]: Accepted password for alice from 198.51.100.10 port 40022
```

Lines that don't match are skipped. To support another text format (for example the real `/var/log/auth.log`, which has no year), adjust `LINE_PATTERN` in `log_analyser.py`.

**Windows Security log (CSV):** columns `TimeCreated, EventId, TargetUserName, IpAddress`. Event 4625 is a failed logon and 4624 is a successful one. You can export your own from an elevated PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated    = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
      EventId        = $_.Id
      TargetUserName = $d['TargetUserName']
      IpAddress      = $d['IpAddress']
    }
  } | Export-Csv security.csv -NoTypeInformation
python log_analyser.py security.csv
```

## What it detects and why it matters

### 1. Brute-force attempts
**What:** Many failed logins from one source IP in a short time (default: 5 or more in 5 minutes), found with a sliding time window.

**Why it matters:** Brute-forcing and password guessing are among the most common ways attackers try to get in. Internet-facing SSH, RDP and web logins are probed constantly. Spotting the burst lets you block the IP, add rate limiting or lockouts, and enforce MFA before a guess succeeds.

### 2. Password spraying
**What:** One IP failing against several *different* accounts inside the window (default: 4 or more accounts).

**Why it matters:** Spraying tries a few common passwords across many accounts to stay under per-account lockouts, so it can look harmless account by account. Grouping by source IP exposes it.

### 3. Unusual-hour logins
**What:** *Successful* logins between certain hours (default 00:00-06:00).

**Why it matters:** Stolen credentials are often used outside working hours, when nobody is watching. A valid password at 3 a.m. is a classic sign of account takeover or an insider threat. It isn't proof on its own, since the user may be on a night shift or in another time zone, but it is worth a look.

### 4. Possible compromise (correlation)
**What:** A successful login from an IP that was just brute-forcing.

**Why it matters:** This is the most serious finding, because it suggests the attacker **got in**. It turns "someone is attacking us" into "someone may be inside", which is when you reset credentials, investigate and respond to an incident.

### 5. Privileged logins after failures
**What:** A successful login to a privileged account (`root`, `admin`, `administrator` by default) from an IP that had already failed to log in earlier in the log. Logins already flagged as a possible compromise are not repeated.

**Why it matters:** Privileged accounts give an attacker full control, so a login that follows failed attempts (typos from a real admin, or guessing by an attacker) deserves a quick check. It is a lower-severity hint than the compromise rule, which needs a full brute-force burst first.

## About the sample data

`generate_sample_logs.py` builds three days of fake traffic with a fixed random seed, so the results are repeatable. `auth.log` contains:

- Normal staff logins in office hours, with the odd typo
- A fast brute-force attack on `admin` / `root`
- A slower password-spraying attack across common usernames
- An attacker who eventually guesses `carol`'s password (the compromise case)
- Two odd-hour logins by `dave` and `bob`
- A night-shift worker (`frank`) who always logs in around 2 a.m.
- Harmless background noise (single failures)

`windows_security.csv` has a brute-force burst on `Administrator` that ends in a successful logon, plus normal logons and one odd-hour logon.

All IPs are from reserved documentation ranges (RFC 5737), so none belong to real systems.

## Limitations and ideas for improvement

- Two log formats only; add parsers for web server logs, firewall logs or the raw `.evtx` format
- `--learn` is a simple heuristic and needs a few logins per user; a real system would use longer baselines
- GeoIP uses one free service; threat-intelligence reputation lookups (e.g. AbuseIPDB) would add context
- Could also send alerts by email or webhook (JSON, CSV, Markdown and HTML export already exist)

## Disclaimer

For learning and defensive use on logs you are authorised to analyse.
