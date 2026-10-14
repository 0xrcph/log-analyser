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
- **Distributed-attack detection**: many IPs sharing the work of attacking one account (`--dist-ips`)
- **New-source login detection** (`--new-ip`): an account logging in from an IP it has never used before
- **Multi-IP account detection** (`--multi-ip N`): one account used from several IPs at once (shared or stolen credentials)
- **Flexible input**: several log files merged in one run, gzip-compressed rotated logs (`auth.log.2.gz`), or stdin (`-`)
- **Per-IP risk score (0-100)** that combines every signal from the same source
- **Config file** (`--config`) so a team can share one set of rules
- **Noisiest source IPs** ranking, including IPs below the brute-force threshold
- Optional **GeoIP lookup** of attacking IPs (`--geoip`)
- **JSON, CSV, Markdown and self-contained HTML export** of all alerts, plus `--top N` to focus on the worst offenders
- Severity labels, a mini bar chart and a final summary with recommended actions
- **More SSH line types**: `keyboard-interactive/pam`, `none`, bare `Invalid user …` and `Connection closed by authenticating user …` lines, with each attempt counted once even when sshd logs it three ways
- **Account takeover detection**: a login right after failures on the same account from *any* IP, or during a distributed attack
- **Low-and-slow detection**: a patient IP that stays under the 5-minute rule but fails 20+ times in 24 hours (`--slow-threshold`, `--slow-window`)
- **Impossible travel** (`--travel`): one account logging in from far-apart places faster than a jet could fly
- **More sources**: nginx/Apache access logs (401/403 floods, scanner URLs such as `/.env`), Windows lockouts (event 4740) and logon types, repeated failed `sudo`/`su`
- **Live mode** (`--follow`) that watches a growing log and alerts as attacks start, with **webhook** (Slack/Discord/Teams style) and **email** notifications
- **Blocklist export** (`--blocklist`) as `ufw`, `iptables`, `nft` or plain text, and **baselines** (`--baseline`) so repeat runs only report what is new
- **GeoIP that behaves**: rate-limited, cached in memory and on disk (`--geoip-cache`), or fully offline with a local MaxMind database (`--geoip-db`)
- **Port-scan detection** from kernel firewall lines (`[UFW BLOCK] … SRC=… DPT=…`): one IP blocked on many different ports
- **journalctl / RFC3339 timestamps** (`2026-10-01T10:00:00+0000`) and US-format Windows CSV dates
- `--ignore-user` to silence monitoring/service accounts; installable as a `log-analyser` command (`pip install .`)
- HTML report with **charts** (failed logins by hour and over time)
- Pure Python 3 standard library, with nothing to install (`geoip2` only if you choose `--geoip-db`)

## Project structure

```
log-analyser/
├── log_analyser.py          # the analyser (main tool)
├── test_log_analyser.py     # unit tests (python -m unittest)
├── generate_sample_logs.py  # creates realistic fake logs for testing
├── sample_logs/auth.log              # generated SSH sample data
├── sample_logs/windows_security.csv  # generated Windows sample data
├── sample_logs/access.log            # generated nginx-style web log
├── sample_logs/ufw.log               # generated firewall log (a port scan)
├── pyproject.toml                    # `pip install .` gives a `log-analyser` command
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
| `--dist-ips N` | `5` | Distinct IPs failing against one account (within `--window`) needed to flag a distributed attack |
| `--config FILE` | none | JSON file of default options (see below); command-line flags override it |
| `--new-ip` | off | Flag a successful login from an IP the account has never logged in from before (needs 3 earlier logins of history) |
| `--multi-ip N` | `0` (off) | Flag accounts that log in successfully from N or more different IPs within `--window` |
| `--no-color` | off | Plain output without ANSI colours (also honoured: the `NO_COLOR` environment variable) |
| `--html FILE` | none | Also save a self-contained HTML report with a colour-coded alerts table |
| `--year YYYY` | this year | Year to assume for syslog timestamps (`Oct  3 02:14:05`), which carry none |
| `--privileged NAMES` | `root,admin,administrator` | Comma-separated privileged accounts to watch for logins from IPs that failed first |
| `--format` | `auto` | `ssh`, `windows` or `web`; `auto` treats `*.csv` as Windows and names containing `access` as a web log |
| `--slow-threshold N` | `20` | Failures from one IP inside `--slow-window` that flag a low-and-slow attack (`0` = off) |
| `--slow-window HOURS` | `24` | The long window for low-and-slow detection |
| `--travel` | off | Flag impossible travel between logins (needs GeoIP; see privacy note) |
| `--travel-speed KMH` | `900` | Speed above which two logins count as impossible travel |
| `--scan-paths N` | `3` | Distinct scanner-only URLs from one IP in the window that flag a web scanner |
| `--scan-ports N` | `10` | Distinct ports from one IP blocked by the firewall inside the window that flag a port scan |
| `--ignore-user NAME` | none | Ignore events for this account (repeatable, case-insensitive), e.g. a monitoring account |
| `--sudo-threshold N` | `3` | Failed `sudo`/`su` attempts by one account in the window that are flagged |
| `--geoip-cache FILE` | none | Remember GeoIP answers between runs (lookups are also rate-limited to about 40/min) |
| `--geoip-db FILE` | none | Use a local MaxMind GeoLite2/GeoIP2 City `.mmdb` file instead of ip-api.com (`pip install geoip2`); no IP leaves your machine |
| `--blocklist FILE` | none | Write block commands for attacking IPs (never run automatically) |
| `--blocklist-format` | `plain` | `plain`, `ufw`, `iptables` or `nft` |
| `--blocklist-private` | off | Also include private/documentation-range IPs (skipped by default so you cannot lock yourself out) |
| `--baseline FILE` | none | An earlier `--json` file; only alerts *not* in it are exported, notified and counted by `--fail-on-alert` |
| `--update-baseline` | off | Add this run's alerts to the `--baseline` file afterwards |
| `--webhook URL` | none | POST alerts as JSON (`text` and `content` keys). Can also come from the `LOG_ANALYSER_WEBHOOK` variable so the secret URL stays out of your shell history |
| `--smtp HOST[:PORT]`, `--mail-to`, `--mail-from` | none | Email alerts; `SMTP_USER` / `SMTP_PASSWORD` environment variables log in (STARTTLS on 587, SSL on 465) |
| `--notify-min-severity` | `HIGH` | Lowest severity sent by webhook/email (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `--follow` | off | Watch one plain-text SSH log and print/notify new alerts as they appear (Ctrl+C to stop) |
| `--follow-hours H`, `--follow-interval S` | `24`, `1` | How much history `--follow` keeps in memory, and how often it checks the file |

Examples:

```bash
# Stricter rules
python log_analyser.py sample_logs/auth.log --threshold 3 --window 2 --night-start 22 --night-end 6

# Windows Security log
python log_analyser.py sample_logs/windows_security.csv

# Several files at once, including rotated gzip logs, with the new login checks
python log_analyser.py auth.log auth.log.1.gz --new-ip --multi-ip 3

# Pipe a log in (stdin is plain text; use zcat/gunzip for compressed data)
zcat auth.log.2.gz | python log_analyser.py - --no-color

# Learned hours, top 3 attackers, save results
python log_analyser.py sample_logs/auth.log --learn --top 3 --json alerts.json --csv alerts.csv

# nginx / Apache access log: scanners and 401/403 floods
python log_analyser.py sample_logs/access.log

# Only report what is NEW since last time (run it from cron), and alert on the new HIGH+ ones
python log_analyser.py /var/log/auth.log --baseline known.json --update-baseline --webhook "$HOOK_URL" --fail-on-alert

# Block the attackers (review the file first, then run it yourself)
python log_analyser.py /var/log/auth.log --blocklist block.sh --blocklist-format ufw

# Watch a log live and email HIGH+ alerts
SMTP_USER=me SMTP_PASSWORD=... python log_analyser.py /var/log/auth.log --follow --smtp smtp.example.com:587 --mail-to ops@example.com

# Impossible travel with no IP leaving the machine
python log_analyser.py auth.log --travel --geoip-db GeoLite2-City.mmdb --geoip-cache geo.json
```

`--follow` reads the existing file first (those alerts are not repeated), then reports each *new* alert once. It survives log rotation and keeps only the last `--follow-hours` of events in memory. With `--baseline`, exports/notifications/exit codes use only the new alerts, while the terminal report still shows everything.

### Config file

Keys are the long option names with underscores. Unknown keys are rejected so typos don't pass silently.

```json
{
  "threshold": 3,
  "window": 2,
  "night_start": 22,
  "night_end": 6,
  "allow": ["10.0.0.0/8", "192.168.0.0/16"],
  "privileged": "root,admin,administrator,postgres",
  "fail_on_alert": true
}
```

```bash
python log_analyser.py auth.log --config analyser.json --html report.html
```

### `--learn` vs fixed night hours
Fixed hours flag *anyone* who logs in at night, including legitimate night-shift staff. With `--learn`, the tool builds each user's normal hours from their own successful logins and only flags logins far from that pattern (more than 3 hours from all their other logins; users with fewer than 3 logins are skipped). On the sample log, the fixed rule raises 3 false alarms about night-shift user `frank`, and `--learn` doesn't.

### GeoIP privacy note
`--geoip` sends public attacker IPs to the free service [ip-api.com](https://ip-api.com), and that free plan is **plain HTTP only**, so the addresses travel unencrypted. Private/reserved addresses are never sent, lookups are rate-limited and cached, and it is off by default. `--travel` additionally looks up the IPs of *successful* logins (your real users). To keep everything local, download a MaxMind GeoLite2 City database and use `--geoip-db`. Don't use the web lookup on logs where even the IPs are sensitive. The sample logs only contain reserved addresses, so they show "private/reserved address".

### Notifications and secrets
Webhook URLs are secrets: prefer the `LOG_ANALYSER_WEBHOOK` environment variable over `--webhook` (command-line arguments show up in process lists and shell history). Only `http://` and `https://` URLs are accepted. A failing webhook or mail server prints a warning but never stops the analysis. Blocklists are only written to a file; the tool never runs firewall commands itself.

### Expected log formats

**SSH-style text log:**

```
2026-10-01 03:12:44 sshd[1234]: Failed password for admin from 203.0.113.45 port 51234
2026-10-01 09:02:10 sshd[2001]: Accepted password for alice from 198.51.100.10 port 40022
```

Lines that don't match are skipped. To support another text format (for example the real `/var/log/auth.log`, which has no year), adjust `LINE_PATTERN` in `log_analyser.py`.

Also understood: `Failed/Accepted keyboard-interactive/pam`, `Invalid user X from IP`, `Connection closed by authenticating user X IP`, `sudo: bob : 3 incorrect password attempts` and `FAILED SU`. The "weak" lines (`Invalid user`, `Connection closed…`) only count when sshd did not also log a `Failed …` line for the same process id and IP, so one attempt is never counted twice.

Timestamps can be `2026-10-01 10:00:00`, journalctl/RFC3339 `2026-10-01T10:00:00+0000` (the zone suffix is ignored, so times stay as written in the log) or classic syslog `Oct  3 02:14:05`.

**Firewall lines** inside a syslog/ufw log are read by the same parser: any line with `SRC=`, `DPT=` and a `BLOCK`/`DROP`/`REJECT`/`DENY` word counts as a blocked attempt (`sample_logs/ufw.log`). They never count as logins; `--scan-ports` different ports from one IP in the window raise a port-scan alert.

**nginx / Apache access log** ("combined" format, `--format web` or a file name containing `access`):

```
203.0.113.99 - - [01/Oct/2026:05:00:00 +0000] "GET /.env HTTP/1.1" 404 512 "-" "Mozilla/5.0"
```

A 401/403 on an ordinary path is a failed login (user = the HTTP-auth name or `-`); a failed `POST /wp-login.php` (WordPress answers 200) also counts; a 4xx on a scanner-only URL (`/.env`, `/.git/`, `/phpmyadmin`, `/xmlrpc.php` …) is a probe, and `--scan-paths` different probes from one IP raise a web-scanner alert. Web logs contain no reliable "success", so only failures are analysed.

**Windows Security log (CSV):** columns `TimeCreated, EventId, TargetUserName, IpAddress`. Event 4625 is a failed logon, 4624 a successful one and 4740 an account lockout. An optional `LogonType` column drops service/batch logons (only types 2, 3, 7, 10 and 11 are kept), and a local logon with no address (`-`, `::1`) is shown as `local` instead of being lumped in with a real source. You can export your own from an elevated PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4740} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated    = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
      EventId        = $_.Id
      TargetUserName = $d['TargetUserName']
      IpAddress      = $d['IpAddress']
      LogonType      = $d['LogonType']
      CallerComputerName = $d['CallerComputerName']  # 4740 lockouts only: the machine the bad logons came from
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

### 6. Distributed attacks
**What:** One account failing from several *different* IPs inside the window (default: 5 or more IPs).

**Why it matters:** A botnet can split a guessing run across many addresses so that no single IP crosses the brute-force threshold. Grouping by target account exposes it. Blocking one IP won't help, so consider lockouts, MFA or geo-restrictions on that account. (The sample logs don't contain this pattern; the unit tests cover it.)

### 7. Logins from a new IP (`--new-ip`)
**What:** A successful login by an account from an IP it has never logged in from earlier in the log. The account needs at least 3 earlier successful logins, otherwise every IP would look new, and each new IP is reported once.

**Why it matters:** People tend to log in from the same few places. A valid login from somewhere new is how a stolen password usually shows up, so it is a cheap, low-noise hint to check. It is off by default because a short log has little history; point it at several days or weeks of logs.

### 8. One account, many IPs (`--multi-ip N`)
**What:** One account logging in successfully from N or more different IPs inside the window.

**Why it matters:** A single person rarely logs in from several networks within minutes. It suggests shared credentials, or an attacker using a stolen password while the real user is also online.

### 9. IP risk score
**What:** Every alert is worth points by severity (CRITICAL 40, HIGH 20, MEDIUM 10, LOW 3). Points add up per source IP, capped at 100.

**Why it matters:** One IP that brute-forces, sprays *and* logs in successfully is far more urgent than one that only logged in at an odd hour. The ranking tells you which IP to deal with first.

### 10. Account takeover
**What:** A successful login on an account that had `--threshold` or more failures inside the window (from any mix of IPs), or that succeeded during a distributed attack on it. Logins already reported as a possible compromise are skipped, and the failures are cleared after a login so one burst gives one alert.

**Why it matters:** The "possible compromise" rule only fires when the *same IP* brute-forced and then got in. A botnet that spreads guesses over many addresses, then logs in from one of them, slips past it. A real user who fumbles their password five times will also trigger this, so treat it as "check with the user", not proof.

### 11. Low-and-slow attacks
**What:** An IP with 20+ failures inside 24 hours (`--slow-threshold`, `--slow-window`) that did not already trip the brute-force rule.

**Why it matters:** Patient attackers deliberately stay under per-minute thresholds. A long window catches them. `--slow-threshold 0` turns it off.

### 12. Impossible travel (`--travel`)
**What:** Successive successful logins by one account from IPs whose locations are more than 100 km apart and would need more than 900 km/h (`--travel-speed`).

**Why it matters:** One person cannot be in London and New York 30 minutes apart; a stolen credential can. VPNs, mobile carriers and corporate proxies cause false alarms, so use it as a prompt to verify. It needs coordinates, so private/reserved addresses are ignored.

### 13. Windows lockouts, web scanners and sudo/su failures
**What:** Event 4740 lockouts are listed (an account being hammered). Web-server IPs requesting several scanner-only URLs are flagged. Accounts with 3+ failed `sudo`/`su` attempts in the window are flagged.

**Why it matters:** Each is a different angle on the same story: someone probing for a way in, or for root. These sections only appear when the log contains that kind of evidence.

### 14. Port scans
**What:** An IP whose connections your firewall blocked on 10 or more different ports inside the window (`--scan-ports`).

**Why it matters:** Scanning is reconnaissance: the attacker is mapping which services you expose before choosing what to attack. Someone knocking repeatedly on one port is just noise, so only the number of *different* ports counts.

## About the sample data

`generate_sample_logs.py` builds three days of fake traffic with a fixed random seed, so the results are repeatable. `auth.log` contains:

- Normal staff logins in office hours, with the odd typo
- A fast brute-force attack on `admin` / `root`
- A slower password-spraying attack across common usernames
- An attacker who eventually guesses `carol`'s password (the compromise case)
- Two odd-hour logins by `dave` and `bob`
- A night-shift worker (`frank`) who always logs in around 2 a.m.
- Harmless background noise (single failures)
- A low-and-slow attacker (24 failures over 22 hours against `backup`)
- A takeover of `erin`: six IPs each guess once, then one gets in
- One attempt logged three ways, a PAM failure and three failed `sudo` attempts by `bob`

`windows_security.csv` has a brute-force burst on `Administrator` that ends in a successful logon, an account lockout, normal logons, a local console logon, a service logon (ignored) and one odd-hour logon.

`access.log` has a vulnerability scanner, a Basic-auth password guesser and one normal visitor. Impossible travel needs public IPs, so it is covered by the unit tests rather than the sample data.

All IPs are from reserved documentation ranges (RFC 5737), so none belong to real systems.

## Limitations and ideas for improvement

- Not supported: the raw `.evtx` format, Windows day-first dates (`25/10/2025`, ambiguous so refused), and time-zone conversion (times are used as written)
- Web logs only yield failures, so there is no compromise or new-IP detection for them; WordPress login detection is a heuristic
- `--follow` handles one plain-text SSH log; `--geoip-db` is written against the `geoip2` API but is only unit-tested with a stand-in reader, not a real `.mmdb` file
- Baseline alerts are matched on type, IP, user and start time, so a burst that keeps growing can be reported again when its worst window shifts
- `--learn` is a simple heuristic and needs a few logins per user; a real system would use longer baselines
- Threat-intelligence reputation lookups (e.g. AbuseIPDB) would add context to attacking IPs
- Sudo/su failures have no source IP, and Windows event 4672 ("special privileges") is not parsed because the export has no usable account or address for it
- Deliberately left out: reputation lookups (AbuseIPDB, Tor lists) that need API keys and send your IPs to third parties, and running firewall commands automatically
- Only tested on Python 3.13 so far; there is no CI yet (run `python -m unittest` on the Python versions you care about)

## Disclaimer

For learning and defensive use on logs you are authorised to analyse.
