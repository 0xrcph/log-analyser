"""Login Log Analyser - a small tool for spotting suspicious login activity.

It reads an SSH-style auth log and looks for:
  1. Brute-force attempts  - many failed logins from one IP in a short time
  2. Unusual-hour logins   - successful logins late at night / early morning
  3. Possible compromise   - a successful login right after a brute-force burst
  4. Password spraying     - one IP trying many different accounts in a short time
  5. Targeted accounts, noisiest source IPs and an hourly histogram of failed logins
  6. Privileged logins - root/admin accounts logged into from an IP that failed first
  7. Distributed attacks - many IPs sharing the work of attacking one account
  8. A combined 0-100 risk score per source IP
  9. Logins from a never-seen-before IP (--new-ip) and one account used from many IPs (--multi-ip N)
 10. Account takeover - a success right after failures on the same account, from any IP
 11. Low-and-slow attacks - a patient IP spreading failures over many hours
 12. Impossible travel (--travel) - one account logging in from far-apart places too fast
 13. Windows lockouts (4740), web-server scanners/401/403 floods, repeated sudo/su failures

Log files can be plain text, gzip (.gz), several at once, or '-' to read from stdin.
Formats: SSH auth.log, Windows Security CSV, nginx/Apache access log (--format web).
Extras: --follow (live), --webhook / --smtp alerts, --blocklist, --baseline, GeoIP cache or local DB.

Usage:  python log_analyser.py sample_logs/auth.log
        python log_analyser.py sample_logs/windows_security.csv
        python log_analyser.py auth.log --learn --geoip --top 3 --json out.json --csv out.csv
        python log_analyser.py auth.log --allow 10.0.0.0/8 --since 2025-01-01 --spray-users 4 --fail-on-alert
        python log_analyser.py auth.log --privileged root --markdown report.md
        python log_analyser.py auth.log --config analyser.json --html report.html
        python log_analyser.py auth.log auth.log.1.gz --new-ip --multi-ip 3 --no-color
        python log_analyser.py auth.log --threshold 5 --window 5 --night-start 0 --night-end 6
"""

import argparse
import csv
import gzip
import html
import json
import ipaddress
import math
import os
import re
import smtplib
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timedelta
from email.message import EmailMessage

# ---------------------------------------------------------------- appearance
# ANSI colour codes. They make the report easier to read in a terminal.
if os.name == "nt":
    os.system("")  # tiny trick that switches on colour support in Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # so box-drawing characters print correctly

RED, YELLOW, GREEN, CYAN = "\033[91m", "\033[93m", "\033[92m", "\033[96m"
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
WIDTH = 72


def disable_colour():
    """Switch off ANSI colours (for --no-color or the NO_COLOR variable)."""
    global RED, YELLOW, GREEN, CYAN, BOLD, DIM, RESET
    RED = YELLOW = GREEN = CYAN = BOLD = DIM = RESET = ""


def banner(text):
    """Print a boxed title."""
    print(f"{CYAN}{BOLD}╔{'═' * (WIDTH - 2)}╗")
    print(f"║{text.center(WIDTH - 2)}║")
    print(f"╚{'═' * (WIDTH - 2)}╝{RESET}")


def section(title, colour):
    """Print a coloured section heading with a line under it."""
    print(f"\n{colour}{BOLD}▌ {title}{RESET}")
    print(f"{DIM}{'─' * WIDTH}{RESET}")


# ------------------------------------------------------------------- parsing
# Every parser turns a log line into an "event" dict: time, success, user, ip.
# Things that are not a login (lockouts, web scanner probes, sudo failures) are "specials":
# dicts with a "kind" of lockout / probe / priv_fail, kept in a separate list.
# Timestamps: '2025-10-03 02:14:05', journalctl/RFC3339 '2025-10-03T02:14:05+0000', or syslog 'Oct  3 02:14:05'.
TIME_PREFIX = (r"^(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
               r"|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) .*?")

# Failed/Accepted <method> for [invalid user] <user> from <ip>. The method can be password, publickey,
# keyboard-interactive/pam, gssapi-with-mic, hostbased, none ...
LINE_PATTERN = re.compile(
    TIME_PREFIX + r"(?P<result>Accepted|Failed) (?P<method>[\w/-]+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
# "Weak" lines: they show a failed attempt, but sshd often logs the same attempt again as a
# "Failed ..." line. They only count when no "Failed/Accepted" line shares their sshd pid and IP.
WEAK_PATTERNS = [
    re.compile(TIME_PREFIX + r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)"),
    re.compile(TIME_PREFIX + r"(?:Connection closed by|Disconnected from) authenticating user (?P<user>\S+) (?P<ip>[0-9a-fA-F:.]+)"),
]
SUDO_PATTERN = re.compile(TIME_PREFIX + r"sudo:\s+(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")
SU_PATTERNS = [
    re.compile(TIME_PREFIX + r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on"),
    re.compile(TIME_PREFIX + r"FAILED su for (?P<target>\S+) by (?P<user>\S+)"),
]
PID_PATTERN = re.compile(r"\[(\d+)\]:")
# Kernel firewall lines (ufw, iptables LOG rules): "... [UFW BLOCK] IN=eth0 SRC=203.0.113.5 DST=10.0.0.1 PROTO=TCP DPT=22 ..."
TIME_ONLY = re.compile(TIME_PREFIX)
FIREWALL_WORDS = re.compile(r"\b(?:BLOCK|DROP|REJECT|DENIED|DENY)\b", re.I)
FW_SRC, FW_DPT, FW_PROTO = (re.compile(r"\bSRC=([0-9a-fA-F:.]+)"), re.compile(r"\bDPT=(\d+)"), re.compile(r"\bPROTO=(\w+)"))


def parse_time(text, year):
    """Parse '2025-10-03 02:14:05' (ISO) or classic syslog 'Oct  3 02:14:05' (no year, so `year` is used)."""
    if text[0].isdigit():  # the time zone suffix, if any, is dropped: times stay as written in the log
        return datetime.strptime(text[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def open_text(path, **kwargs):
    """Open a log for reading as text: '-' is stdin, '*.gz' is decompressed on the fly."""
    if path == "-":
        return sys.stdin
    if path.lower().endswith(".gz"):
        return gzip.open(path, "rt", **kwargs)
    return open(path, **kwargs)


class SshParser:
    """Turns SSH/auth.log lines into events one at a time (used for files and for --follow).

    Syslog lines carry no year, so `year` (default: this year) is assumed. A date that would
    land in the future is moved back a year, which handles a log that spans New Year.
    Unreadable lines are skipped.
    """

    def __init__(self, year=None, memory=20000):
        self.year = year or datetime.now().year
        self.memory = memory
        self.strong = OrderedDict()  # (pid, ip) of attempts already counted from a Failed/Accepted line
        self.weak = {}               # (pid, ip) -> weak event that is dropped if a strong line shows up

    def _when(self, text):
        try:
            when = parse_time(text, self.year)
            if not text[0].isdigit() and when > datetime.now() + timedelta(days=1):
                when = when.replace(year=when.year - 1)
            return when
        except ValueError:
            return None  # e.g. 'Feb 29' in a non-leap year

    @staticmethod
    def _key(line, ip):
        pid = PID_PATTERN.search(line)
        return (pid.group(1), ip) if pid else None  # no pid = cannot tell attempts apart, so never merge

    def feed(self, line, events, specials):
        """Parse one line; append to `events` / `specials` (and remove a weak event it replaces)."""
        match = LINE_PATTERN.match(line)
        if match:
            when = self._when(match["time"])
            if when is None:
                return
            key = self._key(line, match["ip"])
            if key:
                self.strong[key] = True
                if len(self.strong) > self.memory:
                    self.strong.popitem(last=False)
                weak = self.weak.pop(key, None)
                if weak is not None:
                    for i in range(len(events) - 1, -1, -1):
                        if events[i] is weak:
                            del events[i]
                            break
            events.append({"time": when, "success": match["result"] == "Accepted",
                           "user": match["user"], "ip": match["ip"]})
            return
        for pattern in WEAK_PATTERNS:
            match = pattern.match(line)
            if match:
                when = self._when(match["time"])
                key = self._key(line, match["ip"])
                if when is None or (key and key in self.strong):
                    return
                event = {"time": when, "success": False, "user": match["user"] or "(empty)", "ip": match["ip"]}
                events.append(event)
                if key:
                    self.weak[key] = event
                    if len(self.weak) > self.memory:
                        del self.weak[next(iter(self.weak))]
                return
        if "SRC=" in line and "DPT=" in line and FIREWALL_WORDS.search(line):
            stamp, src, dpt = TIME_ONLY.match(line), FW_SRC.search(line), FW_DPT.search(line)
            when = self._when(stamp["time"]) if stamp else None
            if when is not None and src and dpt:
                proto = FW_PROTO.search(line)
                specials.append({"kind": "fw_block", "time": when, "ip": src.group(1), "port": int(dpt.group(1)),
                                 "proto": proto.group(1).upper() if proto else "?"})
            return
        match = SUDO_PATTERN.match(line)
        if match:
            via, count, user = "sudo", int(match["n"]), match["user"]
        else:
            match = next((m for m in (p.match(line) for p in SU_PATTERNS) if m), None)
            via, count, user = "su", 1, (match["user"] if match else None)
        if match:
            when = self._when(match["time"])
            if when is not None:
                specials.append({"kind": "priv_fail", "time": when, "user": user, "ip": "local",
                                 "count": count, "via": via})


# Windows logon types worth looking at: 2 interactive, 3 network, 7 unlock, 10 remote desktop, 11 cached.
# Service (5), batch (4) and system logons are ignored when the CSV has a LogonType column.
WINDOWS_LOGON_TYPES = {"2", "3", "7", "10", "11"}
LOCAL_IPS = {"", "-", "::1", "127.0.0.1", "::ffff:127.0.0.1"}


def parse_windows_time(text):
    """ISO ('2025-10-01 10:00:00' or with a 'T'), or US month-first ('10/01/2025 10:00:00', 12-hour with AM/PM too).

    Day-first dates (01/10/2025) are ambiguous with month-first ones, so they are rejected rather than guessed.
    """
    text = text.strip()
    if text[:4].isdigit():
        return datetime.strptime(text[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S")
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    raise ValueError(f"unrecognised Windows time: {text!r}")


def parse_windows_csv(path, specials=None):
    """Read Windows Security events exported to CSV (see README for the export command).

    Event 4625 = failed logon, event 4624 = successful logon, event 4740 = account lockout.
    Needed columns: TimeCreated, EventId, TargetUserName, IpAddress. An optional LogonType
    column filters out service/batch logons. Local logons (IpAddress "-" or "::1") get the
    address "local" instead of being mixed up with a real source. Lockouts go to `specials`.
    """
    events = []
    with open_text(path, encoding="utf-8-sig", newline="") as f:  # utf-8-sig handles PowerShell's BOM
        for row in csv.DictReader(f):
            event_id = row["EventId"]
            if event_id not in ("4624", "4625", "4740"):
                continue  # ignore every other kind of Windows event
            when = parse_windows_time(row["TimeCreated"])
            if event_id == "4740":
                if specials is not None:
                    specials.append({"kind": "lockout", "time": when, "user": row["TargetUserName"],
                                     "ip": (row.get("CallerComputerName") or row["IpAddress"] or "").strip() or "unknown"})
                continue
            logon_type = (row.get("LogonType") or "").strip()
            if logon_type and logon_type not in WINDOWS_LOGON_TYPES:
                continue
            ip = (row["IpAddress"] or "").strip()
            events.append({
                "time": when,
                "success": event_id == "4624",
                "user": row["TargetUserName"],
                "ip": "local" if ip in LOCAL_IPS else ip,
            })
    return events


# nginx / Apache "combined" access log: ip - user [10/Oct/2025:13:55:36 +0000] "GET /path HTTP/1.1" 401 123 ...
WEB_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\] '
    r'"(?:(?P<method>[A-Z]+) (?P<path>\S+)[^"]*|[^"]*)" (?P<status>\d{3})'
)
# Paths that only vulnerability scanners and bots ask for.
SCANNER_PATHS = re.compile(
    r"(?i)(?:^|/)(?:wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|pma|\.env|\.git(?:/|$)|\.aws|\.ssh|id_rsa|"
    r"config\.php|admin\.php|administrator|manager/html|server-status|cgi-bin|vendor/phpunit|boaform|"
    r"actuator|solr|setup\.php|eval-stdin\.php|backup\.(?:sql|zip|tar))"
)


def parse_web_log(path, specials=None):
    """Read an nginx/Apache access log. Only failures are recorded (there is no reliable 'success').

    * 401/403 on an ordinary path        -> a failed login event for the HTTP-auth user ('-' if none)
    * a failed POST to /wp-login.php     -> a failed login event (WordPress answers a bad password with 200)
    * 4xx on a scanner path (/.env ...)  -> a 'probe' special, counted by the web-scanner rule
    """
    events = []
    with open_text(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            match = WEB_PATTERN.match(line)
            if not match:
                continue
            try:
                when = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                continue
            status, target = int(match["status"]), match["path"] or ""
            scanner = bool(SCANNER_PATHS.search(target))
            if scanner and status >= 400:
                if specials is not None:
                    specials.append({"kind": "probe", "time": when, "ip": match["ip"], "path": target.split("?")[0],
                                     "status": status})
            elif status in (401, 403) or (match["method"] == "POST" and "wp-login.php" in target and status == 200):
                events.append({"time": when, "success": False, "user": match["user"], "ip": match["ip"]})
    return events


def detect_format(path, log_format):
    """Pick a parser name. 'auto' guesses from the file name: *.csv = windows, *access* = web, else ssh."""
    if log_format != "auto":
        return log_format
    name = os.path.basename(path).lower()
    if name.endswith(".gz"):
        name = name[:-3]
    if name.endswith(".csv"):
        return "windows"
    if "access" in name:
        return "web"
    return "ssh"


def parse_log(path, log_format="auto", year=None, specials=None):
    """Read one log file and return its events (non-login findings are appended to `specials`)."""
    kind = detect_format(path, log_format)
    if kind == "windows":
        return parse_windows_csv(path, specials)
    if kind == "web":
        return parse_web_log(path, specials)
    return parse_ssh_log(path, year, specials)


def parse_ssh_log(path, year=None, specials=None):
    """Read an SSH log (ISO or classic syslog timestamps) and return a list of events (dicts)."""
    parser = SshParser(year)
    events, extra = [], specials if specials is not None else []
    with open_text(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parser.feed(line, events, extra)
    return events


# ----------------------------------------------------------------- detection
def find_brute_force(events, threshold, window_minutes):
    """Find IPs with `threshold` or more failures inside any `window_minutes` window.

    Returns a dict: ip -> info about the worst burst.
    """
    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(list)
    for e in events:
        if not e["success"]:
            failures_by_ip[e["ip"]].append(e)

    results = {}
    for ip, fails in failures_by_ip.items():
        fails.sort(key=lambda e: e["time"])
        start = 0
        best = None  # (count, first_event, last_event)
        # Sliding window: move `start` forward until the window is small enough.
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            count = end - start + 1
            if count >= threshold and (best is None or count > best[0]):
                best = (count, fails[start], fails[end])
        if best:
            burst = [e for e in fails if best[1]["time"] <= e["time"] <= best[2]["time"]]
            results[ip] = {
                "count": best[0],
                "first": best[1]["time"],
                "last": best[2]["time"],
                "users": sorted({e["user"] for e in burst}),
                "total_failures": len(fails),
            }
    return results


def find_password_spray(events, min_users, window_minutes):
    """Find IPs that failed against `min_users` or more different accounts inside one window.

    Brute force hammers one account; spraying tries a few passwords on many accounts
    so it slips under per-account lockouts. Returns ip -> info about the widest burst.
    """
    window = timedelta(minutes=window_minutes)
    failures_by_ip = defaultdict(list)
    for e in events:
        if not e["success"]:
            failures_by_ip[e["ip"]].append(e)

    results = {}
    for ip, fails in failures_by_ip.items():
        fails.sort(key=lambda e: e["time"])
        start = 0
        best = None  # (distinct users, first_event, last_event)
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            users = {e["user"] for e in fails[start:end + 1]}
            if len(users) >= min_users and (best is None or len(users) > best[0]):
                best = (len(users), fails[start], fails[end])
        if best:
            burst = [e for e in fails if best[1]["time"] <= e["time"] <= best[2]["time"]]
            results[ip] = {
                "user_count": best[0],
                "first": best[1]["time"],
                "last": best[2]["time"],
                "users": sorted({e["user"] for e in burst}),
                "attempts": len(burst),
            }
    return results


def find_distributed_attack(events, min_ips, window_minutes):
    """Find accounts failed from `min_ips` or more different IPs inside one window.

    This is the mirror image of spraying: a botnet shares the work so that no single
    IP trips the per-IP brute-force rule. Returns user -> info about the widest burst.
    """
    window = timedelta(minutes=window_minutes)
    failures_by_user = defaultdict(list)
    for e in events:
        if not e["success"]:
            failures_by_user[e["user"]].append(e)

    results = {}
    for user, fails in failures_by_user.items():
        fails.sort(key=lambda e: e["time"])
        start = 0
        best = None  # (distinct ips, first_event, last_event)
        for end in range(len(fails)):
            while fails[end]["time"] - fails[start]["time"] > window:
                start += 1
            ips = {e["ip"] for e in fails[start:end + 1]}
            if len(ips) >= min_ips and (best is None or len(ips) > best[0]):
                best = (len(ips), fails[start], fails[end])
        if best:
            burst = [e for e in fails if best[1]["time"] <= e["time"] <= best[2]["time"]]
            results[user] = {
                "ip_count": best[0],
                "first": best[1]["time"],
                "last": best[2]["time"],
                "ips": sorted({e["ip"] for e in burst}),
                "attempts": len(burst),
            }
    return results


RISK_WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}


def risk_scores(alerts, limit=5):
    """Combine all alerts per source IP into one 0-100 score: [(ip, score, [alert types]), ...].

    One loud signal is serious, but several different signals from the same IP are worse,
    so scores add up (capped at 100). Alerts without a single IP (distributed attacks) are skipped.
    """
    total, kinds = defaultdict(int), defaultdict(set)
    for a in alerts:
        try:
            ipaddress.ip_address(a["ip"])
        except ValueError:
            continue
        total[a["ip"]] += RISK_WEIGHTS.get(a["severity"], 0)
        kinds[a["ip"]].add(a["type"])
    ranked = sorted(total, key=lambda ip: (-total[ip], ip))
    return [(ip, min(100, total[ip]), sorted(kinds[ip])) for ip in ranked[:limit]]


def top_targeted_users(events, limit=5):
    """Rank accounts by number of failed logins: [(user, failures), ...]."""
    counts = defaultdict(int)
    for e in events:
        if not e["success"]:
            counts[e["user"]] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def top_source_ips(events, limit=5):
    """Rank source IPs by total failed logins (even below the brute-force threshold)."""
    counts = defaultdict(int)
    for e in events:
        if not e["success"]:
            counts[e["ip"]] += 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def failures_by_hour(events):
    """Count failed logins for each hour of the day (list of 24 numbers)."""
    counts = [0] * 24
    for e in events:
        if not e["success"]:
            counts[e["time"].hour] += 1
    return counts


def filter_events(events, allow, since, until, ignore_users=()):
    """Drop events from allow-listed IPs/networks, ignored accounts and outside the --since/--until range."""
    ignored = {u.lower() for u in ignore_users}
    networks = []
    for item in allow:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            sys.exit(f"Error: invalid --allow value: {item}")

    def allowed(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in networks)

    return [e for e in events
            if not allowed(e["ip"])
            and str(e.get("user", "")).lower() not in ignored
            and (since is None or e["time"] >= since)
            and (until is None or e["time"] < until + timedelta(days=1))]


def parse_date(text):
    """argparse helper: turn YYYY-MM-DD into a datetime."""
    try:
        return datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a date in YYYY-MM-DD form: {text}")


def find_unusual_hours(events, night_start, night_end):
    """Return successful logins that happened between night_start and night_end (hours)."""
    return [e for e in events if e["success"] and night_start <= e["time"].hour < night_end]


def hour_gap(a, b):
    """Distance between two hours of the day, wrapping round midnight (23h and 1h are 2 apart)."""
    diff = abs(a - b)
    return min(diff, 24 - diff)


def find_user_anomalies(events, max_gap=3, min_logins=3):
    """Learn each user's normal hours and flag logins far away from all their other logins.

    A login is odd if it is more than `max_gap` hours from every other successful
    login by the same user. Users with fewer than `min_logins` logins are skipped,
    because there is not enough history to know what is normal.
    """
    logins_by_user = defaultdict(list)
    for e in events:
        if e["success"]:
            logins_by_user[e["user"]].append(e)

    odd = []
    for logins in logins_by_user.values():
        if len(logins) < min_logins:
            continue
        for i, e in enumerate(logins):
            others = [o["time"].hour for j, o in enumerate(logins) if j != i]
            if min(hour_gap(e["time"].hour, h) for h in others) > max_gap:
                odd.append(e)
    return sorted(odd, key=lambda e: e["time"])


def find_compromises(events, brute_force):
    """A success from an IP that was also brute-forcing = likely a breach."""
    hits = []
    for e in events:
        if e["success"] and e["ip"] in brute_force and e["time"] >= brute_force[e["ip"]]["first"]:
            hits.append(e)
    return hits


def find_privileged_logins(events, privileged, compromises):
    """Successful logins to privileged accounts from an IP that had already failed.

    Logins already reported as a possible compromise are skipped so nothing is
    counted twice. Account names are compared case-insensitively.
    """
    names = {p.lower() for p in privileged}
    already = {id(e) for e in compromises}
    failed_ips = set()
    hits = []
    for e in events:  # events are time-sorted, so "already failed" means earlier in the log
        if not e["success"]:
            failed_ips.add(e["ip"])
        elif e["user"].lower() in names and e["ip"] in failed_ips and id(e) not in already:
            hits.append(e)
    return hits


def find_new_source_logins(events, min_history=3):
    """Successful logins from an IP the account has never logged in from before.

    An account needs at least `min_history` earlier successful logins first, otherwise
    every IP would look new. Only the first login from each new IP is reported.
    """
    seen = defaultdict(set)    # user -> IPs it has already logged in from
    count = defaultdict(int)   # user -> number of earlier successful logins
    hits = []
    for e in events:  # events are time-sorted
        if not e["success"]:
            continue
        if count[e["user"]] >= min_history and e["ip"] not in seen[e["user"]]:
            hits.append(e)
        seen[e["user"]].add(e["ip"])
        count[e["user"]] += 1
    return hits


def find_multi_ip_logins(events, min_ips, window_minutes):
    """Find accounts that logged in successfully from `min_ips` or more IPs inside one window.

    One person rarely appears from several networks at once, so this points at shared
    or stolen credentials. Returns user -> info about the widest burst.
    """
    window = timedelta(minutes=window_minutes)
    logins_by_user = defaultdict(list)
    for e in events:
        if e["success"]:
            logins_by_user[e["user"]].append(e)

    results = {}
    for user, logins in logins_by_user.items():
        logins.sort(key=lambda e: e["time"])
        start = 0
        best = None  # (distinct ips, first_event, last_event)
        for end in range(len(logins)):
            while logins[end]["time"] - logins[start]["time"] > window:
                start += 1
            ips = {e["ip"] for e in logins[start:end + 1]}
            if len(ips) >= min_ips and (best is None or len(ips) > best[0]):
                best = (len(ips), logins[start], logins[end])
        if best:
            burst = [e for e in logins if best[1]["time"] <= e["time"] <= best[2]["time"]]
            results[user] = {
                "ip_count": best[0],
                "first": best[1]["time"],
                "last": best[2]["time"],
                "ips": sorted({e["ip"] for e in burst}),
                "logins": len(burst),
            }
    return results


def widest_burst(items, window, minimum, key=None, weight=None):
    """Slide a time window over time-sorted `items` and return (value, first, last) for the widest hit.

    With `key`, value = number of distinct key(item) in the window; with `weight`, value = sum of
    weight(item); otherwise value = number of items. Returns None when no window reaches `minimum`.
    """
    start, running, best = 0, 0, None
    for end, item in enumerate(items):
        running += weight(item) if weight else 1
        while item["time"] - items[start]["time"] > window:
            running -= weight(items[start]) if weight else 1
            start += 1
        value = len({key(i) for i in items[start:end + 1]}) if key else running
        if value >= minimum and (best is None or value > best[0]):
            best = (value, items[start], item)
    return best


def find_account_takeovers(events, threshold, window_minutes, distributed=None, already=()):
    """A success on an account that was just being failed against - from ANY source IP.

    `find_compromises` only catches a success from an IP that itself brute-forced. This also
    catches a success after `threshold` failures on the same account inside the window
    (even spread over many IPs), or after a distributed attack on that account.
    Logins listed in `already` (reported as compromises) are skipped. Failures are cleared
    once the account logs in, so one burst gives one alert.
    """
    window = timedelta(minutes=window_minutes)
    distributed = distributed or {}
    skip = {id(e) for e in already}
    recent = defaultdict(deque)  # user -> failures still inside the window
    hits = []
    for e in events:  # events are time-sorted
        failures = recent[e["user"]]
        while failures and e["time"] - failures[0]["time"] > window:
            failures.popleft()
        if not e["success"]:
            failures.append(e)
            continue
        attack = distributed.get(e["user"])
        if id(e) not in skip:
            if len(failures) >= threshold:
                hits.append({**e, "reason": f"{len(failures)} failed logins on this account in the last {window_minutes} min "
                                            f"(from {len({f['ip'] for f in failures})} IP(s))"})
            elif attack and attack["first"] <= e["time"] <= attack["last"] + window:
                hits.append({**e, "reason": f"login during a distributed attack from {attack['ip_count']} IPs"})
        failures.clear()
    return hits


def find_low_and_slow(events, threshold, window_hours, loud=()):
    """IPs that stay under the per-minute radar but fail `threshold`+ times inside a long window.

    IPs already reported as brute force (`loud`) are skipped. Returns ip -> burst info.
    """
    if threshold <= 0:
        return {}
    found = find_brute_force(events, threshold, int(window_hours * 60))
    return {ip: info for ip, info in found.items() if ip not in loud}


def haversine_km(a, b):
    """Great-circle distance in km between two (lat, lon) pairs."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def find_impossible_travel(events, locate, max_kmh=900.0, min_km=100.0):
    """Successive logins by one account from places too far apart to travel between in the time.

    `locate(ip)` returns {"lat", "lon", "label"} or None (private/unknown addresses are ignored).
    900 km/h is roughly a passenger jet. VPN or mobile-carrier IPs can cause false alarms.
    """
    last, hits = {}, []  # user -> (event, location)
    for e in events:
        if not e["success"]:
            continue
        place = locate(e["ip"])
        if not place:
            continue
        before = last.get(e["user"])
        if before and before[0]["ip"] != e["ip"]:
            km = haversine_km((before[1]["lat"], before[1]["lon"]), (place["lat"], place["lon"]))
            hours = max((e["time"] - before[0]["time"]).total_seconds() / 3600, 1 / 60)
            if km >= min_km and km / hours > max_kmh:
                hits.append({**e, "from_ip": before[0]["ip"], "km": round(km), "hours": hours,
                             "from_place": before[1]["label"], "to_place": place["label"]})
        last[e["user"]] = (e, place)
    return hits


def find_web_scanners(specials, min_paths, window_minutes):
    """IPs that requested `min_paths`+ different scanner-only URLs (/.env, /wp-login.php ...) in one window."""
    window = timedelta(minutes=window_minutes)
    probes = defaultdict(list)
    for s in specials:
        if s["kind"] == "probe":
            probes[s["ip"]].append(s)
    results = {}
    for ip, items in probes.items():
        items.sort(key=lambda s: s["time"])
        best = widest_burst(items, window, min_paths, key=lambda s: s["path"])
        if best:
            burst = [s for s in items if best[1]["time"] <= s["time"] <= best[2]["time"]]
            results[ip] = {"path_count": best[0], "first": best[1]["time"], "last": best[2]["time"],
                           "paths": sorted({s["path"] for s in burst}), "requests": len(burst)}
    return results


def find_port_scans(specials, min_ports, window_minutes):
    """IPs the firewall blocked on `min_ports`+ different ports inside one window (a port scan)."""
    window = timedelta(minutes=window_minutes)
    blocks = defaultdict(list)
    for s in specials:
        if s["kind"] == "fw_block":
            blocks[s["ip"]].append(s)
    results = {}
    for ip, items in blocks.items():
        items.sort(key=lambda s: s["time"])
        best = widest_burst(items, window, min_ports, key=lambda s: (s["proto"], s["port"]))
        if best:
            burst = [s for s in items if best[1]["time"] <= s["time"] <= best[2]["time"]]
            results[ip] = {"port_count": best[0], "first": best[1]["time"], "last": best[2]["time"],
                           "ports": sorted({s["port"] for s in burst}), "attempts": len(burst)}
    return results


def find_priv_failures(specials, threshold, window_minutes):
    """Accounts with `threshold`+ failed sudo/su attempts in one window (someone probing for root)."""
    window = timedelta(minutes=window_minutes)
    by_user = defaultdict(list)
    for s in specials:
        if s["kind"] == "priv_fail":
            by_user[s["user"]].append(s)
    results = {}
    for user, items in by_user.items():
        items.sort(key=lambda s: s["time"])
        best = widest_burst(items, window, threshold, weight=lambda s: s["count"])
        if best:
            results[user] = {"count": best[0], "first": best[1]["time"], "last": best[2]["time"],
                             "via": sorted({s["via"] for s in items})}
    return results


def find_lockouts(specials):
    """Windows account lockouts (event 4740)."""
    return [s for s in specials if s["kind"] == "lockout"]


# -------------------------------------------------------------------- geoip
# Free ip-api.com allows ~45 requests a minute over plain HTTP only (no HTTPS on the free plan),
# so lookups are rate-limited, cached in memory (and optionally on disk), and a local MaxMind
# database (--geoip-db) avoids sending any address over the network at all.
GEO_CACHE = {}           # ip -> {"label": str, "lat": float, "lon": float}
GEO_MIN_INTERVAL = 1.5   # seconds between web requests
GEO_READER = None        # geoip2 database reader when --geoip-db is used
_last_geo_request = [0.0]


def open_geo_db(path):
    """Open a MaxMind GeoLite2/GeoIP2 City .mmdb file (needs `pip install geoip2`)."""
    global GEO_READER
    try:
        import geoip2.database
    except ImportError:
        sys.exit("Error: --geoip-db needs the geoip2 package (pip install geoip2)")
    try:
        GEO_READER = geoip2.database.Reader(path)
    except OSError as err:
        sys.exit(f"Error: cannot open GeoIP database {path}: {err}")


def load_geo_cache(path):
    """Load a previous run's lookups so the same IP is never asked about twice. Bad files are ignored."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            GEO_CACHE.update({ip: info for ip, info in data.items() if isinstance(info, dict) and "label" in info})
    except (OSError, ValueError):
        pass


def save_geo_cache(path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(GEO_CACHE, f)
    except OSError as err:
        print(f"{YELLOW}Warning: could not save GeoIP cache: {err}{RESET}")


def _lookup_db(ip):
    try:
        r = GEO_READER.city(ip)
    except Exception:  # address not in the database
        return {"label": "no location found"}
    place = ", ".join(x for x in (r.city.name, r.country.name) if x) or "unknown place"
    info = {"label": place}
    if r.location.latitude is not None and r.location.longitude is not None:
        info.update(lat=r.location.latitude, lon=r.location.longitude)
    return info


def _lookup_web(ip):
    wait = GEO_MIN_INTERVAL - (time.monotonic() - _last_geo_request[0])
    if wait > 0:
        time.sleep(wait)
    _last_geo_request[0] = time.monotonic()
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,lat,lon"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.load(response)
        if data.get("status") != "success":
            return {"label": "no location found"}
        return {"label": f"{data['city']}, {data['country']} ({data['isp']})", "lat": data["lat"], "lon": data["lon"]}
    except Exception:  # no internet, rate limited, etc. - not cached, so a later run can retry
        return {"label": "lookup failed", "failed": True}


def geo_info(ip):
    """Where is this IP? Returns {"label": ..., optionally "lat"/"lon"}. Private addresses are never sent anywhere."""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {"label": "not a valid IP address"}
    if not address.is_global:
        return {"label": "private/reserved address (not looked up)"}
    info = _lookup_db(ip) if GEO_READER else _lookup_web(ip)
    if not info.get("failed"):
        GEO_CACHE[ip] = info
    return info


def lookup_ip(ip):
    """Text description of an IP's location (country, city, ISP), safe to print."""
    return geo_info(ip)["label"]


def locate(ip):
    """geo_info for find_impossible_travel: None unless the IP has coordinates."""
    info = geo_info(ip)
    return info if "lat" in info else None


def add_locations(*groups):
    """Add a 'location' entry to every source in the given ip -> info dicts."""
    for group in groups:
        for ip, info in group.items():
            info["location"] = lookup_ip(ip)


# -------------------------------------------------------------------- export
def build_alerts(brute_force, compromises, odd_hours, spray=None, privileged=None, distributed=None,
                 new_sources=None, multi_ip=None, takeovers=None, slow=None, travel=None, lockouts=None,
                 scanners=None, priv_fails=None, port_scans=None):
    """Flatten every finding into a simple list of dicts (easy to save as JSON/CSV)."""
    alerts = []
    for ip, b in brute_force.items():
        alerts.append({"type": "brute_force", "severity": severity(b["count"])[0], "ip": ip, "user": ", ".join(b["users"]),
                       "time": b["first"].isoformat(sep=" "), "details": f"{b['count']} failures until {b['last']:%H:%M:%S}"
                                  + (f"; location: {b['location']}" if "location" in b else "")})
    for ip, sp in (spray or {}).items():
        alerts.append({"type": "password_spray", "severity": "HIGH", "ip": ip, "user": ", ".join(sp["users"]),
                       "time": sp["first"].isoformat(sep=" "),
                       "details": f"{sp['user_count']} accounts, {sp['attempts']} attempts until {sp['last']:%H:%M:%S}"})
    for e in compromises:
        alerts.append({"type": "possible_compromise", "severity": "CRITICAL", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "), "details": "successful login after brute-force burst"})
    for user, d in (distributed or {}).items():
        alerts.append({"type": "distributed_attack", "severity": "HIGH", "ip": f"multiple ({d['ip_count']} IPs)", "user": user,
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['attempts']} attempts from {d['ip_count']} IPs until {d['last']:%H:%M:%S}: "
                                  + ", ".join(d["ips"])})
    for e in privileged or []:
        alerts.append({"type": "privileged_login", "severity": "MEDIUM", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "),
                       "details": "privileged account login from an IP with earlier failures"})
    for e in new_sources or []:
        alerts.append({"type": "new_source_login", "severity": "MEDIUM", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "),
                       "details": "first login by this account from this IP"})
    for user, d in (multi_ip or {}).items():
        alerts.append({"type": "multi_ip_login", "severity": "HIGH", "ip": f"multiple ({d['ip_count']} IPs)", "user": user,
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['logins']} logins from {d['ip_count']} IPs until {d['last']:%H:%M:%S}: "
                                  + ", ".join(d["ips"])})
    for e in takeovers or []:
        alerts.append({"type": "account_takeover", "severity": "HIGH", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "), "details": "successful login after failures: " + e["reason"]})
    for ip, d in (slow or {}).items():
        alerts.append({"type": "low_and_slow", "severity": "MEDIUM", "ip": ip, "user": ", ".join(d["users"]),
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['count']} failures between {d['first']:%Y-%m-%d %H:%M} and {d['last']:%Y-%m-%d %H:%M}"
                                  + (f"; location: {d['location']}" if "location" in d else "")})
    for e in travel or []:
        alerts.append({"type": "impossible_travel", "severity": "HIGH", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "),
                       "details": f"{e['km']} km from {e['from_ip']} ({e['from_place']}) to {e['to_place']} in {e['hours'] * 60:.0f} min"})
    for s_ in lockouts or []:
        alerts.append({"type": "account_lockout", "severity": "MEDIUM", "ip": s_["ip"], "user": s_["user"],
                       "time": s_["time"].isoformat(sep=" "), "details": "account locked out (Windows event 4740)"})
    for ip, d in (scanners or {}).items():
        alerts.append({"type": "web_scanner", "severity": "MEDIUM", "ip": ip, "user": "-",
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['path_count']} scanner URLs, {d['requests']} requests: " + ", ".join(d["paths"][:6])
                                  + ("..." if len(d["paths"]) > 6 else "")})
    for ip, d in (port_scans or {}).items():
        shown = ", ".join(map(str, d["ports"][:8])) + ("..." if len(d["ports"]) > 8 else "")
        alerts.append({"type": "port_scan", "severity": "MEDIUM", "ip": ip, "user": "-",
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['port_count']} different ports blocked, {d['attempts']} attempts: {shown}"})
    for user, d in (priv_fails or {}).items():
        alerts.append({"type": "privilege_escalation_attempts", "severity": "MEDIUM", "ip": "local", "user": user,
                       "time": d["first"].isoformat(sep=" "),
                       "details": f"{d['count']} failed {'/'.join(d['via'])} attempts until {d['last']:%H:%M:%S}"})
    for e in odd_hours:
        alerts.append({"type": "unusual_hour_login", "severity": "LOW", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "), "details": "login outside normal hours"})
    return alerts


def export_alerts(alerts, json_path, csv_path):
    """Write the alerts to a JSON and/or CSV file if the user asked for them."""
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2)
        print(f"{GREEN}✔ Saved {len(alerts)} alert(s) to {json_path}{RESET}")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "severity", "ip", "user", "time", "details"])
            writer.writeheader()
            writer.writerows(alerts)
        print(f"{GREEN}✔ Saved {len(alerts)} alert(s) to {csv_path}{RESET}")


def export_markdown(path, source, events, alerts):
    """Write a short Markdown report (handy to paste into a ticket or share with a team)."""
    successes = sum(e["success"] for e in events)
    lines = ["# Login Log Analysis", "",
             f"- **File:** `{source}`",
             f"- **Events analysed:** {len(events)} ({successes} successful, {len(events) - successes} failed)"]
    if events:
        lines.append(f"- **Time range:** {events[0]['time']:%Y-%m-%d %H:%M} to {events[-1]['time']:%Y-%m-%d %H:%M}")
    lines += ["", f"## Alerts ({len(alerts)})", ""]
    if alerts:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        lines += ["| Severity | Type | IP | User | Time | Details |", "|---|---|---|---|---|---|"]
        for a in sorted(alerts, key=lambda a: (order.get(a["severity"], 9), a["time"])):
            cells = [a["severity"], a["type"], a["ip"], a["user"], a["time"], a["details"]]
            lines.append("| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |")
    else:
        lines.append("No alerts.")
    lines += ["", "## Most targeted accounts", ""]
    lines += [f"- `{u}`: {n} failed login(s)" for u, n in top_targeted_users(events)] or ["None."]
    lines += ["", "## Noisiest source IPs", ""]
    lines += [f"- `{ip}`: {n} failed login(s)" for ip, n in top_source_ips(events)] or ["None."]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{GREEN}✔ Saved Markdown report to {path}{RESET}")


def export_html(path, source, events, alerts):
    """Write a self-contained HTML report (no external files, so it can be emailed as is)."""
    esc = html.escape
    successes = sum(e["success"] for e in events)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = "".join(
        f'<tr class="{esc(a["severity"].lower())}"><td>{esc(a["severity"])}</td><td>{esc(a["type"])}</td>'
        f'<td>{esc(a["ip"])}</td><td>{esc(a["user"])}</td><td>{esc(a["time"])}</td><td>{esc(a["details"])}</td></tr>'
        for a in sorted(alerts, key=lambda a: (order.get(a["severity"], 9), a["time"])))
    table = (f"<table><tr><th>Severity</th><th>Type</th><th>IP</th><th>User</th><th>Time</th><th>Details</th></tr>{rows}</table>"
             if alerts else "<p>No alerts.</p>")

    def items(pairs):
        return "<ul>" + "".join(f"<li><code>{esc(k)}</code>: {n} failed login(s)</li>" for k, n in pairs) + "</ul>" if pairs else "<p>None.</p>"

    span = f"{events[0]['time']:%Y-%m-%d %H:%M} to {events[-1]['time']:%Y-%m-%d %H:%M}" if events else "n/a"
    labels, counts = failure_timeline(events)
    charts = (chart_section("Failed logins by hour of day", failures_by_hour(events), [f"{h:02d}" for h in range(24)], 2)
              + chart_section("Failed logins over time", counts, labels, max(1, len(labels) // 10)))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login Log Analysis</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
th{{background:#f0f0f0}} tr.critical td:first-child{{background:#f8d7da;font-weight:bold}}
tr.high td:first-child{{background:#fde5c8}} tr.medium td:first-child{{background:#fff3cd}} tr.low td:first-child{{background:#e2f0d9}}
:root{{color-scheme:light}} body{{background:#fff}}
.chart{{width:100%;height:auto}} .chart .grid{{stroke:#ddd;stroke-width:1}} .chart .tick{{fill:#555;font-size:11px}} .chart .bar{{fill:#2a6fdb}}
details{{margin:.4rem 0 1rem}} table.small{{width:auto;margin-top:.4rem}}
</style></head><body>
<h1>Login Log Analysis</h1>
<p><strong>File:</strong> <code>{esc(source)}</code><br><strong>Events analysed:</strong> {len(events)} ({successes} successful, {len(events) - successes} failed)<br><strong>Time range:</strong> {esc(span)}</p>
<h2>Alerts ({len(alerts)})</h2>{table}
{charts}
<h2>Most targeted accounts</h2>{items(top_targeted_users(events))}
<h2>Noisiest source IPs</h2>{items(top_source_ips(events))}
</body></html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"{GREEN}✔ Saved HTML report to {path}{RESET}")


# ------------------------------------------------------------------ outputs
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def failure_timeline(events):
    """Failed logins per hour across the log (per day when it spans more than a week): (labels, counts)."""
    failed = [e["time"] for e in events if not e["success"]]
    if not failed:
        return [], []
    first, last = min(failed), max(failed)
    per_day = (last - first) > timedelta(days=7)
    step = timedelta(days=1) if per_day else timedelta(hours=1)
    fmt = "%Y-%m-%d" if per_day else "%m-%d %H:00"
    start = first.replace(minute=0, second=0, microsecond=0, **({"hour": 0} if per_day else {}))
    count = int((last - start) / step) + 1
    counts = [0] * count
    for t in failed:
        counts[int((t - start) / step)] += 1
    return [(start + i * step).strftime(fmt) for i in range(count)], counts


def svg_bars(values, labels, title, label_every=1):
    """A small self-contained SVG bar chart: one series, thin rounded bars, hover tooltips, no external files."""
    esc = html.escape
    width, height, left, top, bottom = 720, 190, 40, 14, 26
    peak = max(values) or 1
    plot = height - top - bottom
    slot = (width - left - 8) / len(values)
    bar = max(2.0, min(slot * 0.7, 28.0))
    out = [f'<svg class="chart" role="img" aria-label="{esc(title)}" viewBox="0 0 {width} {height}">']
    for frac in (0, 0.5, 1) if peak >= 4 else (0, 1):
        y = top + plot * (1 - frac)
        out.append(f'<line class="grid" x1="{left}" x2="{width - 8}" y1="{y:.1f}" y2="{y:.1f}"/>'
                   f'<text class="tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">{round(peak * frac)}</text>')
    for i, (value, label) in enumerate(zip(values, labels)):
        x = left + i * slot + (slot - bar) / 2
        if value:
            h = plot * value / peak
            out.append(f'<rect class="bar" x="{x:.1f}" y="{top + plot - h:.1f}" width="{bar:.1f}" height="{h:.1f}" rx="2">'
                       f'<title>{esc(label)}: {value} failed login(s)</title></rect>')
        if i % label_every == 0:
            edge = x + bar / 2 > width - 40  # keep the last labels inside the picture
            out.append(f'<text class="tick" x="{(width - 4) if edge else (x + bar / 2):.1f}" y="{height - 8}" '
                       f'text-anchor="{"end" if edge else "middle"}">{esc(label)}</text>')
    out.append("</svg>")
    return "".join(out)


def chart_section(heading, values, labels, label_every=1):
    """Heading + SVG chart + a collapsible text table of the same numbers (for screen readers and copy/paste)."""
    esc = html.escape
    if not values or not max(values):
        return f"<h2>{esc(heading)}</h2><p>No failed logins.</p>"
    rows = "".join(f"<tr><td>{esc(l)}</td><td>{v}</td></tr>" for l, v in zip(labels, values) if v)
    return (f"<h2>{esc(heading)}</h2>{svg_bars(values, labels, heading, label_every)}"
            f"<details><summary>Show the numbers</summary><table class='small'><tr><th>When</th><th>Failed logins</th></tr>{rows}</table></details>")


def alert_key(alert):
    """Identity of an alert, used to recognise it in a baseline file."""
    return "|".join(str(alert[k]) for k in ("type", "ip", "user", "time"))


def load_baseline(path):
    """Alerts saved by an earlier run (--json output). A missing file just means 'no baseline yet'."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"{DIM}Baseline {path} does not exist yet - every alert counts as new.{RESET}")
        return []
    except (OSError, ValueError) as err:
        sys.exit(f"Error: cannot read baseline {path}: {err}")
    if not isinstance(data, list) or not all(isinstance(a, dict) and {"type", "ip", "user", "time"} <= a.keys() for a in data):
        sys.exit(f"Error: {path} is not an alerts file written by --json")
    return data


def save_baseline(path, old, current):
    """Write old + current alerts (without duplicates) so the next run only reports what is new."""
    known = {alert_key(a): a for a in old}
    known.update({alert_key(a): a for a in current})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(known.values()), f, indent=2)
    print(f"{GREEN}✔ Baseline {path} now knows {len(known)} alert(s){RESET}")


def blocklist_ips(res, include_private=False):
    """Addresses worth blocking: the sources of brute force, spraying, low-and-slow, scanning and breaches.

    Private, loopback and link-local addresses are skipped so you cannot lock yourself out
    (include_private=True keeps private/documentation ranges, handy for demos).
    """
    ips = set(res["brute_force"]) | set(res["spray"]) | set(res["slow"]) | set(res["scanners"]) | set(res.get("port_scans", {}))
    ips |= {e["ip"] for e in res["compromises"]}
    for d in res["distributed"].values():
        ips.update(d["ips"])
    keep = []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue  # "local", "multiple (3 IPs)", computer names ...
        if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
            continue
        if a.is_global or include_private:
            keep.append(a)
    return sorted(keep, key=lambda a: (a.version, int(a)))


def export_blocklist(path, fmt, addresses):
    """Write block commands (never run automatically). Addresses are validated ipaddress objects."""
    lines = [f"# Generated by log_analyser.py on {datetime.now():%Y-%m-%d %H:%M} - {len(addresses)} address(es).",
             "# REVIEW BEFORE RUNNING: make sure none of these are your own or your users' addresses."]
    for a in addresses:
        if fmt == "ufw":
            lines.append(f"ufw deny from {a} to any")
        elif fmt == "iptables":
            lines.append(f"{'ip6tables' if a.version == 6 else 'iptables'} -I INPUT -s {a} -j DROP")
        elif fmt == "nft":
            lines.append(f"nft add rule inet filter input {'ip6' if a.version == 6 else 'ip'} saddr {a} drop")
        else:
            lines.append(str(a))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{GREEN}✔ Saved {len(addresses)} {fmt} block entr{'y' if len(addresses) == 1 else 'ies'} to {path} "
          f"(review before running){RESET}")


def format_alert(a):
    return f"[{a['severity']}] {a['type']} | ip={a['ip']} user={a['user']} | {a['time']} | {a['details']}"


def send_webhook(url, text):
    """POST the text as JSON. Works with Slack, Discord, Teams-style incoming webhooks ('text' and 'content')."""
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        raise ValueError("webhook URL must start with http:// or https://")
    body = json.dumps({"text": text, "content": text[:1900]}).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(request, timeout=10).close()


def send_email(args, subject, text):
    """Send through the SMTP server in --smtp HOST[:PORT]; SMTP_USER / SMTP_PASSWORD env vars log in."""
    host, _, port = args.smtp.partition(":")
    port = int(port or 587)
    user, password = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASSWORD")
    message = EmailMessage()
    message["Subject"], message["To"] = subject, args.mail_to
    message["From"] = args.mail_from or user or "log-analyser@localhost"
    message.set_content(text)
    with (smtplib.SMTP_SSL if port == 465 else smtplib.SMTP)(host, port, timeout=15) as smtp:
        if port not in (25, 465):
            smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(message)


def notify(alerts, args, subject="Login log analyser alerts"):
    """Send alerts at or above --notify-min-severity to the webhook and/or email. Never raises."""
    cutoff = SEVERITY_ORDER[args.notify_min_severity]
    chosen = [a for a in alerts if SEVERITY_ORDER.get(a["severity"], 9) <= cutoff]
    if not chosen or not (args.webhook or args.smtp):
        return 0
    lines = [format_alert(a) for a in chosen[:20]]
    if len(chosen) > 20:
        lines.append(f"... and {len(chosen) - 20} more")
    text = f"{subject} ({len(chosen)})\n" + "\n".join(lines)
    senders = []
    if args.webhook:
        senders.append(("webhook", lambda: send_webhook(args.webhook, text)))
    if args.smtp:
        senders.append(("email", lambda: send_email(args, f"{subject} ({len(chosen)})", text)))
    for name, send in senders:
        try:
            send()
            print(f"{GREEN}✔ Sent {len(chosen)} alert(s) by {name}{RESET}")
        except Exception as err:  # a broken notifier must never stop the analysis
            print(f"{YELLOW}Warning: {name} notification failed: {type(err).__name__}: {err}{RESET}")
    return len(chosen)


# ----------------------------------------------------------------- analysis
def analyse(events, specials, args):
    """Run every detector over time-sorted events. Returns a dict of findings plus `alerts` and `scores`."""
    brute_force = find_brute_force(events, args.threshold, args.window)
    odd_hours = (find_user_anomalies(events) if args.learn
                 else find_unusual_hours(events, args.night_start, args.night_end))
    compromises = find_compromises(events, brute_force)
    distributed = find_distributed_attack(events, args.dist_ips, args.window)
    slow = find_low_and_slow(events, args.slow_threshold, args.slow_window, loud=brute_force)
    if args.geoip:
        add_locations(brute_force, slow)
    res = {
        "brute_force": brute_force, "odd_hours": odd_hours, "compromises": compromises,
        "spray": find_password_spray(events, args.spray_users, args.window),
        "privileged": find_privileged_logins(events, [n.strip() for n in args.privileged.split(",") if n.strip()], compromises),
        "distributed": distributed, "slow": slow,
        "takeovers": find_account_takeovers(events, args.threshold, args.window, distributed, compromises),
        "new_sources": find_new_source_logins(events) if args.new_ip else [],
        "multi_ip": find_multi_ip_logins(events, args.multi_ip, args.window) if args.multi_ip else {},
        "travel": find_impossible_travel(events, locate, args.travel_speed) if args.travel else [],
        "lockouts": find_lockouts(specials),
        "scanners": find_web_scanners(specials, args.scan_paths, args.window),
        "priv_fails": find_priv_failures(specials, args.sudo_threshold, args.window),
        "port_scans": find_port_scans(specials, args.scan_ports, args.window),
    }
    res["alerts"] = build_alerts(brute_force, compromises, odd_hours, res["spray"], res["privileged"], distributed,
                                 res["new_sources"], res["multi_ip"], res["takeovers"], slow, res["travel"],
                                 res["lockouts"], res["scanners"], res["priv_fails"], res["port_scans"])
    res["scores"] = risk_scores(res["alerts"])
    return res


class Follower:
    """Watches a growing SSH log (like `tail -f`) and reports alerts the moment they first appear."""

    def __init__(self, path, args):
        self.path, self.args = path, args
        self.parser = SshParser(args.year)
        self.events, self.specials = [], []
        self.file, self.inode = None, None
        self._open(from_start=True)
        self.seen = {alert_key(a) for a in self._analyse()["alerts"]}  # history is not re-announced

    def _open(self, from_start):
        if self.file:
            self.file.close()
        self.file = open(self.path, encoding="utf-8", errors="replace")
        self.inode = os.fstat(self.file.fileno()).st_ino
        if not from_start:
            self.file.seek(0, os.SEEK_END)
        for line in self.file:
            self.parser.feed(line, self.events, self.specials)

    def _analyse(self):
        self.events.sort(key=lambda e: e["time"])
        if self.events:  # keep memory bounded: only the last --follow-hours matter to the time windows
            cutoff = self.events[-1]["time"] - timedelta(hours=self.args.follow_hours)
            self.events[:] = [e for e in self.events if e["time"] >= cutoff]
            self.specials[:] = [s for s in self.specials if s["time"] >= cutoff]
        args = self.args
        return analyse(filter_events(self.events, args.allow, args.since, args.until, args.ignore_user),
                       filter_events(self.specials, args.allow, args.since, args.until, args.ignore_user), args)

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def _rotated(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return False  # file briefly missing during rotation: keep waiting
        return stat.st_ino != self.inode or stat.st_size < self.file.tell()

    def poll(self):
        """Read whatever was appended since the last call; return the alerts that are new."""
        changed = False
        if self._rotated():
            self._open(from_start=True)  # a new/truncated file: read it from the top
            changed = True
        for line in self.file:
            self.parser.feed(line, self.events, self.specials)
            changed = True
        if not changed:
            return []
        fresh = [a for a in self._analyse()["alerts"] if alert_key(a) not in self.seen]
        self.seen.update(alert_key(a) for a in fresh)
        return fresh


def follow(path, args, interval=1.0):
    """Live mode: print (and notify about) new alerts until Ctrl+C."""
    follower = Follower(path, args)
    print(f"{CYAN}{BOLD}Watching {path}{RESET} - {len(follower.seen)} existing alert(s) ignored. Ctrl+C to stop.")
    try:
        while True:
            fresh = follower.poll()
            for a in sorted(fresh, key=lambda a: SEVERITY_ORDER.get(a["severity"], 9)):
                colour = RED if a["severity"] in ("CRITICAL", "HIGH") else YELLOW
                print(f"{colour}{BOLD}{format_alert(a)}{RESET}", flush=True)
            if fresh:
                notify(fresh, args)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        follower.close()


# ------------------------------------------------------------------- report
def severity(count):
    """Turn a failure count into a label and colour."""
    if count >= 20:
        return "CRITICAL", RED
    if count >= 10:
        return "HIGH", YELLOW
    return "MEDIUM", YELLOW


def bar(count, biggest, length=20):
    """A small text bar chart so the biggest attacker stands out."""
    filled = max(1, round(count / biggest * length))
    return "█" * filled + "░" * (length - filled)


def print_report(path, events, res, args):
    brute_force, odd_hours, compromises = res["brute_force"], res["odd_hours"], res["compromises"]
    spray, privileged, distributed = res["spray"], res["privileged"], res["distributed"]
    scores, new_sources, multi_ip = res["scores"], res["new_sources"], res["multi_ip"]
    banner("LOGIN LOG ANALYSER")
    successes = sum(e["success"] for e in events)
    print(f"{DIM}File:{RESET} {path}")
    print(f"{DIM}Events analysed:{RESET} {len(events)}  "
          f"({GREEN}{successes} successful{RESET}, {RED}{len(events) - successes} failed{RESET})")
    if events:
        print(f"{DIM}Time range:{RESET} {events[0]['time']:%Y-%m-%d %H:%M} → {events[-1]['time']:%Y-%m-%d %H:%M}")
    hours_rule = "learned per-user hours" if args.learn else f"night = {args.night_start:02d}:00–{args.night_end:02d}:00"
    print(f"{DIM}Rules:{RESET} ≥{args.threshold} failures within {args.window} min  |  {hours_rule}")

    # --- Brute force
    section(f"BRUTE-FORCE ATTEMPTS  ({len(brute_force)} source(s))", RED)
    if brute_force:
        biggest = max(b["count"] for b in brute_force.values())
        ranked = sorted(brute_force.items(), key=lambda kv: -kv[1]["count"])
        for ip, b in ranked[:args.top]:  # args.top is None = show everything
            label, colour = severity(b["count"])
            print(f"{colour}{BOLD}[{label}]{RESET} {BOLD}{ip}{RESET}")
            print(f"   {colour}{bar(b['count'], biggest)}{RESET} {b['count']} failures "
                  f"between {b['first']:%H:%M:%S} and {b['last']:%H:%M:%S} on {b['first']:%Y-%m-%d}")
            print(f"   {DIM}accounts targeted:{RESET} {', '.join(b['users'])}")
            if "location" in b:
                print(f"   {DIM}location:{RESET} 🌍 {b['location']}")
        if args.top and len(ranked) > args.top:
            print(f"{DIM}... and {len(ranked) - args.top} more source(s) hidden by --top {args.top}{RESET}")
    else:
        print(f"{GREEN}✔ No brute-force activity detected.{RESET}")

    # --- Password spraying
    section(f"PASSWORD SPRAYING  ({len(spray)} source(s))", RED)
    if spray:
        for ip, sp in sorted(spray.items(), key=lambda kv: -kv[1]["user_count"]):
            print(f"{YELLOW}{BOLD}[HIGH]{RESET} {BOLD}{ip}{RESET}")
            print(f"   {sp['user_count']} different accounts, {sp['attempts']} attempts "
                  f"between {sp['first']:%H:%M:%S} and {sp['last']:%H:%M:%S} on {sp['first']:%Y-%m-%d}")
            print(f"   {DIM}accounts targeted:{RESET} {', '.join(sp['users'])}")
    else:
        print(f"{GREEN}✔ No password-spraying detected.{RESET}")

    # --- Distributed attacks
    section(f"DISTRIBUTED ATTACKS ON ONE ACCOUNT  ({len(distributed)})", RED)
    if distributed:
        for user, d in sorted(distributed.items(), key=lambda kv: -kv[1]["ip_count"]):
            print(f"{YELLOW}{BOLD}[HIGH]{RESET} {BOLD}{user}{RESET}")
            print(f"   {d['attempts']} attempts from {d['ip_count']} different IPs "
                  f"between {d['first']:%H:%M:%S} and {d['last']:%H:%M:%S} on {d['first']:%Y-%m-%d}")
            print(f"   {DIM}source IPs:{RESET} {', '.join(d['ips'])}")
    else:
        print(f"{GREEN}✔ No distributed attacks on a single account.{RESET}")

    # --- Compromise
    section(f"POSSIBLE COMPROMISE  ({len(compromises)})", RED)
    if compromises:
        for e in compromises:
            print(f"{RED}{BOLD}⚠ {e['user']}{RESET} logged in from {BOLD}{e['ip']}{RESET} "
                  f"at {e['time']:%Y-%m-%d %H:%M:%S} {RED}— after a brute-force burst from the same IP!{RESET}")
    else:
        print(f"{GREEN}✔ No successful logins from brute-forcing IPs.{RESET}")

    # --- Privileged logins
    section(f"PRIVILEGED ACCOUNT LOGINS AFTER FAILURES  ({len(privileged)})", YELLOW)
    if privileged:
        for e in privileged:
            print(f"{YELLOW}●{RESET} {e['time']:%Y-%m-%d %H:%M:%S}  {BOLD}{e['user']:<14}{RESET} from {e['ip']}")
    else:
        print(f"{GREEN}✔ No privileged logins from IPs that failed first.{RESET}")

    # --- New source IPs and multi-IP logins (opt-in)
    if args.new_ip:
        section(f"LOGINS FROM A NEW IP  ({len(new_sources)})", YELLOW)
        if new_sources:
            for e in new_sources:
                print(f"{YELLOW}●{RESET} {e['time']:%Y-%m-%d %H:%M:%S}  {BOLD}{e['user']:<14}{RESET} first time from {e['ip']}")
        else:
            print(f"{GREEN}✔ No account logged in from a never-seen-before IP.{RESET}")
    if args.multi_ip:
        section(f"ONE ACCOUNT, MANY IPs  ({len(multi_ip)})", RED)
        if multi_ip:
            for user, d in sorted(multi_ip.items(), key=lambda kv: -kv[1]["ip_count"]):
                print(f"{YELLOW}{BOLD}[HIGH]{RESET} {BOLD}{user}{RESET}")
                print(f"   {d['logins']} logins from {d['ip_count']} different IPs "
                      f"between {d['first']:%H:%M:%S} and {d['last']:%H:%M:%S} on {d['first']:%Y-%m-%d}")
                print(f"   {DIM}source IPs:{RESET} {', '.join(d['ips'])}")
        else:
            print(f"{GREEN}✔ No account used from several IPs at once.{RESET}")

    # --- Account takeover (success after failures on the same account, from any IP)
    section(f"ACCOUNT TAKEOVER  ({len(res['takeovers'])})", RED)
    if res["takeovers"]:
        for e in res["takeovers"]:
            print(f"{YELLOW}{BOLD}[HIGH]{RESET} {BOLD}{e['user']}{RESET} logged in from {e['ip']} at {e['time']:%Y-%m-%d %H:%M:%S}")
            print(f"   {DIM}{e['reason']}{RESET}")
    else:
        print(f"{GREEN}✔ No account was logged into right after a burst of failures.{RESET}")

    # --- Low and slow
    section(f"LOW-AND-SLOW ATTACKS  ({len(res['slow'])} source(s))", YELLOW)
    if res["slow"]:
        for ip, d in sorted(res["slow"].items(), key=lambda kv: -kv[1]["count"]):
            print(f"{YELLOW}{BOLD}[MEDIUM]{RESET} {BOLD}{ip}{RESET}  {d['count']} failures between "
                  f"{d['first']:%Y-%m-%d %H:%M} and {d['last']:%Y-%m-%d %H:%M}")
            print(f"   {DIM}accounts targeted:{RESET} {', '.join(d['users'])}")
            if "location" in d:
                print(f"   {DIM}location:{RESET} 🌍 {d['location']}")
    else:
        print(f"{GREEN}✔ No slow, patient attackers (≥{args.slow_threshold} failures within {args.slow_window}h).{RESET}"
              if args.slow_threshold > 0 else f"{DIM}Low-and-slow detection is off.{RESET}")

    # --- Impossible travel (opt-in)
    if args.travel:
        section(f"IMPOSSIBLE TRAVEL  ({len(res['travel'])})", RED)
        if res["travel"]:
            for e in res["travel"]:
                print(f"{YELLOW}{BOLD}[HIGH]{RESET} {BOLD}{e['user']}{RESET} at {e['time']:%Y-%m-%d %H:%M:%S}: "
                      f"{e['from_place']} → {e['to_place']}, {e['km']} km in {e['hours'] * 60:.0f} min ({e['from_ip']} → {e['ip']})")
        else:
            print(f"{GREEN}✔ No account jumped between far-apart locations.{RESET}")

    # --- Sections that only appear when the log contained that kind of evidence
    if res["lockouts"]:
        section(f"ACCOUNT LOCKOUTS  ({len(res['lockouts'])})", YELLOW)
        for s_ in res["lockouts"]:
            print(f"{YELLOW}●{RESET} {s_['time']:%Y-%m-%d %H:%M:%S}  {BOLD}{s_['user']:<14}{RESET} locked out (source: {s_['ip']})")
    if res["scanners"]:
        section(f"WEB SCANNERS  ({len(res['scanners'])} source(s))", YELLOW)
        for ip, d in sorted(res["scanners"].items(), key=lambda kv: -kv[1]["path_count"]):
            print(f"{YELLOW}{BOLD}[MEDIUM]{RESET} {BOLD}{ip}{RESET}  {d['path_count']} scanner URLs, {d['requests']} requests")
            print(f"   {DIM}paths:{RESET} {', '.join(d['paths'][:8])}{'...' if len(d['paths']) > 8 else ''}")
    if res["port_scans"]:
        section(f"PORT SCANS  ({len(res['port_scans'])} source(s))", YELLOW)
        for ip, d in sorted(res["port_scans"].items(), key=lambda kv: -kv[1]["port_count"]):
            print(f"{YELLOW}{BOLD}[MEDIUM]{RESET} {BOLD}{ip}{RESET}  {d['port_count']} different ports, {d['attempts']} blocked attempts "
                  f"between {d['first']:%H:%M:%S} and {d['last']:%H:%M:%S} on {d['first']:%Y-%m-%d}")
            print(f"   {DIM}ports:{RESET} {', '.join(map(str, d['ports'][:12]))}{'...' if len(d['ports']) > 12 else ''}")
    if res["priv_fails"]:
        section(f"FAILED sudo/su ATTEMPTS  ({len(res['priv_fails'])} account(s))", YELLOW)
        for user, d in sorted(res["priv_fails"].items(), key=lambda kv: -kv[1]["count"]):
            print(f"{YELLOW}●{RESET} {BOLD}{user:<14}{RESET} {d['count']} failed {'/'.join(d['via'])} attempts, "
                  f"{d['first']:%Y-%m-%d %H:%M:%S} to {d['last']:%H:%M:%S}")

    # --- Unusual hours
    section(f"UNUSUAL-HOUR LOGINS  ({len(odd_hours)})", YELLOW)
    if odd_hours:
        for e in odd_hours:
            print(f"{YELLOW}●{RESET} {e['time']:%Y-%m-%d %H:%M:%S}  {BOLD}{e['user']:<8}{RESET} from {e['ip']}")
    else:
        print(f"{GREEN}✔ No logins during unusual hours.{RESET}")

    # --- Most targeted accounts
    section("MOST TARGETED ACCOUNTS", CYAN)
    targeted = top_targeted_users(events)
    if targeted:
        for user, count in targeted:
            print(f"{BOLD}{user:<14}{RESET} {RED}{bar(count, targeted[0][1], 16)}{RESET} {count} failed login(s)")
    else:
        print(f"{GREEN}✔ No failed logins.{RESET}")

    # --- Noisiest source IPs
    section("NOISIEST SOURCE IPs", CYAN)
    sources = top_source_ips(events)
    if sources:
        for ip, count in sources:
            print(f"{BOLD}{ip:<18}{RESET} {RED}{bar(count, sources[0][1], 16)}{RESET} {count} failed login(s)")
    else:
        print(f"{GREEN}✔ No failed logins.{RESET}")

    # --- Risk scores
    section("IP RISK SCORES  (all signals combined, 0-100)", RED)
    if scores:
        for ip, score, kinds in scores:
            colour = RED if score >= 60 else YELLOW if score >= 30 else GREEN
            print(f"{BOLD}{ip:<18}{RESET} {colour}{bar(score, 100, 16)}{RESET} {score:>3}  {DIM}{', '.join(kinds)}{RESET}")
    else:
        print(f"{GREEN}✔ No IP triggered any alert.{RESET}")

    # --- Hourly histogram
    section("FAILED LOGINS BY HOUR", CYAN)
    hourly = failures_by_hour(events)
    if max(hourly) > 0:
        for hour, count in enumerate(hourly):
            if count:
                print(f"{DIM}{hour:02d}:00{RESET} {YELLOW}{bar(count, max(hourly), 30)}{RESET} {count}")
    else:
        print(f"{GREEN}✔ No failed logins.{RESET}")

    # --- Summary
    section("SUMMARY", CYAN)
    counts = [("brute-force source(s)", len(brute_force)), ("spraying source(s)", len(spray)),
              ("possible compromise(s)", len(compromises)), ("account takeover(s)", len(res["takeovers"])),
              ("low-and-slow source(s)", len(res["slow"])), ("unusual-hour login(s)", len(odd_hours)),
              ("privileged login(s)", len(privileged)), ("distributed attack(s)", len(distributed)),
              ("new-IP login(s)", len(new_sources)), ("multi-IP account(s)", len(multi_ip)),
              ("impossible-travel login(s)", len(res["travel"])), ("lockout(s)", len(res["lockouts"])),
              ("web scanner(s)", len(res["scanners"])), ("port scan(s)", len(res["port_scans"])),
              ("sudo/su account(s)", len(res["priv_fails"]))]
    total_alerts = len(res["alerts"])
    colour = RED if compromises or res["takeovers"] else YELLOW if total_alerts else GREEN
    print(f"{colour}{BOLD}{total_alerts} alert(s){RESET}" + (": " + ", ".join(f"{n} {label}" for label, n in counts if n) if total_alerts else ""))
    if compromises or res["takeovers"]:
        print(f"{RED}Action:{RESET} reset the affected account(s), review what they did, and block the source IP(s).")
    elif brute_force or spray or distributed or multi_ip or res["slow"] or res["scanners"] or res["port_scans"]:
        print(f"{YELLOW}Action:{RESET} block the source IP(s) (see --blocklist) and consider rate-limiting or MFA.")
    print()


# --------------------------------------------------------------------- main
def apply_config(parser):
    """If --config FILE was given, use its JSON keys as option defaults (CLI flags still win).

    Keys are the long option names with underscores, e.g. "night_start" for --night-start.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    path = pre.parse_known_args()[0].config
    if not path:
        return
    try:
        with open(path, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        sys.exit(f"Error: config file not found: {path}")
    except json.JSONDecodeError as err:
        sys.exit(f"Error: config file is not valid JSON: {err}")
    if not isinstance(config, dict):
        sys.exit("Error: config file must contain a JSON object")

    actions = {a.dest: a for a in parser._actions if a.dest not in ("help", "logfile", "config")}
    for key, value in config.items():
        if key not in actions:
            sys.exit(f"Error: unknown option in config file: {key} (valid: {', '.join(sorted(actions))})")
        convert = actions[key].type
        try:
            if convert and isinstance(value, str):
                value = convert(value)
            elif convert and isinstance(value, list):
                value = [convert(v) if isinstance(v, str) else v for v in value]
        except (ValueError, argparse.ArgumentTypeError):
            sys.exit(f"Error: bad value for '{key}' in config file: {value!r}")
        parser.set_defaults(**{key: value})


def build_parser():
    parser = argparse.ArgumentParser(description="Detect brute-force and unusual-hour logins in an auth log.")
    parser.add_argument("logfile", nargs="+",
                        help="log file(s); several files are merged, .gz is decompressed, '-' reads stdin")
    parser.add_argument("--threshold", type=int, default=5, help="failures needed to flag brute force (default 5)")
    parser.add_argument("--window", type=int, default=5, help="time window in minutes (default 5)")
    parser.add_argument("--night-start", type=int, default=0, help="first 'unusual' hour, 0-23 (default 0)")
    parser.add_argument("--night-end", type=int, default=6, help="hour unusual period ends (default 6)")
    parser.add_argument("--learn", action="store_true",
                        help="learn each user's normal hours instead of using fixed night hours")
    parser.add_argument("--top", type=int, default=None, help="only show the N worst brute-force sources")
    parser.add_argument("--format", choices=["auto", "ssh", "windows", "web"], default="auto",
                        help="log format: ssh text log, Windows Security CSV, or nginx/Apache access log "
                             "(default: guess from the file name)")
    parser.add_argument("--geoip", action="store_true",
                        help="look up the country/ISP of attacking IPs (sends public IPs to ip-api.com)")
    parser.add_argument("--spray-users", type=int, default=4,
                        help="distinct accounts from one IP within the window to flag password spraying (default 4)")
    parser.add_argument("--allow", action="append", default=[], metavar="IP/CIDR",
                        help="ignore events from this IP or network (repeatable, e.g. --allow 10.0.0.0/8)")
    parser.add_argument("--since", type=parse_date, metavar="YYYY-MM-DD", help="ignore events before this date")
    parser.add_argument("--until", type=parse_date, metavar="YYYY-MM-DD", help="ignore events after this date (inclusive)")
    parser.add_argument("--privileged", default="root,admin,administrator", metavar="NAMES",
                        help="comma-separated privileged account names to watch (default root,admin,administrator)")
    parser.add_argument("--markdown", metavar="FILE", help="also save a Markdown report to this file")
    parser.add_argument("--html", metavar="FILE", help="also save a self-contained HTML report to this file")
    parser.add_argument("--year", type=int, help="year to assume for syslog timestamps that have none (default: this year)")
    parser.add_argument("--fail-on-alert", action="store_true",
                        help="exit with code 1 on any alert and 2 on a possible compromise (for scripts/CI)")
    parser.add_argument("--json", metavar="FILE", help="also save the alerts to a JSON file")
    parser.add_argument("--csv", metavar="FILE", help="also save the alerts to a CSV file")
    parser.add_argument("--config", metavar="FILE",
                        help="JSON file of default options, e.g. {\"threshold\": 3, \"allow\": [\"10.0.0.0/8\"]}; command-line flags win")
    parser.add_argument("--dist-ips", type=int, default=5,
                        help="distinct IPs failing against one account within the window to flag a distributed attack (default 5)")
    parser.add_argument("--new-ip", action="store_true",
                        help="flag a successful login from an IP the account has never used before")
    parser.add_argument("--multi-ip", type=int, default=0, metavar="N",
                        help="flag accounts that log in from N or more different IPs within the window (0 = off)")
    parser.add_argument("--slow-threshold", type=int, default=20,
                        help="failures from one IP inside --slow-window hours to flag a low-and-slow attack (default 20, 0 = off)")
    parser.add_argument("--slow-window", type=float, default=24, metavar="HOURS",
                        help="long window for low-and-slow detection in hours (default 24)")
    parser.add_argument("--travel", action="store_true",
                        help="flag impossible travel between logins (needs GeoIP; sends login IPs to ip-api.com unless --geoip-db)")
    parser.add_argument("--travel-speed", type=float, default=900, metavar="KMH",
                        help="speed above which two logins count as impossible travel (default 900)")
    parser.add_argument("--geoip-cache", metavar="FILE", help="remember GeoIP answers in this JSON file between runs")
    parser.add_argument("--geoip-db", metavar="FILE",
                        help="use a local MaxMind GeoLite2/GeoIP2 City .mmdb file instead of ip-api.com (pip install geoip2)")
    parser.add_argument("--scan-paths", type=int, default=3,
                        help="distinct scanner-only URLs from one IP in the window to flag a web scanner (default 3)")
    parser.add_argument("--scan-ports", type=int, default=10,
                        help="distinct ports from one IP blocked by the firewall in the window to flag a port scan (default 10)")
    parser.add_argument("--ignore-user", action="append", default=[], metavar="NAME",
                        help="ignore events for this account, e.g. a monitoring/service account (repeatable, case-insensitive)")
    parser.add_argument("--sudo-threshold", type=int, default=3,
                        help="failed sudo/su attempts by one account in the window to flag (default 3)")
    parser.add_argument("--blocklist", metavar="FILE", help="write block commands for the attacking IPs to this file (never run automatically)")
    parser.add_argument("--blocklist-format", choices=["plain", "ufw", "iptables", "nft"], default="plain",
                        help="format of the --blocklist file (default plain: one address per line)")
    parser.add_argument("--blocklist-private", action="store_true",
                        help="also include private/documentation-range addresses (skipped by default so you cannot lock yourself out)")
    parser.add_argument("--baseline", metavar="FILE",
                        help="alerts file from an earlier --json run; only alerts NOT in it are exported, notified and counted by --fail-on-alert")
    parser.add_argument("--update-baseline", action="store_true", help="add this run's alerts to the --baseline file afterwards")
    parser.add_argument("--webhook", metavar="URL", default=os.environ.get("LOG_ANALYSER_WEBHOOK"),
                        help="POST alerts as JSON to this Slack/Discord/Teams-style webhook (or set LOG_ANALYSER_WEBHOOK)")
    parser.add_argument("--smtp", metavar="HOST[:PORT]", help="email alerts through this SMTP server (SMTP_USER / SMTP_PASSWORD env vars log in)")
    parser.add_argument("--mail-to", metavar="ADDRESS", help="recipient for --smtp")
    parser.add_argument("--mail-from", metavar="ADDRESS", help="sender for --smtp (default: SMTP_USER)")
    parser.add_argument("--notify-min-severity", choices=list(SEVERITY_ORDER), default="HIGH",
                        help="lowest severity sent by --webhook / --smtp (default HIGH)")
    parser.add_argument("--follow", action="store_true",
                        help="keep watching one SSH log and print/notify new alerts as they appear (Ctrl+C to stop)")
    parser.add_argument("--follow-hours", type=float, default=24,
                        help="with --follow, how many hours of events to keep in memory (default 24)")
    parser.add_argument("--follow-interval", type=float, default=1.0, metavar="SECONDS",
                        help="with --follow, how often to check the file (default 1)")
    parser.add_argument("--no-color", action="store_true", help="plain output without ANSI colours")
    return parser


def main():
    parser = build_parser()
    apply_config(parser)
    args = parser.parse_args()
    if args.no_color or os.environ.get("NO_COLOR"):
        disable_colour()
    if args.smtp and not args.mail_to:
        parser.error("--smtp needs --mail-to")
    if args.update_baseline and not args.baseline:
        parser.error("--update-baseline needs --baseline FILE")
    if args.follow:
        one = args.logfile[0]
        if len(args.logfile) != 1 or one == "-" or one.lower().endswith(".gz") or detect_format(one, args.format) != "ssh":
            parser.error("--follow watches exactly one plain-text SSH log file")
    if args.geoip_db:
        open_geo_db(args.geoip_db)
    if args.geoip_cache:
        load_geo_cache(args.geoip_cache)
    if args.follow:
        try:
            follow(args.logfile[0], args, args.follow_interval)
        except FileNotFoundError:
            sys.exit(f"Error: file not found: {args.logfile[0]}")
        finally:
            if args.geoip_cache:
                save_geo_cache(args.geoip_cache)
        return

    events, specials = [], []
    for path in args.logfile:
        try:
            events += parse_log(path, args.format, args.year, specials)
        except FileNotFoundError:
            sys.exit(f"Error: file not found: {path}")
        except (KeyError, ValueError, OSError):
            sys.exit(f"Error: could not read {path}. Check it matches the expected format (see README).")
    source = ", ".join(args.logfile)

    events = filter_events(events, args.allow, args.since, args.until, args.ignore_user)
    specials = filter_events(specials, args.allow, args.since, args.until, args.ignore_user)
    events.sort(key=lambda e: e["time"])
    specials.sort(key=lambda s: s["time"])
    res = analyse(events, specials, args)
    print_report(source, events, res, args)

    alerts, old_baseline = res["alerts"], []
    if args.baseline:
        old_baseline = load_baseline(args.baseline)
        known = {alert_key(a) for a in old_baseline}
        alerts = [a for a in res["alerts"] if alert_key(a) not in known]
        section(f"NEW SINCE BASELINE  ({len(alerts)} of {len(res['alerts'])})", CYAN)
        for a in alerts:
            print(f"{YELLOW}●{RESET} {format_alert(a)}")
        if not alerts:
            print(f"{GREEN}✔ Nothing new.{RESET}")
        print()

    export_alerts(alerts, args.json, args.csv)
    if args.markdown:
        export_markdown(args.markdown, source, events, alerts)
    if args.html:
        export_html(args.html, source, events, alerts)
    if args.blocklist:
        export_blocklist(args.blocklist, args.blocklist_format, blocklist_ips(res, args.blocklist_private))
    notify(alerts, args)
    if args.update_baseline:
        save_baseline(args.baseline, old_baseline, res["alerts"])
    if args.geoip_cache:
        save_geo_cache(args.geoip_cache)
    if args.fail_on_alert:
        if any(a["type"] == "possible_compromise" for a in alerts):
            sys.exit(2)
        if alerts:
            sys.exit(1)


if __name__ == "__main__":
    main()
