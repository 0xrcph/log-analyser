"""Login Log Analyser - a small tool for spotting suspicious login activity.

It reads an SSH-style auth log and looks for:
  1. Brute-force attempts  - many failed logins from one IP in a short time
  2. Unusual-hour logins   - successful logins late at night / early morning
  3. Possible compromise   - a successful login right after a brute-force burst
  4. Password spraying     - one IP trying many different accounts in a short time
  5. Targeted accounts, noisiest source IPs and an hourly histogram of failed logins
  6. Privileged logins - root/admin accounts logged into from an IP that failed first

Usage:  python log_analyser.py sample_logs/auth.log
        python log_analyser.py sample_logs/windows_security.csv
        python log_analyser.py auth.log --learn --geoip --top 3 --json out.json --csv out.csv
        python log_analyser.py auth.log --allow 10.0.0.0/8 --since 2025-01-01 --spray-users 4 --fail-on-alert
        python log_analyser.py auth.log --privileged root --markdown report.md
        python log_analyser.py auth.log --threshold 5 --window 5 --night-start 0 --night-end 6
"""

import argparse
import csv
import json
import ipaddress
import os
import re
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------- appearance
# ANSI colour codes. They make the report easier to read in a terminal.
if os.name == "nt":
    os.system("")  # tiny trick that switches on colour support in Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # so box-drawing characters print correctly

RED, YELLOW, GREEN, CYAN = "\033[91m", "\033[93m", "\033[92m", "\033[96m"
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
WIDTH = 72


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
# This pattern pulls the useful parts out of each log line.
LINE_PATTERN = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .*?"
    r"(?P<result>Accepted|Failed) password for (?P<user>\S+) from (?P<ip>\S+)"
)


def parse_windows_csv(path):
    """Read Windows Security events exported to CSV (see README for the export command).

    Event 4625 = failed logon, event 4624 = successful logon.
    Needed columns: TimeCreated, EventId, TargetUserName, IpAddress.
    """
    events = []
    with open(path, encoding="utf-8-sig", newline="") as f:  # utf-8-sig handles PowerShell's BOM
        for row in csv.DictReader(f):
            if row["EventId"] not in ("4624", "4625"):
                continue  # ignore every other kind of Windows event
            events.append({
                "time": datetime.strptime(row["TimeCreated"][:19], "%Y-%m-%d %H:%M:%S"),
                "success": row["EventId"] == "4624",
                "user": row["TargetUserName"],
                "ip": row["IpAddress"],
            })
    return events


def parse_log(path, log_format="auto"):
    """Pick the right parser. 'auto' guesses from the file extension (.csv = Windows)."""
    if log_format == "windows" or (log_format == "auto" and path.lower().endswith(".csv")):
        return parse_windows_csv(path)
    return parse_ssh_log(path)


def parse_ssh_log(path):
    """Read an SSH-style log and return a list of events (dicts). Unreadable lines are skipped."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            match = LINE_PATTERN.match(line)
            if match:
                events.append({
                    "time": datetime.strptime(match["time"], "%Y-%m-%d %H:%M:%S"),
                    "success": match["result"] == "Accepted",
                    "user": match["user"],
                    "ip": match["ip"],
                })
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


def filter_events(events, allow, since, until):
    """Drop events from allow-listed IPs/networks and outside the --since/--until range."""
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


# -------------------------------------------------------------------- geoip
def lookup_ip(ip):
    """Look up where an IP is (country, city, ISP) using the free ip-api.com service.

    Private and reserved addresses are never sent anywhere. Any network problem
    just returns a short message so the report still works offline.
    """
    try:
        if ipaddress.ip_address(ip).is_private:
            return "private/reserved address (not looked up)"
    except ValueError:
        return "not a valid IP address"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.load(response)
        if data.get("status") != "success":
            return "no location found"
        return f"{data['city']}, {data['country']} ({data['isp']})"
    except Exception:  # no internet, rate limited, etc.
        return "lookup failed"


def add_locations(brute_force):
    """Add a 'location' entry to every brute-force source."""
    for ip, info in brute_force.items():
        info["location"] = lookup_ip(ip)


# -------------------------------------------------------------------- export
def build_alerts(brute_force, compromises, odd_hours, spray=None, privileged=None):
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
    for e in privileged or []:
        alerts.append({"type": "privileged_login", "severity": "MEDIUM", "ip": e["ip"], "user": e["user"],
                       "time": e["time"].isoformat(sep=" "),
                       "details": "privileged account login from an IP with earlier failures"})
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


def print_report(path, events, brute_force, odd_hours, compromises, args, spray=None, privileged=None):
    spray = spray or {}
    privileged = privileged or []
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
    total_alerts = len(brute_force) + len(spray) + len(compromises) + len(odd_hours) + len(privileged)
    colour = RED if compromises else YELLOW if total_alerts else GREEN
    print(f"{colour}{BOLD}{total_alerts} alert(s){RESET}: {len(brute_force)} brute-force source(s), "
          f"{len(spray)} spraying source(s), {len(compromises)} possible compromise(s), "
          f"{len(odd_hours)} unusual-hour login(s), {len(privileged)} privileged login(s)")
    if compromises:
        print(f"{RED}Action:{RESET} reset the affected account(s), review what they did, and block the source IP(s).")
    elif brute_force or spray:
        print(f"{YELLOW}Action:{RESET} block the source IP(s) and consider rate-limiting or MFA.")
    print()


# --------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description="Detect brute-force and unusual-hour logins in an auth log.")
    parser.add_argument("logfile", help="path to the log file")
    parser.add_argument("--threshold", type=int, default=5, help="failures needed to flag brute force (default 5)")
    parser.add_argument("--window", type=int, default=5, help="time window in minutes (default 5)")
    parser.add_argument("--night-start", type=int, default=0, help="first 'unusual' hour, 0-23 (default 0)")
    parser.add_argument("--night-end", type=int, default=6, help="hour unusual period ends (default 6)")
    parser.add_argument("--learn", action="store_true",
                        help="learn each user's normal hours instead of using fixed night hours")
    parser.add_argument("--top", type=int, default=None, help="only show the N worst brute-force sources")
    parser.add_argument("--format", choices=["auto", "ssh", "windows"], default="auto",
                        help="log format: ssh text log or Windows Security CSV (default: guess from extension)")
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
    parser.add_argument("--fail-on-alert", action="store_true",
                        help="exit with code 1 on any alert and 2 on a possible compromise (for scripts/CI)")
    parser.add_argument("--json", metavar="FILE", help="also save the alerts to a JSON file")
    parser.add_argument("--csv", metavar="FILE", help="also save the alerts to a CSV file")
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile, args.format)
    except FileNotFoundError:
        sys.exit(f"Error: file not found: {args.logfile}")
    except (KeyError, ValueError):
        sys.exit("Error: could not read the file. Check it matches the expected format (see README).")

    events = filter_events(events, args.allow, args.since, args.until)
    events.sort(key=lambda e: e["time"])
    brute_force = find_brute_force(events, args.threshold, args.window)
    if args.learn:
        odd_hours = find_user_anomalies(events)
    else:
        odd_hours = find_unusual_hours(events, args.night_start, args.night_end)
    compromises = find_compromises(events, brute_force)
    spray = find_password_spray(events, args.spray_users, args.window)
    privileged = find_privileged_logins(events, [n.strip() for n in args.privileged.split(",") if n.strip()], compromises)
    if args.geoip:
        add_locations(brute_force)
    print_report(args.logfile, events, brute_force, odd_hours, compromises, args, spray, privileged)
    alerts = build_alerts(brute_force, compromises, odd_hours, spray, privileged)
    export_alerts(alerts, args.json, args.csv)
    if args.markdown:
        export_markdown(args.markdown, args.logfile, events, alerts)
    if args.fail_on_alert:
        if compromises:
            sys.exit(2)
        if brute_force or spray or odd_hours or privileged:
            sys.exit(1)


if __name__ == "__main__":
    main()
