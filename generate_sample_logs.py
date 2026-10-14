"""Generate realistic sample login logs for testing log_analyser.py.

Run:  python generate_sample_logs.py
Output: sample_logs/auth.log, sample_logs/windows_security.csv, sample_logs/access.log

The log uses the same shape as a simplified SSH auth log:
    2026-10-01 03:12:44 sshd[1234]: Failed password for admin from 203.0.113.45 port 51234
All IP addresses come from the reserved documentation ranges (RFC 5737),
so they are safe, fake addresses.
"""

import os
import random
from datetime import datetime, timedelta

random.seed(42)  # same seed = same log every time, so results are repeatable

USERS = ["alice", "bob", "carol", "dave", "erin"]
OFFICE_IPS = {  # each employee normally logs in from one internal address
    "alice": "198.51.100.10",
    "bob": "198.51.100.11",
    "carol": "198.51.100.12",
    "dave": "198.51.100.13",
    "erin": "198.51.100.14",
}
START = datetime(2026, 10, 1, 0, 0, 0)

lines = []  # list of (timestamp, text) so we can sort everything at the end


def add(when, outcome, user, ip):
    """Add one log line. outcome is 'Accepted' or 'Failed'."""
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 65000)
    text = f"{when:%Y-%m-%d %H:%M:%S} sshd[{pid}]: {outcome} password for {user} from {ip} port {port}"
    lines.append((when, text))


# 1. Normal behaviour: staff log in during working hours, with the odd typo.
for day in range(3):
    for user in USERS:
        login = START + timedelta(days=day, hours=random.randint(8, 10), minutes=random.randint(0, 59))
        if random.random() < 0.3:  # occasional mistyped password
            add(login - timedelta(seconds=20), "Failed", user, OFFICE_IPS[user])
        add(login, "Accepted", user, OFFICE_IPS[user])

# 2. Brute-force attack: one outside IP hammers the 'admin' account, 40 tries in ~2 minutes.
attacker = "203.0.113.45"
t = START + timedelta(days=1, hours=14, minutes=5)
for i in range(40):
    add(t + timedelta(seconds=i * 3), "Failed", random.choice(["admin", "root"]), attacker)

# 3. Password spraying: a second attacker tries a few common users slowly but persistently.
sprayer = "203.0.113.77"
t = START + timedelta(days=2, hours=2, minutes=30)
for i in range(12):
    add(t + timedelta(seconds=i * 20), "Failed", random.choice(["test", "oracle", "ubuntu", "admin"]), sprayer)

# 4. A successful break-in: attacker guesses 'carol' password after several failures.
breacher = "192.0.2.99"
t = START + timedelta(days=2, hours=3, minutes=12)
for i in range(8):
    add(t + timedelta(seconds=i * 10), "Failed", "carol", breacher)
add(t + timedelta(seconds=90), "Accepted", "carol", breacher)

# 5. Unusual-hour logins: legitimate accounts, but at times nobody normally works.
add(START + timedelta(hours=3, minutes=47), "Accepted", "dave", "198.51.100.13")
add(START + timedelta(days=1, hours=1, minutes=15), "Accepted", "bob", "198.51.100.11")

# 6. Background noise: a few harmless one-off failures from random addresses.
for _ in range(6):
    when = START + timedelta(days=random.randint(0, 2), hours=random.randint(8, 18), minutes=random.randint(0, 59))
    add(when, "Failed", random.choice(USERS), f"192.0.2.{random.randint(100, 200)}")

# 7. A night-shift worker: frank always logs in around 2am. Normal for him, but a
#    fixed "night hours" rule flags it, while `--learn` correctly learns it is normal.
for day in range(3):
    add(START + timedelta(days=day, hours=2, minutes=random.randint(0, 40)), "Accepted", "frank", "198.51.100.15")

# 8. Low and slow: one IP fails once every ~55 minutes - far too slow for the 5-minute brute-force rule.
slow_ip = "203.0.113.88"
for i in range(24):
    add(START + timedelta(days=1, hours=1, minutes=i * 55), "Failed", "backup", slow_ip)

# 9. Account takeover without a loud IP: erin's password is tried once each from six addresses,
#    then one of them gets in. No single IP trips the brute-force rule.
t = START + timedelta(days=2, hours=11, minutes=3)
for i in range(6):
    add(t + timedelta(seconds=i * 20), "Failed", "erin", f"192.0.2.{150 + i}")
add(t + timedelta(seconds=140), "Accepted", "erin", "192.0.2.156")


# 10. Other line types real sshd/sudo write: the same attempt logged twice (counted once),
#     PAM keyboard-interactive failures, and a user who failed sudo three times.
def raw(when, text):
    lines.append((when, f"{when:%Y-%m-%d %H:%M:%S} {text}"))


t = START + timedelta(days=0, hours=16, minutes=20)
raw(t, "sshd[4001]: Invalid user oracle from 192.0.2.120 port 40001")
raw(t, "sshd[4001]: Failed password for invalid user oracle from 192.0.2.120 port 40001 ssh2")
raw(t + timedelta(seconds=5), "sshd[4001]: Connection closed by authenticating user oracle 192.0.2.120 port 40001 [preauth]")
raw(t + timedelta(minutes=1), "sshd[4002]: Failed keyboard-interactive/pam for bob from 192.0.2.121 port 40002 ssh2")
raw(START + timedelta(days=1, hours=11), "sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash")

# Sort by time, then write the file.
lines.sort(key=lambda pair: pair[0])
os.makedirs("sample_logs", exist_ok=True)
with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(text for _, text in lines) + "\n")

print(f"Wrote {len(lines)} log lines to sample_logs/auth.log")

# ---------------------------------------------------------------- Windows sample
# A short Windows Security log in the CSV shape produced by the export command in the README.
# Event 4625 = failed logon, 4624 = successful logon.
win_rows = []


def add_win(when, event_id, user, ip, logon_type="3"):
    win_rows.append((when, event_id, user, ip, logon_type))


t = START + timedelta(days=1, hours=10, minutes=20)
for i in range(25):  # brute force against the Administrator account
    add_win(t + timedelta(seconds=i * 4), 4625, "Administrator", "203.0.113.50")
add_win(t + timedelta(seconds=140), 4624, "Administrator", "203.0.113.50")  # ...and it works
for user in ["alice", "bob"]:  # ordinary logins
    for day in range(3):
        add_win(START + timedelta(days=day, hours=9, minutes=random.randint(0, 40)), 4624, user, "198.51.100.20")
add_win(START + timedelta(days=2, hours=4, minutes=5), 4624, "bob", "198.51.100.20")  # odd hour

# A lockout (4740), a local console logon (no IP) and a service logon (type 5, ignored by the analyser).
add_win(START + timedelta(days=1, hours=10, minutes=22), 4740, "Administrator", "", "")
add_win(START + timedelta(days=1, hours=8, minutes=0), 4624, "alice", "-", "2")
add_win(START + timedelta(days=1, hours=8, minutes=1), 4624, "SYSTEM", "-", "5")

win_rows.sort()
with open("sample_logs/windows_security.csv", "w", encoding="utf-8", newline="") as f:
    f.write("TimeCreated,EventId,TargetUserName,IpAddress,LogonType\n")
    for when, event_id, user, ip, logon_type in win_rows:
        f.write(f"{when:%Y-%m-%d %H:%M:%S},{event_id},{user},{ip},{logon_type}\n")
print(f"Wrote {len(win_rows)} events to sample_logs/windows_security.csv")

# ------------------------------------------------------------ web server sample
# An nginx "combined" access log: a vulnerability scanner, a Basic-auth guesser and a normal visitor.
web_lines = []


def add_web(when, ip, path, status, user="-", method="GET"):
    web_lines.append((when, f'{ip} - {user} [{when:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} 512 "-" "Mozilla/5.0"'))


t = START + timedelta(days=1, hours=5)
for i, path in enumerate(["/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/xmlrpc.php", "/server-status"]):
    add_web(t + timedelta(seconds=i * 2), "203.0.113.99", path, 404)
for i in range(12):  # guessing the Basic-auth password on /admin
    add_web(t + timedelta(hours=3, seconds=i * 5), "203.0.113.100", "/admin/", 401, user="admin")
for i in range(5):  # an ordinary visitor
    add_web(t + timedelta(hours=4, minutes=i * 7), "198.51.100.30", "/index.html", 200)

web_lines.sort(key=lambda pair: pair[0])
with open("sample_logs/access.log", "w", encoding="utf-8") as f:
    f.write("\n".join(text for _, text in web_lines) + "\n")
print(f"Wrote {len(web_lines)} requests to sample_logs/access.log")

# ------------------------------------------------------------ firewall sample
# Kernel firewall lines as written by ufw: one host sweeping many ports (a port scan) and some normal noise.
fw_lines = []


def add_fw(when, ip, port):
    fw_lines.append((when, f"{when:%Y-%m-%d %H:%M:%S} fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=198.51.100.1 "
                           f"LEN=44 TOS=0x00 TTL=52 PROTO=TCP SPT={random.randint(30000, 65000)} DPT={port} WINDOW=1024 SYN"))


t = START + timedelta(days=1, hours=6)
for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 3306, 3389, 5432, 8080]):
    add_fw(t + timedelta(seconds=i), "203.0.113.120", port)
for i in range(4):  # a host that keeps knocking on one port is not a scan
    add_fw(t + timedelta(minutes=10, seconds=i * 30), "203.0.113.121", 23)

fw_lines.sort(key=lambda pair: pair[0])
with open("sample_logs/ufw.log", "w", encoding="utf-8") as f:
    f.write("\n".join(text for _, text in fw_lines) + "\n")
print(f"Wrote {len(fw_lines)} firewall lines to sample_logs/ufw.log")
