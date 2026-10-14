"""Unit tests for log_analyser. Run with:  python -m unittest -v"""

import os
import tempfile
import unittest
from datetime import datetime

import log_analyser as la


def ev(minute, success, user="root", ip="198.51.100.9", hour=10):
    return {"time": datetime(2025, 10, 1, hour, minute), "success": success, "user": user, "ip": ip}


class ParsingTests(unittest.TestCase):
    def parse(self, text, year=2025):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return la.parse_ssh_log(path, year)

    def test_iso_timestamp(self):
        events = self.parse("2025-10-01 10:00:00 h sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2\n")
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0]["success"])
        self.assertEqual((events[0]["user"], events[0]["ip"]), ("root", "198.51.100.9"))

    def test_syslog_timestamp_and_invalid_user(self):
        events = self.parse("Oct  3 02:14:05 h sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2\n")
        self.assertEqual(events[0]["time"], datetime(2025, 10, 3, 2, 14, 5))
        self.assertEqual(events[0]["user"], "admin")  # not the word "invalid"

    def test_publickey_login_is_success(self):
        events = self.parse("Oct  3 09:00:00 h sshd[1]: Accepted publickey for bob from 198.51.100.2 port 22 ssh2\n")
        self.assertTrue(events[0]["success"])

    def test_junk_lines_skipped(self):
        self.assertEqual(self.parse("hello\nOct  3 09:00:00 h cron[1]: job done\n"), [])


class DetectionTests(unittest.TestCase):
    def test_brute_force_threshold(self):
        fails = [ev(m, False) for m in range(5)]
        self.assertIn("198.51.100.9", la.find_brute_force(fails, 5, 5))
        self.assertEqual(la.find_brute_force(fails[:4], 5, 5), {})

    def test_brute_force_window(self):
        spread = [ev(0, False, hour=10 + m) for m in range(5)]  # one failure an hour apart
        self.assertEqual(la.find_brute_force(spread, 5, 5), {})

    def test_password_spray(self):
        events = [ev(i, False, user=u) for i, u in enumerate(["a", "b", "c", "d"])]
        self.assertIn("198.51.100.9", la.find_password_spray(events, 4, 5))
        self.assertEqual(la.find_password_spray(events, 5, 5), {})

    def test_compromise_needs_success_after_burst(self):
        events = [ev(m, False) for m in range(5)] + [ev(6, True, user="carol")]
        brute = la.find_brute_force(events, 5, 5)
        self.assertEqual(len(la.find_compromises(events, brute)), 1)

    def test_privileged_login_only_after_failure_from_same_ip(self):
        events = [ev(0, False), ev(1, True), ev(2, True, ip="198.51.100.8")]
        hits = la.find_privileged_logins(events, ["root"], [])
        self.assertEqual([e["ip"] for e in hits], ["198.51.100.9"])

    def test_privileged_login_skips_known_compromise(self):
        events = [ev(0, False), ev(1, True)]
        self.assertEqual(la.find_privileged_logins(events, ["root"], [events[1]]), [])

    def test_unusual_hours(self):
        events = [ev(0, True, hour=3), ev(0, True, hour=12), ev(0, False, hour=3)]
        self.assertEqual(len(la.find_unusual_hours(events, 0, 6)), 1)

    def test_allow_list(self):
        events = [ev(0, False, ip="10.1.2.3"), ev(1, False)]
        kept = la.filter_events(events, ["10.0.0.0/8"], None, None)
        self.assertEqual([e["ip"] for e in kept], ["198.51.100.9"])

    def test_rankings(self):
        events = [ev(0, False, ip="1.1.1.1"), ev(1, False, ip="1.1.1.1"), ev(2, False, ip="2.2.2.2")]
        self.assertEqual(la.top_source_ips(events)[0], ("1.1.1.1", 2))


class AdvancedTests(unittest.TestCase):
    def test_distributed_attack_many_ips_one_account(self):
        events = [ev(i, False, user="admin", ip=f"203.0.113.{i}") for i in range(5)]
        found = la.find_distributed_attack(events, 5, 5)
        self.assertEqual(found["admin"]["ip_count"], 5)
        self.assertEqual(la.find_distributed_attack(events[:4], 5, 5), {})
        self.assertEqual(la.find_brute_force(events, 5, 5), {})  # no single IP is loud enough

    def test_distributed_alert_is_built(self):
        events = [ev(i, False, user="admin", ip=f"203.0.113.{i}") for i in range(5)]
        dist = la.find_distributed_attack(events, 5, 5)
        alerts = la.build_alerts({}, [], [], None, None, dist)
        self.assertEqual(alerts[0]["type"], "distributed_attack")

    def test_risk_scores_add_up_and_skip_non_ips(self):
        alerts = [
            {"severity": "CRITICAL", "type": "brute_force", "ip": "1.1.1.1"},
            {"severity": "HIGH", "type": "password_spray", "ip": "1.1.1.1"},
            {"severity": "LOW", "type": "unusual_hour_login", "ip": "2.2.2.2"},
            {"severity": "HIGH", "type": "distributed_attack", "ip": "multiple (5 IPs)"},
        ]
        scores = la.risk_scores(alerts)
        self.assertEqual(scores[0], ("1.1.1.1", 60, ["brute_force", "password_spray"]))
        self.assertEqual([s[0] for s in scores], ["1.1.1.1", "2.2.2.2"])

    def test_risk_score_is_capped(self):
        alerts = [{"severity": "CRITICAL", "type": f"t{i}", "ip": "1.1.1.1"} for i in range(5)]
        self.assertEqual(la.risk_scores(alerts)[0][1], 100)

    def test_config_file_sets_defaults_and_cli_wins(self):
        import argparse
        import sys
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"threshold": 3, "since": "2025-01-02", "allow": ["10.0.0.0/8"]}')
            parser = argparse.ArgumentParser()
            parser.add_argument("--config")
            parser.add_argument("--threshold", type=int, default=5)
            parser.add_argument("--since", type=la.parse_date)
            parser.add_argument("--allow", action="append", default=[])
            old = sys.argv
            try:
                sys.argv = ["x", "--config", path]
                la.apply_config(parser)
                args = parser.parse_args(["--threshold", "9"])
            finally:
                sys.argv = old
        self.assertEqual(args.threshold, 9)
        self.assertEqual(args.since, datetime(2025, 1, 2))
        self.assertEqual(args.allow, ["10.0.0.0/8"])

    def test_config_rejects_unknown_key(self):
        import argparse
        import sys
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"nonsense": 1}')
            parser = argparse.ArgumentParser()
            parser.add_argument("--config")
            old = sys.argv
            try:
                sys.argv = ["x", "--config", path]
                with self.assertRaises(SystemExit):
                    la.apply_config(parser)
            finally:
                sys.argv = old


class NewFeatureTests(unittest.TestCase):
    def test_new_source_login_needs_history(self):
        events = [ev(i, True, user="bob", ip="10.0.0.1") for i in range(3)] + [ev(5, True, user="bob", ip="198.51.100.77")]
        hits = la.find_new_source_logins(events)
        self.assertEqual([e["ip"] for e in hits], ["198.51.100.77"])
        # too little history: a second IP on the 2nd login is not suspicious yet
        few = [ev(0, True, user="eve", ip="10.0.0.1"), ev(1, True, user="eve", ip="10.0.0.2")]
        self.assertEqual(la.find_new_source_logins(few), [])

    def test_new_source_login_reported_once_per_ip(self):
        events = [ev(i, True, user="bob", ip="10.0.0.1") for i in range(3)]
        events += [ev(5, True, user="bob", ip="198.51.100.77"), ev(6, True, user="bob", ip="198.51.100.77")]
        self.assertEqual(len(la.find_new_source_logins(events)), 1)

    def test_multi_ip_logins(self):
        events = [ev(i, True, user="alice", ip=f"203.0.113.{i}") for i in range(3)]
        self.assertEqual(la.find_multi_ip_logins(events, 3, 5)["alice"]["ip_count"], 3)
        self.assertEqual(la.find_multi_ip_logins(events, 4, 5), {})
        spread = [ev(0, True, user="alice", ip=f"203.0.113.{i}", hour=10 + i) for i in range(3)]
        self.assertEqual(la.find_multi_ip_logins(spread, 3, 5), {})

    def test_new_alert_types_are_built(self):
        events = [ev(i, True, user="alice", ip=f"203.0.113.{i}") for i in range(3)]
        multi = la.find_multi_ip_logins(events, 3, 5)
        alerts = la.build_alerts({}, [], [], None, None, None, [events[0]], multi)
        self.assertEqual({a["type"] for a in alerts}, {"new_source_login", "multi_ip_login"})

    def test_gzip_ssh_log(self):
        import gzip
        line = "2025-10-01 10:00:00 h sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2\n"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log.gz")
            with gzip.open(path, "wt", encoding="utf-8") as f:
                f.write(line)
            self.assertEqual(len(la.parse_log(path)), 1)

    def test_gzip_csv_is_detected_as_windows(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sec.csv.gz")
            with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
                f.write("TimeCreated,EventId,TargetUserName,IpAddress\n2025-10-01 10:00:00,4625,bob,198.51.100.9\n")
            events = la.parse_log(path)
        self.assertEqual((events[0]["user"], events[0]["success"]), ("bob", False))


class ExportTests(unittest.TestCase):
    def test_html_report_escapes_input(self):
        events = [ev(0, False, user="<script>")]
        alerts = [{"type": "brute_force", "severity": "HIGH", "ip": "1.1.1.1", "user": "<script>",
                   "time": "2025-10-01 10:00:00", "details": "x"}]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            la.export_html(path, "auth.log", events, alerts)
            with open(path, encoding="utf-8") as f:
                page = f.read()
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)


# ------------------------------------------------------------------ helpers for the newer tests
def write_temp(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return path


def make_args(*argv):
    """The real default options, optionally overridden: make_args('--threshold', '3')."""
    return la.build_parser().parse_args(["x.log", *argv])


class MoreSshLineTests(unittest.TestCase):
    def feed(self, *lines):
        parser, events, specials = la.SshParser(2025), [], []
        for line in lines:
            parser.feed(line + "\n", events, specials)
        return events, specials

    def test_pam_and_other_methods(self):
        events, _ = self.feed(
            "2025-10-01 10:00:00 h sshd[1]: Failed keyboard-interactive/pam for bob from 198.51.100.9 port 22 ssh2",
            "2025-10-01 10:00:01 h sshd[2]: Failed none for invalid user admin from 198.51.100.9 port 22 ssh2",
            "2025-10-01 10:00:02 h sshd[3]: Accepted gssapi-with-mic for bob from 198.51.100.9 port 22 ssh2")
        self.assertEqual([e["success"] for e in events], [False, False, True])

    def test_one_attempt_logged_three_ways_counts_once(self):
        events, _ = self.feed(
            "2025-10-01 10:00:00 h sshd[7]: Invalid user oracle from 198.51.100.9 port 1",
            "2025-10-01 10:00:00 h sshd[7]: Failed password for invalid user oracle from 198.51.100.9 port 1 ssh2",
            "2025-10-01 10:00:02 h sshd[7]: Connection closed by authenticating user oracle 198.51.100.9 port 1 [preauth]")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["user"], "oracle")

    def test_weak_lines_count_when_nothing_else_was_logged(self):
        events, _ = self.feed(
            "2025-10-01 10:00:00 h sshd[7]: Invalid user test from 198.51.100.9 port 1",
            "2025-10-01 10:00:09 h sshd[8]: Connection closed by authenticating user root 198.51.100.8 port 2 [preauth]")
        self.assertEqual([(e["user"], e["ip"]) for e in events], [("test", "198.51.100.9"), ("root", "198.51.100.8")])

    def test_lines_without_pid_are_never_merged(self):
        events, _ = self.feed(
            "2025-10-01 10:00:00 Invalid user a from 198.51.100.9 port 1",
            "2025-10-01 10:00:01 Invalid user b from 198.51.100.9 port 1")
        self.assertEqual(len(events), 2)

    def test_sudo_and_su_failures_are_specials(self):
        events, specials = self.feed(
            "Oct  3 02:14:05 h sudo:      bob : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/sh",
            "Oct  3 02:15:00 h su[99]: FAILED SU (to root) carol on /dev/pts/1",
            "Oct  3 02:16:00 h su[99]: FAILED su for root by dave")
        self.assertEqual(events, [])
        self.assertEqual([(s["user"], s["count"], s["via"]) for s in specials],
                         [("bob", 3, "sudo"), ("carol", 1, "su"), ("dave", 1, "su")])


class WindowsAndWebParsingTests(unittest.TestCase):
    def test_windows_lockout_local_ip_and_logon_types(self):
        text = ("TimeCreated,EventId,TargetUserName,IpAddress,LogonType\n"
                "2025-10-01 10:00:00,4625,bob,198.51.100.9,3\n"
                "2025-10-01 10:00:01,4624,bob,-,2\n"
                "2025-10-01 10:00:02,4624,SYSTEM,-,5\n"
                "2025-10-01 10:00:03,4740,bob,,\n")
        with tempfile.TemporaryDirectory() as d:
            specials = []
            events = la.parse_log(write_temp(d, "sec.csv", text), specials=specials)
        self.assertEqual([(e["user"], e["ip"]) for e in events], [("bob", "198.51.100.9"), ("bob", "local")])
        self.assertEqual([s["kind"] for s in specials], ["lockout"])

    def test_windows_csv_without_logon_type_still_works(self):
        text = "TimeCreated,EventId,TargetUserName,IpAddress\n2025-10-01 10:00:00,4625,bob,198.51.100.9\n"
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(len(la.parse_log(write_temp(d, "sec.csv", text))), 1)

    WEB = ('198.51.100.9 - admin [01/Oct/2025:10:00:00 +0000] "GET /admin/ HTTP/1.1" 401 10 "-" "ua"\n'
           '198.51.100.9 - - [01/Oct/2025:10:00:01 +0000] "GET /.env HTTP/1.1" 404 10 "-" "ua"\n'
           '198.51.100.9 - - [01/Oct/2025:10:00:02 +0000] "POST /wp-login.php HTTP/1.1" 200 10 "-" "ua"\n'
           '198.51.100.9 - - [01/Oct/2025:10:00:03 +0000] "GET /index.html HTTP/1.1" 200 10 "-" "ua"\n'
           'garbage line\n')

    def test_web_log_events_and_probes(self):
        with tempfile.TemporaryDirectory() as d:
            specials = []
            events = la.parse_log(write_temp(d, "access.log", self.WEB), specials=specials)
        self.assertEqual([(e["user"], e["success"]) for e in events], [("admin", False), ("-", False)])
        self.assertEqual([(s["kind"], s["path"]) for s in specials], [("probe", "/.env")])

    def test_format_is_guessed_from_the_file_name(self):
        self.assertEqual(la.detect_format("a/auth.log", "auto"), "ssh")
        self.assertEqual(la.detect_format("sec.CSV.gz", "auto"), "windows")
        self.assertEqual(la.detect_format("nginx/access.log.1", "auto"), "web")
        self.assertEqual(la.detect_format("whatever", "web"), "web")


class NewDetectionTests(unittest.TestCase):
    def test_takeover_from_many_ips_and_no_double_report(self):
        events = [ev(i, False, user="erin", ip=f"192.0.2.{i}") for i in range(5)] + [ev(5, True, user="erin", ip="192.0.2.99")]
        hits = la.find_account_takeovers(events, 5, 5)
        self.assertEqual(len(hits), 1)
        self.assertIn("5 failed logins", hits[0]["reason"])
        self.assertEqual(la.find_account_takeovers(events + [ev(6, True, user="erin")], 5, 5), hits)  # failures were consumed

    def test_takeover_needs_enough_failures_inside_the_window(self):
        few = [ev(i, False, user="erin") for i in range(4)] + [ev(5, True, user="erin")]
        self.assertEqual(la.find_account_takeovers(few, 5, 5), [])
        old = [ev(0, False, user="erin", hour=8)] * 5 + [ev(0, True, user="erin", hour=10)]
        self.assertEqual(la.find_account_takeovers(old, 5, 5), [])

    def test_takeover_skips_known_compromises_and_counts_distributed_attacks(self):
        events = [ev(i, False) for i in range(5)] + [ev(6, True)]
        self.assertEqual(la.find_account_takeovers(events, 5, 5, already=[events[-1]]), [])
        spread = [ev(i, False, user="admin", ip=f"203.0.113.{i}") for i in range(5)] + [ev(7, True, user="admin")]
        dist = la.find_distributed_attack(spread, 5, 5)
        hits = la.find_account_takeovers(spread, 99, 5, dist)
        self.assertEqual(len(hits), 1)
        self.assertIn("distributed attack", hits[0]["reason"])

    def test_low_and_slow_finds_patient_ips_only(self):
        slow = [ev(0, False, hour=h) for h in range(20)]  # one failure an hour for 20 hours
        self.assertIn("198.51.100.9", la.find_low_and_slow(slow, 20, 24))
        self.assertEqual(la.find_low_and_slow(slow, 20, 24, loud={"198.51.100.9"}), {})
        self.assertEqual(la.find_low_and_slow(slow, 0, 24), {})
        self.assertEqual(la.find_low_and_slow(slow[:19], 20, 24), {})

    def test_haversine(self):
        london, new_york = (51.5074, -0.1278), (40.7128, -74.0060)
        self.assertAlmostEqual(la.haversine_km(london, new_york), 5570, delta=30)
        self.assertEqual(la.haversine_km(london, london), 0)

    def test_impossible_travel(self):
        places = {"1.1.1.1": {"lat": 51.5, "lon": -0.12, "label": "London"},
                  "2.2.2.2": {"lat": 40.7, "lon": -74.0, "label": "New York"},
                  "3.3.3.3": {"lat": 51.6, "lon": -0.1, "label": "Also London"}}
        events = [ev(0, True, user="al", ip="1.1.1.1"), ev(30, True, user="al", ip="2.2.2.2")]
        hits = la.find_impossible_travel(events, places.get)
        self.assertEqual((hits[0]["from_place"], hits[0]["to_place"]), ("London", "New York"))
        # same trip with a day in between is fine, and a nearby IP is not travel
        later = [ev(0, True, user="al", ip="1.1.1.1", hour=1), ev(0, True, user="al", ip="2.2.2.2", hour=23)]
        self.assertEqual(la.find_impossible_travel(later, places.get), [])
        near = [ev(0, True, user="al", ip="1.1.1.1"), ev(1, True, user="al", ip="3.3.3.3")]
        self.assertEqual(la.find_impossible_travel(near, places.get), [])
        self.assertEqual(la.find_impossible_travel(events, lambda ip: None), [])  # unknown places are ignored

    def test_widest_burst_modes(self):
        from datetime import timedelta
        items = [{"time": datetime(2025, 1, 1, 0, m), "k": m % 2, "w": 2} for m in range(4)]
        window = timedelta(minutes=5)
        self.assertEqual(la.widest_burst(items, window, 4)[0], 4)
        self.assertEqual(la.widest_burst(items, window, 2, key=lambda i: i["k"])[0], 2)
        self.assertEqual(la.widest_burst(items, window, 8, weight=lambda i: i["w"])[0], 8)
        self.assertIsNone(la.widest_burst(items, window, 5))

    def test_web_scanners_need_distinct_paths(self):
        def probe(s, path, ip="1.1.1.1"):
            return {"kind": "probe", "time": datetime(2025, 1, 1, 0, 0, s), "ip": ip, "path": path}
        specials = [probe(0, "/.env"), probe(1, "/.git/config"), probe(2, "/xmlrpc.php"), probe(3, "/.env", ip="2.2.2.2")]
        found = la.find_web_scanners(specials, 3, 5)
        self.assertEqual(list(found), ["1.1.1.1"])
        self.assertEqual(found["1.1.1.1"]["path_count"], 3)
        self.assertEqual(la.find_web_scanners(specials[:2], 3, 5), {})

    def test_priv_failures_add_up_the_attempt_counts(self):
        def fail(m, n):
            return {"kind": "priv_fail", "time": datetime(2025, 1, 1, 0, m), "user": "bob", "count": n, "via": "sudo"}
        self.assertEqual(la.find_priv_failures([fail(0, 3)], 3, 5)["bob"]["count"], 3)
        self.assertEqual(la.find_priv_failures([fail(0, 1), fail(1, 1)], 3, 5), {})
        self.assertEqual(la.find_priv_failures([fail(0, 2), fail(1, 2)], 3, 5)["bob"]["count"], 4)

    def test_new_alert_types_are_built(self):
        takeover = [{**ev(0, True), "reason": "why"}]
        slow = {"1.1.1.1": {"count": 20, "first": datetime(2025, 1, 1), "last": datetime(2025, 1, 1, 20), "users": ["a"]}}
        lockout = [{"kind": "lockout", "time": datetime(2025, 1, 1), "user": "bob", "ip": "PC1"}]
        scanners = {"2.2.2.2": {"path_count": 3, "requests": 3, "first": datetime(2025, 1, 1), "paths": ["/.env"]}}
        priv = {"bob": {"count": 3, "first": datetime(2025, 1, 1), "last": datetime(2025, 1, 1), "via": ["sudo"]}}
        travel = [{**ev(0, True), "from_ip": "9.9.9.9", "km": 5000, "hours": 0.5, "from_place": "A", "to_place": "B"}]
        alerts = la.build_alerts({}, [], [], takeovers=takeover, slow=slow, travel=travel, lockouts=lockout,
                                 scanners=scanners, priv_fails=priv)
        self.assertEqual({a["type"] for a in alerts}, {"account_takeover", "low_and_slow", "impossible_travel",
                                                        "account_lockout", "web_scanner", "privilege_escalation_attempts"})

    def test_analyse_end_to_end_on_samples(self):
        here = os.path.dirname(os.path.abspath(__file__))
        specials = []
        events = la.parse_log(os.path.join(here, "sample_logs", "auth.log"), specials=specials, year=2026)
        events.sort(key=lambda e: e["time"])
        specials.sort(key=lambda s: s["time"])
        res = la.analyse(events, specials, make_args())
        types = {a["type"] for a in res["alerts"]}
        for expected in ("brute_force", "possible_compromise", "account_takeover", "low_and_slow",
                         "privilege_escalation_attempts", "password_spray"):
            self.assertIn(expected, types)


class GeoIpTests(unittest.TestCase):
    def setUp(self):
        self._saved = (dict(la.GEO_CACHE), la.GEO_READER, la.GEO_MIN_INTERVAL, la._lookup_web)
        la.GEO_CACHE.clear()
        la.GEO_READER = None

    def tearDown(self):
        la.GEO_CACHE.clear()
        la.GEO_CACHE.update(self._saved[0])
        la.GEO_READER, la.GEO_MIN_INTERVAL, la._lookup_web = self._saved[1:]

    def test_private_and_invalid_addresses_are_never_sent(self):
        la._lookup_web = lambda ip: self.fail("must not look this up")
        self.assertIn("private", la.lookup_ip("10.1.2.3"))
        self.assertIn("private", la.lookup_ip("198.51.100.9"))
        self.assertIn("not a valid", la.lookup_ip("local"))

    def test_answers_are_cached(self):
        calls = []
        la._lookup_web = lambda ip: calls.append(ip) or {"label": "Paris, France (ISP)", "lat": 48.8, "lon": 2.3}
        self.assertEqual(la.lookup_ip("8.8.8.8"), "Paris, France (ISP)")
        la.lookup_ip("8.8.8.8")
        self.assertEqual(calls, ["8.8.8.8"])
        self.assertEqual(la.locate("8.8.8.8")["lat"], 48.8)

    def test_failed_lookups_are_not_cached(self):
        answers = iter([{"label": "lookup failed", "failed": True}, {"label": "Rome, Italy (X)"}])
        la._lookup_web = lambda ip: next(answers)
        self.assertEqual(la.lookup_ip("8.8.4.4"), "lookup failed")
        self.assertEqual(la.lookup_ip("8.8.4.4"), "Rome, Italy (X)")
        self.assertIsNone(la.locate("8.8.4.4"))  # no coordinates in that answer

    def test_web_lookups_are_rate_limited(self):
        la._lookup_web = self._saved[3]
        la.GEO_MIN_INTERVAL = 0.2
        la._last_geo_request[0] = la.time.monotonic()
        slept = []
        real_sleep, la.time.sleep = la.time.sleep, slept.append
        real_open = la.urllib.request.urlopen
        la.urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("offline"))
        try:
            self.assertEqual(la.lookup_ip("1.0.0.1"), "lookup failed")
        finally:
            la.time.sleep, la.urllib.request.urlopen = real_sleep, real_open
        self.assertTrue(slept and 0 < slept[0] <= 0.2)

    def test_cache_file_round_trip_and_bad_file(self):
        la.GEO_CACHE["8.8.8.8"] = {"label": "X", "lat": 1.0, "lon": 2.0}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "geo.json")
            la.save_geo_cache(path)
            la.GEO_CACHE.clear()
            la.load_geo_cache(path)
            self.assertEqual(la.GEO_CACHE["8.8.8.8"]["lat"], 1.0)
            la.GEO_CACHE.clear()
            la.load_geo_cache(write_temp(d, "bad.json", "{not json"))
            la.load_geo_cache(os.path.join(d, "missing.json"))
        self.assertEqual(la.GEO_CACHE, {})

    def test_local_database_reader_is_used_instead_of_the_web(self):
        class Obj:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        class Reader:
            def city(self, ip):
                if ip == "8.8.4.4":
                    raise KeyError("not in db")
                return Obj(city=Obj(name="Oslo"), country=Obj(name="Norway"), location=Obj(latitude=59.9, longitude=10.7))

        la.GEO_READER = Reader()
        la._lookup_web = lambda ip: self.fail("must not use the web")
        self.assertEqual(la.lookup_ip("8.8.8.8"), "Oslo, Norway")
        self.assertEqual(la.locate("8.8.8.8")["lon"], 10.7)
        self.assertEqual(la.lookup_ip("8.8.4.4"), "no location found")


class OutputTests(unittest.TestCase):
    RES = {"brute_force": {"203.0.113.5": {}, "10.0.0.5": {}}, "spray": {"2001:db8::1": {}}, "slow": {},
           "scanners": {"127.0.0.1": {}}, "compromises": [{"ip": "8.8.8.8"}, {"ip": "not an ip"}],
           "distributed": {"admin": {"ips": ["1.1.1.1", "10.9.9.9"]}}}

    def test_blocklist_skips_private_loopback_and_junk(self):
        self.assertEqual([str(a) for a in la.blocklist_ips(self.RES)], ["1.1.1.1", "8.8.8.8"])
        everything = [str(a) for a in la.blocklist_ips(self.RES, include_private=True)]
        self.assertIn("10.0.0.5", everything)
        self.assertIn("2001:db8::1", everything)
        self.assertNotIn("127.0.0.1", everything)

    def test_blocklist_formats(self):
        addresses = la.blocklist_ips(self.RES, include_private=True)
        with tempfile.TemporaryDirectory() as d:
            def written(fmt):
                path = os.path.join(d, fmt)
                la.export_blocklist(path, fmt, addresses)
                with open(path, encoding="utf-8") as f:
                    return f.read()
            self.assertIn("ufw deny from 8.8.8.8 to any", written("ufw"))
            iptables = written("iptables")
            self.assertIn("iptables -I INPUT -s 8.8.8.8 -j DROP", iptables)
            self.assertIn("ip6tables -I INPUT -s 2001:db8::1 -j DROP", iptables)
            nft = written("nft")
            self.assertIn("nft add rule inet filter input ip saddr 8.8.8.8 drop", nft)
            self.assertIn("ip6 saddr 2001:db8::1", nft)
            plain = written("plain")
            self.assertIn("\n8.8.8.8\n", plain)
            self.assertTrue(plain.startswith("# Generated"))

    def test_baseline_hides_known_alerts_and_survives_a_round_trip(self):
        a = {"type": "brute_force", "severity": "HIGH", "ip": "1.1.1.1", "user": "root", "time": "2025-10-01 10:00:00", "details": "x"}
        b = {**a, "ip": "2.2.2.2"}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "base.json")
            self.assertEqual(la.load_baseline(path), [])  # missing file = empty baseline
            la.save_baseline(path, [], [a])
            la.save_baseline(path, la.load_baseline(path), [a, b])
            saved = la.load_baseline(path)
            self.assertEqual(len(saved), 2)
            with self.assertRaises(SystemExit):
                la.load_baseline(write_temp(d, "bad.json", '{"not": "a list"}'))
            with self.assertRaises(SystemExit):
                la.load_baseline(write_temp(d, "worse.json", "{oops"))
        self.assertEqual(la.alert_key(a), "brute_force|1.1.1.1|root|2025-10-01 10:00:00")

    def alerts(self):
        return [{"type": "possible_compromise", "severity": "CRITICAL", "ip": "1.1.1.1", "user": "u", "time": "t", "details": "d"},
                {"type": "unusual_hour_login", "severity": "LOW", "ip": "2.2.2.2", "user": "u", "time": "t", "details": "d"}]

    def test_notify_filters_by_severity_and_survives_errors(self):
        sent, real = [], la.send_webhook
        la.send_webhook = lambda url, text: sent.append((url, text))
        try:
            args = make_args("--webhook", "https://hooks.example/x")
            self.assertEqual(la.notify(self.alerts(), args), 1)  # default HIGH keeps only the CRITICAL one
            self.assertIn("possible_compromise", sent[0][1])
            self.assertNotIn("unusual_hour", sent[0][1])
            self.assertEqual(la.notify(self.alerts(), make_args("--webhook", "https://h/x", "--notify-min-severity", "LOW")), 2)
            self.assertEqual(la.notify(self.alerts(), make_args()), 0)  # nowhere to send
            la.send_webhook = lambda url, text: (_ for _ in ()).throw(OSError("down"))
            self.assertEqual(la.notify(self.alerts(), args), 1)  # does not raise
        finally:
            la.send_webhook = real

    def test_webhook_rejects_non_http_urls(self):
        for url in ("file:///etc/passwd", "ftp://x/y", "javascript:alert(1)"):
            with self.assertRaises(ValueError):
                la.send_webhook(url, "hi")

    def test_email_goes_through_smtp_with_starttls_and_login(self):
        log = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                log.append(("connect", host, port))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def starttls(self):
                log.append(("starttls",))

            def login(self, user, password):
                log.append(("login", user))

            def send_message(self, message):
                log.append(("send", message["To"], message["Subject"]))

        real, la.smtplib.SMTP = la.smtplib.SMTP, FakeSMTP
        saved_env = {k: os.environ.get(k) for k in ("SMTP_USER", "SMTP_PASSWORD")}
        os.environ["SMTP_USER"], os.environ["SMTP_PASSWORD"] = "me", "pw"
        try:
            args = make_args("--smtp", "mail.example:587", "--mail-to", "ops@example.com")
            self.assertEqual(la.notify(self.alerts(), args), 1)
        finally:
            la.smtplib.SMTP = real
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual([entry[0] for entry in log], ["connect", "starttls", "login", "send"])
        self.assertEqual(log[0], ("connect", "mail.example", 587))
        self.assertEqual(log[3][1], "ops@example.com")

    def test_timeline_buckets_hours_then_days(self):
        events = [ev(0, False, hour=1), ev(5, False, hour=1), ev(0, False, hour=3), ev(0, True, hour=2)]
        labels, counts = la.failure_timeline(events)
        self.assertEqual(counts, [2, 0, 1])
        self.assertEqual(labels[0], "10-01 01:00")
        week = [{"time": datetime(2025, 10, 1), "success": False, "user": "a", "ip": "1.1.1.1"},
                {"time": datetime(2025, 10, 12, 5), "success": False, "user": "a", "ip": "1.1.1.1"}]
        labels, counts = la.failure_timeline(week)
        self.assertEqual((len(counts), counts[0], counts[-1], labels[0]), (12, 1, 1, "2025-10-01"))
        self.assertEqual(la.failure_timeline([ev(0, True)]), ([], []))

    def test_html_report_has_charts_and_stays_escaped(self):
        events = [ev(m, False, user="<b>x</b>") for m in range(6)]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.html")
            la.export_html(path, "auth.log", events, [])
            with open(path, encoding="utf-8") as f:
                page = f.read()
        self.assertEqual(page.count("<svg"), 2)
        self.assertIn("Failed logins by hour of day", page)
        self.assertIn("<title>10: 6 failed login(s)</title>", page)  # per-bar tooltip
        self.assertNotIn("<b>x</b>", page)

    def test_chart_for_a_log_without_failures(self):
        self.assertIn("No failed logins", la.chart_section("Nothing", [0, 0], ["a", "b"]))


class FollowTests(unittest.TestCase):
    LINE = "2025-10-01 10:00:{s:02d} h sshd[{pid}]: Failed password for root from 203.0.113.9 port 22 ssh2\n"

    def attack(self, start, count, pid=100):
        return "".join(self.LINE.format(s=start + i, pid=pid + i) for i in range(count))

    def setup_log(self, text, *argv):
        """A temp log plus a Follower on it; both are cleaned up in the right order (file closed first)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)  # registered first, so it runs last (after the follower closes its file)
        directory = tmp.name
        path = write_temp(directory, "auth.log", text)
        follower = la.Follower(path, make_args("--year", "2025", *argv))
        self.addCleanup(follower.close)
        return directory, path, follower

    def append(self, path, text):
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)

    def test_only_new_alerts_are_reported_and_history_is_ignored(self):
        _, path, follower = self.setup_log(self.attack(0, 5))  # an old attack, already in the file
        self.assertEqual(len(follower.seen), 1)
        self.assertEqual(follower.poll(), [])  # nothing appended
        self.append(path, "2025-10-01 10:01:00 h sshd[9]: Accepted password for bob from 198.51.100.1 port 22 ssh2\n")
        self.assertEqual(follower.poll(), [])  # a normal login is not an alert (the hour is not unusual)
        self.append(path, "2025-10-01 02:30:00 h sshd[10]: Accepted password for bob from 198.51.100.1 port 22 ssh2\n")
        self.assertEqual([a["type"] for a in follower.poll()], ["unusual_hour_login"])
        self.assertEqual(follower.poll(), [])  # not announced twice

    def test_a_new_burst_is_announced_as_it_happens(self):
        _, path, follower = self.setup_log("")
        self.append(path, self.attack(0, 4))
        self.assertEqual(follower.poll(), [])
        self.append(path, self.attack(4, 2, pid=200))
        self.assertIn("brute_force", [a["type"] for a in follower.poll()])

    def test_log_rotation_is_followed(self):
        directory, path, follower = self.setup_log(self.attack(0, 2))
        follower.file.close()  # Windows cannot delete a file that is still open
        os.remove(path)
        write_temp(directory, "auth.log", self.attack(10, 5, pid=300))  # a fresh file with a new attack
        self.assertIn("brute_force", [a["type"] for a in follower.poll()])

    def test_old_events_are_dropped_to_bound_memory(self):
        _, path, follower = self.setup_log(
            "2025-10-01 10:00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1\n", "--follow-hours", "1")
        self.append(path, "2025-10-02 10:00:00 h sshd[2]: Failed password for b from 2.2.2.2 port 1\n")
        follower.poll()
        self.assertEqual([e["user"] for e in follower.events], ["b"])


class OptionTests(unittest.TestCase):
    def test_new_options_have_safe_defaults(self):
        args = make_args()
        self.assertEqual((args.slow_threshold, args.slow_window, args.travel, args.follow), (20, 24, False, False))
        self.assertEqual((args.notify_min_severity, args.blocklist_format, args.scan_paths, args.sudo_threshold),
                         ("HIGH", "plain", 3, 3))

    def test_config_file_can_set_the_new_options(self):
        import sys
        with tempfile.TemporaryDirectory() as d:
            path = write_temp(d, "c.json", '{"slow_threshold": 7, "blocklist_format": "ufw", "notify_min_severity": "LOW"}')
            parser, old = la.build_parser(), sys.argv
            try:
                sys.argv = ["x", "--config", path]
                la.apply_config(parser)
                args = parser.parse_args(["x.log"])
            finally:
                sys.argv = old
        self.assertEqual((args.slow_threshold, args.blocklist_format, args.notify_min_severity), (7, "ufw", "LOW"))

    def run_cli(self, *argv):
        import contextlib
        import io
        import sys
        out, old, code = io.StringIO(), sys.argv, 0
        sys.argv = ["log_analyser.py", *argv, "--no-color"]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                la.main()
        except SystemExit as exc:
            code = exc.code or 0
        finally:
            sys.argv = old
        return code, out.getvalue()

    def test_cli_baseline_workflow_and_exit_codes(self):
        here = os.path.dirname(os.path.abspath(__file__))
        sample = os.path.join(here, "sample_logs", "auth.log")
        with tempfile.TemporaryDirectory() as d:
            base = os.path.join(d, "base.json")
            code, _ = self.run_cli(sample, "--year", "2026", "--fail-on-alert")
            self.assertEqual(code, 2)  # the sample contains a possible compromise
            code, _ = self.run_cli(sample, "--year", "2026", "--baseline", base, "--update-baseline", "--fail-on-alert")
            self.assertEqual(code, 2)  # first run: everything is new
            code, out = self.run_cli(sample, "--year", "2026", "--baseline", base, "--fail-on-alert")
            self.assertEqual(code, 0)  # second run: nothing new
            self.assertIn("Nothing new", out)

    def test_cli_rejects_bad_option_combinations(self):
        for argv in (["a.log", "--smtp", "host"], ["a.log", "--update-baseline"],
                     ["a.log", "b.log", "--follow"], ["-", "--follow"], ["x.csv", "--follow"]):
            code, _ = self.run_cli(*argv)
            self.assertEqual(code, 2, argv)

    def test_cli_writes_blocklist_and_html(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with tempfile.TemporaryDirectory() as d:
            block, page = os.path.join(d, "block.txt"), os.path.join(d, "r.html")
            self.run_cli(os.path.join(here, "sample_logs", "access.log"), "--blocklist", block, "--blocklist-private",
                         "--blocklist-format", "iptables", "--html", page)
            with open(block, encoding="utf-8") as f:
                self.assertIn("iptables -I INPUT -s 203.0.113.99 -j DROP", f.read())
            self.assertTrue(os.path.getsize(page) > 1000)


class RoundThreeTests(unittest.TestCase):
    def feed(self, *lines):
        parser, events, specials = la.SshParser(2025), [], []
        for line in lines:
            parser.feed(line + "\n", events, specials)
        return events, specials

    def test_journalctl_and_rfc3339_timestamps(self):
        events, _ = self.feed(
            "2025-10-01T10:00:00+0000 host sshd[1]: Failed password for root from 198.51.100.9 port 22 ssh2",
            "2025-10-01T10:00:01.123456+02:00 host sshd[2]: Failed password for bob from 198.51.100.9 port 22 ssh2",
            "2025-10-01T10:00:02Z host sshd[3]: Accepted publickey for bob from 198.51.100.9 port 22 ssh2")
        self.assertEqual([e["time"].second for e in events], [0, 1, 2])
        self.assertEqual(events[0]["time"].hour, 10)  # the zone suffix is ignored, the written time is kept

    FW = ("2025-10-01 10:00:{s:02d} fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.1 "
          "LEN=44 PROTO=TCP SPT=4444 DPT={port} WINDOW=1024 SYN")

    def test_firewall_lines_become_specials_not_logins(self):
        events, specials = self.feed(self.FW.format(s=0, port=22), "Oct  3 02:14:05 h kernel: IPTABLES-DROP: SRC=1.2.3.4 DST=5.6.7.8 PROTO=UDP DPT=53")
        self.assertEqual(events, [])
        self.assertEqual([(s["ip"], s["port"], s["proto"]) for s in specials], [("203.0.113.9", 22, "TCP"), ("1.2.3.4", 53, "UDP")])

    def test_firewall_line_without_block_word_or_ports_is_ignored(self):
        _, specials = self.feed("2025-10-01 10:00:00 fw kernel: [UFW ALLOW] SRC=1.1.1.1 DPT=22",
                                "2025-10-01 10:00:00 fw kernel: [UFW BLOCK] SRC=1.1.1.1 no destination port")
        self.assertEqual(specials, [])

    def test_port_scan_needs_distinct_ports_in_the_window(self):
        _, specials = self.feed(*[self.FW.format(s=i, port=20 + i) for i in range(10)],
                                *[self.FW.format(s=i, port=23).replace("203.0.113.9", "203.0.113.10") for i in range(20)])
        found = la.find_port_scans(specials, 10, 5)
        self.assertEqual(list(found), ["203.0.113.9"])  # the host hammering one port is not a scanner
        self.assertEqual(found["203.0.113.9"]["port_count"], 10)
        self.assertEqual(la.find_port_scans(specials, 11, 5), {})

    def test_port_scan_alert_blocklist_and_end_to_end(self):
        here = os.path.dirname(os.path.abspath(__file__))
        specials = []
        events = la.parse_log(os.path.join(here, "sample_logs", "ufw.log"), specials=specials, year=2026)
        res = la.analyse(events, specials, make_args())
        self.assertEqual([a["type"] for a in res["alerts"]], ["port_scan"])
        self.assertEqual([str(a) for a in la.blocklist_ips(res, include_private=True)], ["203.0.113.120"])

    def test_ignore_user_drops_events_case_insensitively(self):
        events = [ev(0, False, user="Nagios"), ev(1, False, user="root")]
        self.assertEqual([e["user"] for e in la.filter_events(events, [], None, None, ["nagios"])], ["root"])
        self.assertEqual(len(la.filter_events(events, [], None, None)), 2)
        self.assertEqual(make_args("--ignore-user", "a", "--ignore-user", "b").ignore_user, ["a", "b"])

    def test_windows_timestamp_formats(self):
        for text, expected in (("2025-10-01 10:00:00", (10, 0)), ("2025-10-01T10:00:00.5Z", (10, 0)),
                               ("10/01/2025 13:05:00", (13, 5)), ("10/01/2025 01:05:00 PM", (13, 5))):
            when = la.parse_windows_time(text)
            self.assertEqual((when.month, when.day, (when.hour, when.minute)), (10, 1, expected), text)
        with self.assertRaises(ValueError):
            la.parse_windows_time("25/10/2025 10:00:00")  # day-first is refused, not guessed

    def test_windows_csv_with_us_timestamps(self):
        text = "TimeCreated,EventId,TargetUserName,IpAddress\n10/01/2025 10:00:00,4625,bob,198.51.100.9\n"
        with tempfile.TemporaryDirectory() as d:
            events = la.parse_log(write_temp(d, "sec.csv", text))
        self.assertEqual(events[0]["time"], datetime(2025, 10, 1, 10, 0))


if __name__ == "__main__":
    unittest.main()
