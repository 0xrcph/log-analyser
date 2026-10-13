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


if __name__ == "__main__":
    unittest.main()
