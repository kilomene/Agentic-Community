"""Tests for Agent Analytics (acp_connector analytics + API aggregates).

Covers: connector-side day-bucketed counters, heartbeat idempotency,
summary(days), opt-in reporting to the directory (signed), server-side
aggregation (counts only), CSV export, and report sig-auth (forged ->
401, stale -> 401, unregistered -> 404, bad metric -> 400).

Privacy: assertions check that no message/file content ever appears in
any analytics surface — see docs/ANALYTICS.md.

Run:  python3 tests/test_analytics.py
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "packages"))
sys.path.insert(0, os.path.join(ROOT, "services", "acp_api"))

from acp_crypto import (  # noqa: E402
    generate_ed25519_keypair, generate_x25519_keypair,
)
from acp_proto import b62encode  # noqa: E402

import server as api_server  # noqa: E402
from client import DirectoryClient, DirectoryError  # noqa: E402
from keys import create_key  # noqa: E402
from acp_connector.analytics import Analytics  # noqa: E402
from acp_connector import Connector  # noqa: E402

API_HOST, API_PORT = "127.0.0.1", 18283
ALL_SCOPES = ["registry:read", "listings:write", "presence:write",
              "analytics:read", "analytics:write", "verify:request"]


def gen_identity():
    ed_priv, ed_pub = generate_ed25519_keypair()
    _, x_pub = generate_x25519_keypair()
    return ed_priv, ed_pub, x_pub


def today_utc():
    return time.strftime("%Y-%m-%d", time.gmtime())


class ConnectorAnalyticsTests(unittest.TestCase):
    """Local counters: no server involved."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="acp_analytics_conn_")
        self.conn = Connector(self.home, "analytics-pass", handle="metrics")
        # lazy import + one-line wiring (Connector class untouched)
        self.metrics = Analytics(self.conn)

    def tearDown(self):
        self.conn.stop()

    def test_record_and_summary(self):
        self.metrics.message_sent(nbytes=120)
        self.metrics.message_sent(nbytes=80)
        self.metrics.message_received(nbytes=50)
        self.metrics.file_completed()
        self.metrics.pairing_completed()
        self.metrics.call_placed()
        s = self.metrics.summary(days=30)
        c = s["counters"]
        self.assertEqual(c["messages_sent"], 2)
        self.assertEqual(c["bytes_sent"], 200)
        self.assertEqual(c["messages_received"], 1)
        self.assertEqual(c["bytes_received"], 50)
        self.assertEqual(c["files_completed"], 1)
        self.assertEqual(c["pairings"], 1)
        self.assertEqual(c["calls_placed"], 1)
        self.assertEqual(c["uptime_days"], 0)
        self.assertEqual(s["to_day"], today_utc())

    def test_heartbeat_idempotent(self):
        for _ in range(5):
            self.metrics.heartbeat()
        self.assertEqual(self.metrics.get("uptime_days"), 1)

    def test_day_bucketing(self):
        self.metrics.record("messages_sent", 3, day="2026-01-01")
        self.metrics.record("messages_sent", 7, day="2026-01-02")
        self.assertEqual(self.metrics.daily("messages_sent", days=365),
                         [("2026-01-01", 3), ("2026-01-02", 7)])
        # explicit old days don't leak into a 30-day summary
        self.assertEqual(self.metrics.get("messages_sent", days=30), 0)

    def test_unknown_metric_rejected(self):
        with self.assertRaises(ValueError):
            self.metrics.record("message_text", 1)

    def test_no_content_recorded(self):
        # even hostile input is reduced to counts
        self.metrics.message_sent(nbytes=10)
        s = self.metrics.summary()
        blob = str(s)
        self.assertNotIn("secret", blob)
        self.assertNotIn("text", blob.replace("bytes_sent", ""))

    def test_summary_window(self):
        with self.assertRaises(ValueError):
            self.metrics.summary(days=0)
        with self.assertRaises(ValueError):
            self.metrics.summary(days=366)


class DirectoryAnalyticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="acp_analytics_api_")
        cls.db_path = os.path.join(cls.tmp, "registry.db")
        cls.server, cls.thread = api_server.run(API_HOST, API_PORT,
                                                db_path=cls.db_path)
        raw, _ = create_key(cls.db_path, name="test",
                            scopes=ALL_SCOPES, per_min=100000)
        cls.client = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                     api_key=raw)
        cls.plain = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT))
        cls.alice_priv, cls.alice_pub, alice_x = gen_identity()
        cls.client.register("alice_a", b62encode(cls.alice_pub),
                            b62encode(alice_x))

    @classmethod
    def tearDownClass(cls):
        api_server.graceful_shutdown(cls.server, cls.thread)

    def test_report_and_read(self):
        # dedicated handle: other tests' reports must not leak in
        priv, pub, x_pub = gen_identity()
        self.client.register("alice_a2", b62encode(pub), b62encode(x_pub))
        day = today_utc()
        resp = self.client.report_analytics(
            "alice_a2", day,
            {"messages_sent": 10, "bytes_sent": 2048, "uptime_days": 1},
            priv)
        self.assertEqual(resp["ok"], True)
        self.assertEqual(resp["stored"], 3)
        # public read, counts only
        got = self.plain.get_analytics("alice_a2")
        self.assertEqual(got["handle"], "alice_a2")
        self.assertEqual(got["counters"]["messages_sent"], 10)
        self.assertEqual(got["counters"]["bytes_sent"], 2048)
        self.assertEqual(got["counters"]["uptime_days"], 1)

    def test_report_aggregates_across_days(self):
        day2 = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 86400))
        self.client.report_analytics(
            "alice_a", day2, {"messages_sent": 4}, self.alice_priv)
        got = self.client.get_analytics("alice_a", days=30)
        self.assertGreaterEqual(got["counters"]["messages_sent"], 14)

    def test_report_unknown_handle_404(self):
        ghost_priv, _, _ = gen_identity()
        with self.assertRaises(DirectoryError) as cm:
            self.client.report_analytics(
                "ghost_a_xyz", today_utc(), {"messages_sent": 1},
                ghost_priv)
        self.assertEqual(cm.exception.status, 404)

    def test_report_forged_sig_401(self):
        evil_priv, _, _ = gen_identity()
        with self.assertRaises(DirectoryError) as cm:
            self.client.report_analytics(
                "alice_a", today_utc(), {"messages_sent": 999}, evil_priv)
        self.assertEqual(cm.exception.status, 401)
        # the forged numbers did not land
        got = self.client.get_analytics("alice_a")
        self.assertNotEqual(got["counters"].get("messages_sent"), 999)

    def test_report_stale_ts_401(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client._request(
                "POST", "/v1/analytics/report",
                {"handle": "alice_a", "day": today_utc(),
                 "counters": {"messages_sent": 1},
                 "ts": int(time.time()) - 900, "sig": "0"})
        self.assertEqual(cm.exception.status, 401)

    def test_report_bad_metric_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.report_analytics(
                "alice_a", today_utc(), {"message_text": 1},
                self.alice_priv)
        self.assertEqual(cm.exception.status, 400)

    def test_report_negative_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client.report_analytics(
                "alice_a", today_utc(), {"messages_sent": -1},
                self.alice_priv)
        self.assertEqual(cm.exception.status, 400)

    def test_report_no_key_401(self):
        with self.assertRaises(DirectoryError) as cm:
            self.plain.report_analytics(
                "alice_a", today_utc(), {"messages_sent": 1},
                self.alice_priv)
        self.assertEqual(cm.exception.status, 401)

    def test_report_wrong_scope_403(self):
        raw, _ = create_key(self.db_path, name="narrow",
                            scopes=["presence:write"], per_min=100000)
        narrow = DirectoryClient("http://%s:%d" % (API_HOST, API_PORT),
                                 api_key=raw)
        with self.assertRaises(DirectoryError) as cm:
            narrow.report_analytics(
                "alice_a", today_utc(), {"messages_sent": 1},
                self.alice_priv)
        self.assertEqual(cm.exception.status, 403)

    def test_get_unknown_handle_404(self):
        with self.assertRaises(DirectoryError) as cm:
            self.plain.get_analytics("ghost_a_xyz")
        self.assertEqual(cm.exception.status, 404)

    def test_get_bad_days_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.plain.get_analytics("alice_a", days=999)
        self.assertEqual(cm.exception.status, 400)

    def test_export_csv(self):
        day = today_utc()
        self.client.report_analytics(
            "alice_a", day, {"messages_sent": 10}, self.alice_priv)
        csv = self.client.export_analytics("alice_a", days=30, format="csv")
        lines = csv.strip().split("\n")
        self.assertEqual(lines[0], "handle,day,metric,value")
        rows = [l.split(",") for l in lines[1:]]
        self.assertTrue(any(r[0] == "alice_a" and r[2] == "messages_sent"
                            for r in rows))
        # counts only: four columns, no content fields
        for r in rows:
            self.assertEqual(len(r), 4)

    def test_export_json(self):
        body = self.client._request(
            "GET", "/v1/analytics/alice_a/export",
            params={"days": 30, "format": "json"})[1]
        self.assertEqual(body["handle"], "alice_a")
        self.assertIn("counters", body)

    def test_export_bad_format_400(self):
        with self.assertRaises(DirectoryError) as cm:
            self.client._request("GET", "/v1/analytics/alice_a/export",
                                 params={"format": "xml"})
        self.assertEqual(cm.exception.status, 400)

    def test_privacy_no_content_fields(self):
        got = self.plain.get_analytics("alice_a")
        blob = str(got)
        for forbidden in ("message_text", "content", "payload", "filename"):
            self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
