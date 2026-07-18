import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import recorder


def pi_event(event_type="started", sequence=1, success=0):
    event_epoch = 1710000000 + sequence
    return {
        "event_id": f"rasp:test-incident:{sequence}",
        "source": "rasp",
        "incident_id": "test-incident",
        "event_type": event_type,
        "event_time": recorder.format_ts(event_epoch),
        "event_epoch": event_epoch,
        "sequence": sequence,
        "batch": {
            "group_window_seconds": 30,
            "batch_started_at": recorder.format_ts(1710000000),
            "batch_started_at_epoch": 1710000000,
        },
        "trigger": {
            "probe_layer": "icmp",
            "job": "blackbox_icmp",
            "target": "192.168.66.1",
            "target_name": "gateway 192.168.66.1",
            "module": "icmp_v4",
            "reason": f"probe_success={success}",
        },
        "probe_results": [
            {
                "sample_at": recorder.format_ts(event_epoch),
                "sample_epoch": event_epoch,
                "job": "blackbox_icmp",
                "probe_layer": "icmp",
                "target": "192.168.66.1",
                "target_name": "gateway 192.168.66.1",
                "module": "icmp_v4",
                "success": success,
                "duration_seconds": 0.1,
                "metrics": [
                    {"name": "probe_success", "labels": {}, "value": success},
                    {"name": "probe_duration_seconds", "labels": {}, "value": 0.1},
                    {"name": "probe_icmp_replies", "labels": {}, "value": success},
                ],
                "error": "",
            }
        ],
        "evidence": {
            "blackbox_debug": {
                "blackbox_icmp|192.168.66.1|icmp_v4": {
                    "fetched_at": recorder.format_ts(event_epoch),
                    "fetched_at_epoch": event_epoch,
                    "job": "blackbox_icmp",
                    "probe_layer": "icmp",
                    "target": "192.168.66.1",
                    "module": "icmp_v4",
                    "metrics": [{"name": "probe_success", "labels": {}, "value": success}],
                    "error": "",
                    "body": f"probe_success {success}\n",
                }
            },
            "pi_snapshot": {"uptime": "100 200"},
            "probe_ring": [],
            "erx_snapshot": {"skipped": "test"},
            "erx_syslog": [],
        },
    }


class PiIngestTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "incidents.db")
        self.old_sqlite_path = recorder.SQLITE_PATH
        self.old_pi_ingest_token = recorder.PI_INGEST_TOKEN
        recorder.SQLITE_PATH = self.db_path

    def tearDown(self):
        recorder.SQLITE_PATH = self.old_sqlite_path
        recorder.PI_INGEST_TOKEN = self.old_pi_ingest_token
        self.tmpdir.cleanup()

    def rows(self, query):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(query).fetchall()
        finally:
            conn.close()

    def test_started_duplicate_and_recovered_are_idempotent(self):
        status, response = recorder.ingest_pi_event(pi_event("started", 1, 0))
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "accepted")

        status, response = recorder.ingest_pi_event(pi_event("started", 1, 0))
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "duplicate")

        incidents = self.rows("SELECT * FROM incidents")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source"], "rasp")
        self.assertEqual(incidents[0]["status"], "down")
        self.assertEqual(incidents[0]["source_incident_id"], "test-incident")

        status, response = recorder.ingest_pi_event(pi_event("recovered", 2, 1))
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "accepted")

        incidents = self.rows("SELECT * FROM incidents")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "recovered")
        self.assertGreaterEqual(incidents[0]["duration_seconds"], 0)

        evidence = self.rows("SELECT event_type FROM incident_evidence ORDER BY sequence")
        self.assertEqual([row["event_type"] for row in evidence], ["started", "recovered"])

    def test_http_ingest_requires_bearer_and_writes_event(self):
        recorder.PI_INGEST_TOKEN = "secret"
        try:
            server = ThreadingHTTPServer(("127.0.0.1", 0), recorder.AnalyzeHandler)
        except PermissionError as exc:
            self.skipTest(f"local listening socket is unavailable in this sandbox: {exc}")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/v1/pi-incident-events"
        body = recorder.json.dumps(pi_event("started", 1, 0)).encode("utf-8")
        try:
            request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
            with self.assertRaises(HTTPError) as context:
                urlopen(request, timeout=2)
            self.assertEqual(context.exception.code, 401)

            request = Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer secret",
                },
                method="POST",
            )
            with urlopen(request, timeout=2) as response:
                payload = recorder.json.loads(response.read())
            self.assertEqual(payload["status"], "accepted")
            self.assertEqual(len(self.rows("SELECT * FROM incident_evidence")), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
