import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import agent


class AgentStateTest(unittest.TestCase):
    def test_parse_probe_metrics(self):
        body = """
# HELP probe_success Displays whether or not the probe was a success
probe_success 0
probe_duration_seconds 0.123
probe_http_status_code{phase="processing"} 502
"""
        metrics = agent.parse_probe_metrics(body)
        self.assertEqual(agent.int_metric(metrics, "probe_success", 1), 0)
        self.assertEqual(agent.float_metric(metrics, "probe_duration_seconds"), 0.123)
        status_metric = [metric for metric in metrics if metric["name"] == "probe_http_status_code"][0]
        self.assertEqual(status_metric["labels"], {"phase": "processing"})

    def test_batch_sequence_and_outbox(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "agent.db")
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            agent.init_db(conn)
            incident_id = agent.create_batch(conn, 1710000000)
            self.assertEqual(agent.next_sequence(conn, incident_id), 1)
            self.assertEqual(agent.next_sequence(conn, incident_id), 2)
            payload = {
                "event_id": "rasp:test:1",
                "source": "rasp",
                "incident_id": incident_id,
                "event_type": "started",
                "event_time": agent.format_ts(1710000000),
                "event_epoch": 1710000000,
                "sequence": 1,
                "trigger": {"target": "192.168.66.1"},
            }
            agent.queue_event(conn, payload)
            agent.queue_event(conn, payload)
            rows = conn.execute("SELECT event_id FROM outbox").fetchall()
            self.assertEqual([row["event_id"] for row in rows], ["rasp:test:1"])
            conn.close()

    def test_parse_ingest_urls_prefers_ordered_fallback_list(self):
        with patch.dict(
            os.environ,
            {
                "DELL_INGEST_URL": "http://legacy.example/ingest",
                "DELL_INGEST_URLS": "http://primary.example/ingest, http://fallback.example/ingest http://primary.example/ingest/",
            },
        ):
            self.assertEqual(
                agent.parse_ingest_urls(),
                ["http://primary.example/ingest", "http://fallback.example/ingest"],
            )

    def test_parse_ingest_urls_keeps_legacy_single_url(self):
        with patch.dict(os.environ, {"DELL_INGEST_URL": "http://legacy.example/ingest"}, clear=True):
            self.assertEqual(agent.parse_ingest_urls(), ["http://legacy.example/ingest"])

    def test_parse_ingest_urls_defaults_to_usb_eth_only(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                agent.parse_ingest_urls(),
                ["http://192.168.66.152:8088/api/v1/pi-incident-events"],
            )


if __name__ == "__main__":
    unittest.main()
