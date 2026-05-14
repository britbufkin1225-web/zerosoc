import json
import tempfile
import unittest
from pathlib import Path

import run


class ZeroSOCHelperTests(unittest.TestCase):
    def configure_temp_database(self, temp_dir):
        original_data_dir = run.DATA_DIR
        original_db_file = run.DB_FILE

        run.DATA_DIR = temp_dir
        run.DB_FILE = str(Path(temp_dir) / "zerosoc-test.db")
        run.init_database()

        return original_data_dir, original_db_file

    def restore_temp_database(self, original_data_dir, original_db_file):
        run.DATA_DIR = original_data_dir
        run.DB_FILE = original_db_file

    def test_normalize_route_handles_trailing_slashes(self):
        self.assertEqual(run.normalize_route(""), "/")
        self.assertEqual(run.normalize_route("/"), "/")
        self.assertEqual(run.normalize_route("/api/v1/events/"), "/api/v1/events")

    def test_create_and_read_security_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="manual-test",
                    severity="low",
                    source="unittest",
                    message="Manual test event"
                )

                fetched = run.get_security_event_by_id(created["id"])

                self.assertIsNotNone(fetched)
                self.assertEqual(fetched["event_type"], "manual-test")
                self.assertEqual(fetched["severity"], "low")
                self.assertEqual(fetched["source_ip"], "unittest")
                self.assertIn("type:manual-test", fetched["tags"])
                self.assertIn("source:unittest", fetched["tags"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_security_event_summary_counts_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="medium",
                    source="unittest",
                    message="Failed login from test"
                )

                summary = run.get_security_event_summary()

                self.assertEqual(summary["total_events"], 1)
                self.assertEqual(summary["severity_counts"]["medium"], 1)
                self.assertEqual(summary["event_type_counts"]["auth-failure"], 1)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_events_summary_includes_tags_and_latest_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                first = run.create_security_event(
                    event_type="auth-failure",
                    severity="medium",
                    source="unittest",
                    message="Failed login from test"
                )
                latest = run.create_security_event(
                    event_type="port-scan",
                    severity="high",
                    source="unittest",
                    message="Possible port scan from test"
                )

                summary = run.get_events_summary()

                self.assertEqual(summary["total_events"], 2)
                self.assertEqual(summary["by_severity"]["medium"], 1)
                self.assertEqual(summary["by_severity"]["high"], 1)
                self.assertEqual(summary["by_event_type"]["auth-failure"], 1)
                self.assertEqual(summary["by_event_type"]["port-scan"], 1)
                self.assertEqual(summary["by_tag"]["source:unittest"], 2)
                self.assertEqual(summary["latest_event"]["id"], latest["id"])
                self.assertNotEqual(summary["latest_event"]["id"], first["id"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_process_network_devices_marks_new_then_known(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                device = {
                    "ip_address": "192.168.1.42",
                    "hostname": "test-device",
                    "status": "online",
                    "mac_address": "aa:bb:cc:dd:ee:ff"
                }

                first_scan = run.process_network_devices([device.copy()])
                second_scan = run.process_network_devices([device.copy()])
                stored_devices = run.get_recent_network_devices()
                summary = run.get_security_event_summary()

                self.assertEqual(len(first_scan["unknown_devices"]), 1)
                self.assertFalse(first_scan["devices"][0]["known"])
                self.assertEqual(first_scan["devices"][0]["device_status"], "new")

                self.assertEqual(len(second_scan["unknown_devices"]), 0)
                self.assertTrue(second_scan["devices"][0]["known"])
                self.assertEqual(second_scan["devices"][0]["device_status"], "known")

                self.assertEqual(len(stored_devices), 1)
                self.assertEqual(stored_devices[0]["ip_address"], "192.168.1.42")
                self.assertEqual(summary["total_events"], 1)
                self.assertEqual(summary["event_type_counts"]["unknown-device"], 1)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_include_high_priority_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="manual-test",
                    severity="low",
                    source="unittest",
                    message="Low severity event"
                )
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )

                alerts = run.get_alerts()
                summary = run.get_alert_summary(alerts)

                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0]["id"], high_event["id"])
                self.assertEqual(alerts[0]["status"], "open")
                self.assertIn("needs-review", alerts[0]["tags"])
                self.assertEqual(summary["total_alerts"], 1)
                self.assertEqual(summary["open_alerts"], 1)
                self.assertEqual(summary["severity_counts"]["high"], 1)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_status_can_be_acknowledged_and_resolved(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )

                acknowledged = run.update_alert_status(
                    high_event["id"],
                    "acknowledged",
                    note="Investigating"
                )
                active_alerts = run.get_alerts()
                active_summary = run.get_alert_summary(active_alerts)

                self.assertEqual(acknowledged["status"], "acknowledged")
                self.assertEqual(active_alerts[0]["status"], "acknowledged")
                self.assertEqual(active_alerts[0]["note"], "Investigating")
                self.assertEqual(active_summary["open_alerts"], 0)
                self.assertEqual(active_summary["acknowledged_alerts"], 1)

                resolved = run.update_alert_status(high_event["id"], "resolved")
                active_alerts = run.get_alerts()
                all_alerts = run.get_alerts(status="all")
                all_summary = run.get_alert_summary(all_alerts)

                self.assertEqual(resolved["status"], "resolved")
                self.assertEqual(active_alerts, [])
                self.assertEqual(all_alerts[0]["status"], "resolved")
                self.assertEqual(all_summary["resolved_alerts"], 1)
                self.assertEqual(
                    run.get_alerts(status="resolved")[0]["id"],
                    high_event["id"]
                )
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_status_rejects_non_alert_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                low_event = run.create_security_event(
                    event_type="manual-test",
                    severity="low",
                    source="unittest",
                    message="Low severity event"
                )

                self.assertIsNone(
                    run.update_alert_status(low_event["id"], "acknowledged")
                )

                with self.assertRaises(ValueError):
                    run.update_alert_status(low_event["id"], "invalid")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_request_log_helpers_parse_recent_logs_and_metrics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_log_file = run.REQUEST_LOG_FILE
            original_db_file = run.DB_FILE
            log_file = Path(temp_dir) / "requests.log"
            db_file_without_request_logs = Path(temp_dir) / "no-request-log-table.db"
            run.REQUEST_LOG_FILE = str(log_file)
            run.DB_FILE = str(db_file_without_request_logs)

            try:
                entries = [
                    {
                        "timestamp": "2026-05-13T20:00:00",
                        "request_id": "req-1",
                        "method": "GET",
                        "endpoint": "/api/v1/health",
                        "client_ip": "127.0.0.1",
                        "status_code": 200,
                        "latency_ms": 10.0,
                        "message": "Health check"
                    },
                    {
                        "timestamp": "2026-05-13T20:01:00",
                        "request_id": "req-2",
                        "method": "GET",
                        "endpoint": "/api/v1/system",
                        "client_ip": "127.0.0.1",
                        "status_code": 500,
                        "latency_ms": 30.0,
                        "message": "System error"
                    }
                ]

                log_file.write_text(
                    "\n".join(json.dumps(entry) for entry in entries)
                    + "\nnot-json\n",
                    encoding="utf-8"
                )

                recent_logs = run.get_recent_logs(limit=2)
                metrics = run.get_request_metrics()

                self.assertEqual(recent_logs[0]["request_id"], "req-2")
                self.assertTrue(recent_logs[1]["parse_error"])
                self.assertEqual(metrics["total_requests_logged"], 2)
                self.assertEqual(metrics["status_code_counts"]["200"], 1)
                self.assertEqual(metrics["status_code_counts"]["500"], 1)
                self.assertEqual(metrics["recent_error_count"], 1)
                self.assertEqual(metrics["average_latency_ms"], 20.0)
            finally:
                run.REQUEST_LOG_FILE = original_log_file
                run.DB_FILE = original_db_file

    def test_request_logs_are_stored_and_read_from_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.save_request_log({
                    "timestamp": "2026-05-13T20:00:00",
                    "request_id": "req-db-1",
                    "method": "GET",
                    "endpoint": "/api/v1/health",
                    "client_ip": "127.0.0.1",
                    "status_code": 200,
                    "latency_ms": 8.5,
                    "message": "Health check"
                })
                run.save_request_log({
                    "timestamp": "2026-05-13T20:01:00",
                    "request_id": "req-db-2",
                    "method": "GET",
                    "endpoint": "/api/v1/system",
                    "client_ip": "127.0.0.1",
                    "status_code": 401,
                    "latency_ms": 11.5,
                    "message": "Unauthorized request"
                })

                recent_logs = run.get_recent_logs(limit=2)
                metrics = run.get_request_metrics()

                self.assertEqual(recent_logs[0]["request_id"], "req-db-1")
                self.assertEqual(recent_logs[1]["request_id"], "req-db-2")
                self.assertEqual(metrics["total_requests_logged"], 2)
                self.assertEqual(metrics["status_code_counts"]["200"], 1)
                self.assertEqual(metrics["status_code_counts"]["401"], 1)
                self.assertEqual(metrics["recent_error_count"], 1)
                self.assertEqual(metrics["average_latency_ms"], 10.0)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)


if __name__ == "__main__":
    unittest.main()
