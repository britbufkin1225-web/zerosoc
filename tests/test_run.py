import tempfile
import unittest
from pathlib import Path

import run


class ZeroSOCHelperTests(unittest.TestCase):
    def test_normalize_route_handles_trailing_slashes(self):
        self.assertEqual(run.normalize_route(""), "/")
        self.assertEqual(run.normalize_route("/"), "/")
        self.assertEqual(run.normalize_route("/api/v1/events/"), "/api/v1/events")

    def test_create_and_read_security_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir = run.DATA_DIR
            original_db_file = run.DB_FILE

            try:
                run.DATA_DIR = temp_dir
                run.DB_FILE = str(Path(temp_dir) / "zerosoc-test.db")
                run.init_database()

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
                run.DATA_DIR = original_data_dir
                run.DB_FILE = original_db_file

    def test_security_event_summary_counts_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir = run.DATA_DIR
            original_db_file = run.DB_FILE

            try:
                run.DATA_DIR = temp_dir
                run.DB_FILE = str(Path(temp_dir) / "zerosoc-test.db")
                run.init_database()

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
                run.DATA_DIR = original_data_dir
                run.DB_FILE = original_db_file


if __name__ == "__main__":
    unittest.main()
