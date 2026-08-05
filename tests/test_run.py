import json
import csv
import io
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

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

    def test_alerts_can_be_filtered_by_severity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )
                medium_event = run.create_security_event(
                    event_type="malware-signal",
                    severity="medium",
                    source="unittest",
                    message="Malware payload detected during test"
                )

                high_alerts = run.get_alerts(severity="high")
                medium_alerts = run.get_alerts(severity="medium")
                all_alerts = run.get_alerts()

                self.assertEqual([alert["id"] for alert in high_alerts], [high_event["id"]])
                self.assertEqual([alert["id"] for alert in medium_alerts], [medium_event["id"]])
                self.assertEqual(len(all_alerts), 2)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_can_be_searched_by_source_message_or_type(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                login_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                malware_event = run.create_security_event(
                    event_type="malware-signal",
                    severity="medium",
                    source="10.0.0.9",
                    message="Suspicious payload detected"
                )

                source_alerts = run.get_alerts(search="10.0.0.5")
                message_alerts = run.get_alerts(search="payload")
                type_alerts = run.get_alerts(search="auth")

                self.assertEqual([alert["id"] for alert in source_alerts], [login_event["id"]])
                self.assertEqual([alert["id"] for alert in message_alerts], [malware_event["id"]])
                self.assertEqual([alert["id"] for alert in type_alerts], [login_event["id"]])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_can_be_exported_as_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login, needs investigation"
                )
                run.update_alert_status(
                    created["id"],
                    "acknowledged",
                    note="Investigating failed login"
                )

                csv_body = run.alerts_to_csv(run.get_alerts(status="all"))
                rows = list(csv.DictReader(io.StringIO(csv_body)))

                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["id"], created["id"])
                self.assertEqual(rows[0]["source_ip"], "10.0.0.5")
                self.assertEqual(rows[0]["status"], "acknowledged")
                self.assertEqual(rows[0]["note"], "Investigating failed login")
                self.assertIn("Repeated failed login", rows[0]["message"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_include_priority_scores(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="critical",
                    source="10.0.0.5",
                    message="Repeated password spray from test"
                )

                alerts = run.get_alerts()
                summary = run.get_alert_summary(alerts)

                self.assertEqual(alerts[0]["id"], created["id"])
                self.assertGreaterEqual(alerts[0]["priority_score"], 85)
                self.assertEqual(alerts[0]["priority_label"], "urgent")
                self.assertEqual(alerts[0]["incident_key"], "10.0.0.5:auth-failure")
                self.assertEqual(summary["highest_priority_score"], alerts[0]["priority_score"])
                self.assertEqual(summary["priority_counts"]["urgent"], 1)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_are_grouped_into_incidents(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                first = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                second = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Another failed login from test"
                )
                run.create_security_event(
                    event_type="malware-signal",
                    severity="critical",
                    source="10.0.0.9",
                    message="Malware signature detected"
                )

                alerts = run.get_alerts()
                incidents = run.group_alerts_into_incidents(alerts)
                auth_incident = next(
                    incident for incident in incidents
                    if incident["id"] == "10.0.0.5:auth-failure"
                )

                self.assertEqual(len(incidents), 2)
                self.assertEqual(auth_incident["alert_count"], 2)
                self.assertEqual(auth_incident["open_alerts"], 2)
                self.assertIn(first["id"], auth_incident["alert_ids"])
                self.assertIn(second["id"], auth_incident["alert_ids"])
                self.assertGreater(auth_incident["highest_priority_score"], 0)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_incidents_can_be_exported_as_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Another failed login from test"
                )

                incidents = run.group_alerts_into_incidents(run.get_alerts())
                rows = list(csv.DictReader(io.StringIO(run.incidents_to_csv(incidents))))

                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["id"], "10.0.0.5:auth-failure")
                self.assertEqual(rows[0]["alert_count"], "2")
                self.assertEqual(rows[0]["source_ip"], "10.0.0.5")
                self.assertIn("auth-failure", rows[0]["event_type"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_incident_state_owner_and_note_are_saved_and_grouped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )

                state = run.update_incident_state(
                    "10.0.0.5:auth-failure",
                    owner="Brit",
                    note="Watching source IP and login spray pattern."
                )
                incidents = run.group_alerts_into_incidents(run.get_alerts())
                incident = incidents[0]
                rows = list(csv.DictReader(io.StringIO(run.incidents_to_csv(incidents))))

                self.assertEqual(state["owner"], "Brit")
                self.assertEqual(incident["owner"], "Brit")
                self.assertEqual(incident["note"], "Watching source IP and login spray pattern.")
                self.assertEqual(rows[0]["owner"], "Brit")
                self.assertIn("Watching source IP", rows[0]["note"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_incident_status_and_activity_are_tracked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )

                state = run.update_incident_state(
                    "10.0.0.5:auth-failure",
                    owner="Brit",
                    note="Watching source IP.",
                    status="investigating"
                )
                incidents = run.group_alerts_into_incidents(run.get_alerts())
                activity = run.get_incident_activity(
                    incident_id="10.0.0.5:auth-failure"
                )
                actions = [item["action"] for item in activity]

                self.assertEqual(state["status"], "investigating")
                self.assertEqual(incidents[0]["status"], "investigating")
                self.assertIn("status_updated", actions)
                self.assertIn("owner_updated", actions)
                self.assertIn("note_updated", actions)
                self.assertEqual(activity[0]["incident_id"], "10.0.0.5:auth-failure")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_incident_activity_can_be_exported_as_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.update_incident_state(
                    "10.0.0.5:auth-failure",
                    owner="Brit",
                    note="Watching source IP.",
                    status="investigating"
                )

                activity = run.get_incident_activity(
                    incident_id="10.0.0.5:auth-failure"
                )
                rows = list(csv.DictReader(io.StringIO(run.incident_activity_to_csv(activity))))

                self.assertGreaterEqual(len(rows), 1)
                self.assertEqual(rows[0]["incident_id"], "10.0.0.5:auth-failure")
                self.assertIn(rows[0]["action"], {"status_updated", "owner_updated", "note_updated"})
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_incident_status_rejects_unknown_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                with self.assertRaises(ValueError):
                    run.update_incident_state(
                        "10.0.0.5:auth-failure",
                        status="waiting"
                    )
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_investigation_reports_can_be_saved_and_listed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )

                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Reviewing source IP and account lockout logs.",
                    status="draft"
                )
                reports = run.get_alert_reports(alert_id=created["id"])
                summary = run.get_alert_report_summary()

                self.assertIsNotNone(report)
                self.assertEqual(report["alert_id"], created["id"])
                self.assertEqual(report["title"], "Failed login investigation")
                self.assertEqual(reports[0]["summary"], "Reviewing source IP and account lockout logs.")
                self.assertEqual(summary["total_reports"], 1)
                self.assertEqual(summary["draft_reports"], 1)
                self.assertEqual(summary["latest_report"]["alert_id"], created["id"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_print_html_includes_report_and_alert_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Reviewed source IP and account lockout logs."
                )

                html_body = run.render_alert_report_html(report)

                self.assertIn("Failed login investigation", html_body)
                self.assertIn("Reviewed source IP", html_body)
                self.assertIn("10.0.0.5", html_body)
                self.assertIn("Repeated failed login", html_body)
                self.assertIn("Print report", html_body)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_status_can_be_finalized_and_reopened(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Reviewed source IP and account lockout logs."
                )

                finalized = run.update_alert_report_status(report["id"], "final")
                final_summary = run.get_alert_report_summary()
                reopened = run.update_alert_report_status(report["id"], "draft")
                draft_summary = run.get_alert_report_summary()

                self.assertEqual(finalized["status"], "final")
                self.assertEqual(final_summary["final_reports"], 1)
                self.assertEqual(final_summary["draft_reports"], 0)
                self.assertEqual(reopened["status"], "draft")
                self.assertEqual(draft_summary["final_reports"], 0)
                self.assertEqual(draft_summary["draft_reports"], 1)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_status_rejects_unknown_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Reviewed source IP and account lockout logs."
                )

                with self.assertRaises(ValueError):
                    run.update_alert_report_status(report["id"], "archived")

                self.assertEqual(run.get_alert_report_by_id(report["id"])["status"], "draft")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_reports_can_be_filtered_by_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                first_alert = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                second_alert = run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Malware signature detected"
                )
                draft_report = run.save_alert_report(
                    alert_id=first_alert["id"],
                    title="Draft failed login report",
                    summary="Still reviewing."
                )
                final_report = run.save_alert_report(
                    alert_id=second_alert["id"],
                    title="Final malware report",
                    summary="Containment complete.",
                    status="final"
                )

                draft_reports = run.get_alert_reports(status="draft")
                final_reports = run.get_alert_reports(status="final")
                all_reports = run.get_alert_reports(status="unknown")

                self.assertEqual([report["id"] for report in draft_reports], [draft_report["id"]])
                self.assertEqual([report["id"] for report in final_reports], [final_report["id"]])
                self.assertEqual(len(all_reports), 2)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_details_can_be_updated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Initial notes."
                )

                updated = run.update_alert_report_details(
                    report_id=report["id"],
                    title="Failed login investigation updated",
                    summary="Confirmed password spray pattern."
                )
                saved = run.get_alert_report_by_id(report["id"])

                self.assertEqual(updated["title"], "Failed login investigation updated")
                self.assertEqual(updated["summary"], "Confirmed password spray pattern.")
                self.assertEqual(saved["title"], "Failed login investigation updated")
                self.assertEqual(saved["summary"], "Confirmed password spray pattern.")
                self.assertEqual(saved["status"], "draft")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_reports_can_be_searched_by_title_or_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                first_alert = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                second_alert = run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Malware signature detected"
                )
                spray_report = run.save_alert_report(
                    alert_id=first_alert["id"],
                    title="Password spray investigation",
                    summary="Reviewing authentication logs."
                )
                containment_report = run.save_alert_report(
                    alert_id=second_alert["id"],
                    title="Malware containment",
                    summary="Endpoint isolated and forensic image captured."
                )

                title_matches = run.get_alert_reports(search="spray")
                summary_matches = run.get_alert_reports(search="forensic")

                self.assertEqual([report["id"] for report in title_matches], [spray_report["id"]])
                self.assertEqual([report["id"] for report in summary_matches], [containment_report["id"]])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_export_bundle_includes_report_and_alert_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Confirmed password spray pattern."
                )

                bundle = run.get_alert_report_export_bundle(report["id"])

                self.assertEqual(bundle["type"], "zerosoc-alert-investigation-report")
                self.assertEqual(bundle["report"]["id"], report["id"])
                self.assertEqual(bundle["report"]["summary"], "Confirmed password spray pattern.")
                self.assertEqual(bundle["alert"]["id"], created["id"])
                self.assertEqual(bundle["alert"]["source_ip"], "10.0.0.5")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_can_be_archived_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Confirmed password spray pattern."
                )

                archived = run.archive_alert_report(report["id"])
                active_reports = run.get_alert_reports()
                archived_reports = run.get_alert_reports(include_archived=True)
                summary = run.get_alert_report_summary()

                self.assertTrue(archived["archived_at"])
                self.assertEqual(active_reports, [])
                self.assertEqual(len(archived_reports), 1)
                self.assertEqual(archived_reports[0]["id"], report["id"])
                self.assertEqual(summary["total_reports"], 1)
                self.assertEqual(summary["active_reports"], 0)
                self.assertEqual(summary["archived_reports"], 1)
                self.assertEqual(summary["draft_reports"], 0)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_archived_alert_report_can_be_restored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Confirmed password spray pattern."
                )

                run.archive_alert_report(report["id"])
                restored = run.restore_alert_report(report["id"])
                active_reports = run.get_alert_reports()
                summary = run.get_alert_report_summary()

                self.assertEqual(restored["archived_at"], "")
                self.assertEqual(len(active_reports), 1)
                self.assertEqual(active_reports[0]["id"], report["id"])
                self.assertEqual(summary["active_reports"], 1)
                self.assertEqual(summary["archived_reports"], 0)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_report_activity_tracks_report_lifecycle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Confirmed password spray pattern."
                )

                run.update_alert_report_status(report["id"], "final")
                run.update_alert_report_details(
                    report_id=report["id"],
                    title="Failed login investigation updated",
                    summary="Confirmed password spray pattern and lockout."
                )
                run.archive_alert_report(report["id"])
                run.restore_alert_report(report["id"])

                activity = run.get_report_activity(report_id=report["id"])
                actions = [item["action"] for item in activity]

                self.assertIn("created", actions)
                self.assertIn("status_updated", actions)
                self.assertIn("details_updated", actions)
                self.assertIn("archived", actions)
                self.assertIn("restored", actions)
                self.assertEqual(activity[0]["report_id"], report["id"])
                self.assertEqual(activity[0]["report_title"], "Failed login investigation updated")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_report_activity_can_be_filtered_by_action_and_exported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                created = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )
                report = run.save_alert_report(
                    alert_id=created["id"],
                    title="Failed login investigation",
                    summary="Confirmed password spray pattern."
                )
                run.archive_alert_report(report["id"])

                archived_activity = run.get_report_activity(
                    report_id=report["id"],
                    action="archived"
                )
                csv_body = run.report_activity_to_csv(archived_activity)

                self.assertEqual(len(archived_activity), 1)
                self.assertEqual(archived_activity[0]["action"], "archived")
                self.assertIn("report_id", csv_body)
                self.assertIn("archived", csv_body)
                self.assertIn("Failed login investigation", csv_body)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_report_rejects_non_alert_events(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                low_event = run.create_security_event(
                    event_type="manual-test",
                    severity="low",
                    source="unittest",
                    message="Low severity event"
                )

                report = run.save_alert_report(
                    alert_id=low_event["id"],
                    title="Low event report",
                    summary="Should not save for a non-alert."
                )

                self.assertIsNone(report)
                self.assertEqual(run.get_alert_reports(), [])
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
                self.assertEqual(resolved["note"], "Investigating")
                self.assertEqual(active_alerts, [])
                self.assertEqual(all_alerts[0]["status"], "resolved")
                self.assertEqual(all_alerts[0]["note"], "Investigating")
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

    def test_unresolved_alert_notifications_are_logged(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )
                run.create_security_event(
                    event_type="manual-test",
                    severity="low",
                    source="unittest",
                    message="Low severity event"
                )

                result = run.notify_unresolved_alerts(channel="dashboard")
                notifications = run.get_alert_notifications()

                self.assertEqual(result["channel"], "dashboard")
                self.assertEqual(result["unresolved_alert_count"], 1)
                self.assertEqual(result["delivered_count"], 1)
                self.assertEqual(notifications[0]["alert_id"], high_event["id"])
                self.assertEqual(notifications[0]["channel"], "dashboard")
                self.assertEqual(notifications[0]["status"], "delivered")
                self.assertEqual(notifications[0]["details"], "Stored in local notification log")
                self.assertIn("Repeated failed login", notifications[0]["message"])

                run.update_alert_status(high_event["id"], "resolved")
                resolved_result = run.notify_unresolved_alerts(channel="dashboard")

                self.assertEqual(resolved_result["unresolved_alert_count"], 0)
                self.assertEqual(resolved_result["delivered_count"], 0)
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_webhook_notifications_are_skipped_without_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )

                result = run.notify_unresolved_alerts(
                    channel="webhook",
                    webhook_url=""
                )
                notification = result["notifications"][0]

                self.assertEqual(result["channel"], "webhook")
                self.assertEqual(result["delivered_count"], 0)
                self.assertEqual(result["failed_count"], 0)
                self.assertEqual(result["skipped_count"], 1)
                self.assertEqual(notification["alert_id"], high_event["id"])
                self.assertEqual(notification["status"], "skipped")
                self.assertIn("not configured", notification["details"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_notification_cooldown_suppresses_duplicates(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                high_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="unittest",
                    message="Repeated failed login from test"
                )

                first_result = run.notify_unresolved_alerts(
                    channel="dashboard",
                    cooldown_seconds=900
                )
                second_result = run.notify_unresolved_alerts(
                    channel="dashboard",
                    cooldown_seconds=900
                )
                notifications = run.get_alert_notifications()

                self.assertEqual(first_result["delivered_count"], 1)
                self.assertEqual(first_result["skipped_count"], 0)
                self.assertEqual(second_result["delivered_count"], 0)
                self.assertEqual(second_result["skipped_count"], 1)
                self.assertEqual(second_result["cooldown_seconds"], 900)
                self.assertEqual(notifications[0]["alert_id"], high_event["id"])
                self.assertEqual(notifications[0]["status"], "skipped")
                self.assertIn("Suppressed duplicate", notifications[0]["details"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_notification_summary_counts_delivery_statuses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.save_alert_notification(
                    alert_id="alert-1",
                    channel="dashboard",
                    status="delivered",
                    message="Delivered alert",
                    details="Stored locally",
                    created_at="2026-05-14T10:00:00"
                )
                run.save_alert_notification(
                    alert_id="alert-2",
                    channel="webhook",
                    status="failed",
                    message="Failed alert",
                    details="Webhook returned HTTP 500",
                    created_at="2026-05-14T10:01:00"
                )
                run.save_alert_notification(
                    alert_id="alert-3",
                    channel="webhook",
                    status="skipped",
                    message="Skipped alert",
                    details="Suppressed duplicate",
                    created_at="2026-05-14T10:02:00"
                )

                summary = run.get_alert_notification_summary()

                self.assertEqual(summary["total_notifications"], 3)
                self.assertEqual(summary["delivered_notifications"], 1)
                self.assertEqual(summary["failed_notifications"], 1)
                self.assertEqual(summary["skipped_notifications"], 1)
                self.assertEqual(summary["channel_counts"]["webhook"], 2)
                self.assertEqual(summary["latest_notification"]["alert_id"], "alert-3")
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

    def test_security_events_can_be_filtered_by_search_type_and_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from workstation"
                )
                run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Ransomware signature detected"
                )

                search_results = run.get_security_events(search="workstation")
                type_results = run.get_security_events(event_type="malware")
                source_results = run.get_security_events(source="10.0.0.5")

                self.assertEqual(len(search_results), 1)
                self.assertEqual(search_results[0]["event_type"], "auth-failure")
                self.assertEqual(len(type_results), 1)
                self.assertEqual(type_results[0]["source_ip"], "10.0.0.9")
                self.assertEqual(len(source_results), 1)
                self.assertEqual(source_results[0]["message"], "Repeated failed login from workstation")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_security_events_can_be_exported_as_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Repeated failed login from test"
                )

                rows = list(csv.DictReader(io.StringIO(run.events_to_csv(run.get_security_events()))))

                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["source_ip"], "10.0.0.5")
                self.assertEqual(rows[0]["event_type"], "auth-failure")
                self.assertIn("high-priority", rows[0]["tags"])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_network_devices_can_be_filtered_and_exported_as_csv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.process_network_devices([
                    {
                        "ip_address": "192.168.1.42",
                        "hostname": "test-laptop",
                        "status": "online",
                        "mac_address": "aa:bb:cc:dd:ee:ff"
                    },
                    {
                        "ip_address": "192.168.1.43",
                        "hostname": "lab-printer",
                        "status": "offline",
                        "mac_address": "aa:bb:cc:dd:ee:00"
                    }
                ])

                filtered = run.get_recent_network_devices(status="online", search="laptop")
                rows = list(csv.DictReader(io.StringIO(run.network_devices_to_csv(filtered))))

                self.assertEqual(len(filtered), 1)
                self.assertEqual(filtered[0]["hostname"], "test-laptop")
                self.assertEqual(rows[0]["ip_address"], "192.168.1.42")
                self.assertEqual(rows[0]["status"], "online")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_security_events_can_be_filtered_by_recent_time_window(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                old_event = run.create_security_event(
                    event_type="auth-failure",
                    severity="medium",
                    source="10.0.0.5",
                    message="Older failed login"
                )
                recent_event = run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Recent malware alert"
                )

                conn = run.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE security_events SET timestamp = ? WHERE id = ?",
                    ((datetime.now() - timedelta(hours=3)).isoformat(), old_event["id"])
                )
                conn.commit()
                conn.close()

                recent_results = run.get_security_events(since_hours=1)

                self.assertEqual([event["id"] for event in recent_results], [recent_event["id"]])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_network_device_summary_counts_stale_devices(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                run.process_network_devices([
                    {
                        "ip_address": "192.168.1.42",
                        "hostname": "old-laptop",
                        "status": "online",
                        "mac_address": "aa:bb:cc:dd:ee:ff"
                    },
                    {
                        "ip_address": "192.168.1.43",
                        "hostname": "fresh-printer",
                        "status": "offline",
                        "mac_address": "aa:bb:cc:dd:ee:00"
                    }
                ])

                conn = run.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE network_devices SET last_seen = ? WHERE ip_address = ?",
                    ((datetime.now() - timedelta(hours=48)).isoformat(), "192.168.1.42")
                )
                conn.commit()
                conn.close()

                devices = run.get_recent_network_devices()
                summary = run.get_network_device_summary(devices)
                rows = list(csv.DictReader(io.StringIO(run.network_devices_to_csv(devices))))

                self.assertEqual(summary["total_devices"], 2)
                self.assertEqual(summary["online_devices"], 1)
                self.assertEqual(summary["offline_devices"], 1)
                self.assertEqual(summary["stale_devices"], 1)
                self.assertIn("is_stale", rows[0])
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alerts_include_sla_fields_and_can_filter_by_sla_and_priority(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                old_alert = run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Critical malware alert from test"
                )
                run.create_security_event(
                    event_type="auth-failure",
                    severity="high",
                    source="10.0.0.5",
                    message="Recent failed login from test"
                )

                conn = run.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE security_events SET timestamp = ? WHERE id = ?",
                    ((datetime.now() - timedelta(hours=2)).isoformat(), old_alert["id"])
                )
                conn.commit()
                conn.close()

                overdue_alerts = run.get_alerts(sla_status="overdue")
                urgent_alerts = run.get_alerts(priority="urgent")
                rows = list(csv.DictReader(io.StringIO(run.alerts_to_csv(overdue_alerts))))

                self.assertEqual([alert["id"] for alert in overdue_alerts], [old_alert["id"]])
                self.assertEqual(overdue_alerts[0]["sla_status"], "overdue")
                self.assertTrue(overdue_alerts[0]["is_overdue"])
                self.assertIn(old_alert["id"], [alert["id"] for alert in urgent_alerts])
                self.assertEqual(rows[0]["sla_status"], "overdue")
                self.assertEqual(rows[0]["is_overdue"], "True")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)

    def test_alert_summary_and_incidents_include_sla_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original_data_dir, original_db_file = self.configure_temp_database(temp_dir)

            try:
                old_alert = run.create_security_event(
                    event_type="malware",
                    severity="critical",
                    source="10.0.0.9",
                    message="Critical malware alert from test"
                )

                conn = run.get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE security_events SET timestamp = ? WHERE id = ?",
                    ((datetime.now() - timedelta(hours=2)).isoformat(), old_alert["id"])
                )
                conn.commit()
                conn.close()

                alerts = run.get_alerts()
                summary = run.get_alert_summary(alerts)
                incidents = run.group_alerts_into_incidents(alerts)
                rows = list(csv.DictReader(io.StringIO(run.incidents_to_csv(incidents))))

                self.assertEqual(summary["overdue_alerts"], 1)
                self.assertEqual(summary["sla_counts"]["overdue"], 1)
                self.assertEqual(incidents[0]["overdue_alerts"], 1)
                self.assertEqual(rows[0]["overdue_alerts"], "1")
            finally:
                self.restore_temp_database(original_data_dir, original_db_file)


class ZeroSOCSecurityHardeningTests(unittest.TestCase):
    """ZS-1 secrets and network exposure hardening regression tests."""

    TEST_KEY = "unit-test-only-key-not-a-real-secret"
    OTHER_KEY = "a-different-unit-test-key"

    def test_missing_api_key_configuration_is_rejected(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(run.ConfigurationError):
                run.get_configured_api_key()

    def test_blank_api_key_configuration_is_rejected(self):
        with mock.patch.dict(os.environ, {"ZEROSOC_API_KEY": "   "}, clear=True):
            with self.assertRaises(run.ConfigurationError):
                run.get_configured_api_key()

    def test_configured_api_key_is_accepted(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": f"  {self.TEST_KEY}  "}, clear=True
        ):
            self.assertEqual(run.get_configured_api_key(), self.TEST_KEY)

    def test_configuration_error_is_guidance_only(self):
        # The error message must be fixed guidance and never interpolate the
        # raw (secret) environment value, so it is identical regardless of the
        # rejected input.
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(run.ConfigurationError) as unset_ctx:
                run.get_configured_api_key()

        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": "  \t \n"}, clear=True
        ):
            with self.assertRaises(run.ConfigurationError) as blank_ctx:
                run.get_configured_api_key()

        self.assertEqual(str(unset_ctx.exception), str(blank_ctx.exception))
        self.assertIn("ZEROSOC_API_KEY", str(unset_ctx.exception))

    def test_is_authorized_rejects_missing_header(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": self.TEST_KEY}, clear=True
        ):
            self.assertFalse(run.is_authorized({}))

    def test_is_authorized_rejects_incorrect_key(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": self.TEST_KEY}, clear=True
        ):
            headers = {run.API_KEY_HEADER: self.OTHER_KEY}
            self.assertFalse(run.is_authorized(headers))

    def test_is_authorized_accepts_correct_key(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": self.TEST_KEY}, clear=True
        ):
            headers = {run.API_KEY_HEADER: self.TEST_KEY}
            self.assertTrue(run.is_authorized(headers))

    def test_is_authorized_fails_closed_without_configured_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            headers = {run.API_KEY_HEADER: self.TEST_KEY}
            self.assertFalse(run.is_authorized(headers))

    def test_requires_auth_protects_bare_system_endpoint(self):
        self.assertTrue(
            run.ZeroSOCHandler.requires_auth(None, "/system")
        )
        self.assertTrue(
            run.ZeroSOCHandler.requires_auth(None, "/api/v1/system")
        )

    def test_public_health_and_status_routes_remain_public(self):
        for endpoint in [
            "/health",
            "/status",
            "/api/v1/health",
            "/api/v1/status",
        ]:
            self.assertFalse(
                run.ZeroSOCHandler.requires_auth(None, endpoint),
                msg=f"{endpoint} should remain public",
            )

    def test_default_host_resolves_to_localhost(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(run.get_configured_host(), "127.0.0.1")

    def test_blank_host_resolves_to_localhost(self):
        with mock.patch.dict(os.environ, {"ZEROSOC_HOST": "  "}, clear=True):
            self.assertEqual(run.get_configured_host(), "127.0.0.1")

    def test_explicit_host_configuration_is_respected(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_HOST": "0.0.0.0"}, clear=True
        ):
            self.assertEqual(run.get_configured_host(), "0.0.0.0")

    def test_cors_defaults_do_not_use_wildcard_origin(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotIn("*", run.get_allowed_origins())

            # An untrusted or wildcard origin receives no CORS grant.
            self.assertEqual(run.build_cors_headers("*"), {})
            self.assertEqual(run.build_cors_headers("http://evil.example"), {})

            allowed = run.build_cors_headers("http://localhost:5500")
            self.assertEqual(
                allowed.get("Access-Control-Allow-Origin"),
                "http://localhost:5500",
            )
            self.assertNotEqual(
                allowed.get("Access-Control-Allow-Origin"), "*"
            )

    def test_private_network_access_is_not_granted_unconditionally(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            for origin in [
                None,
                "*",
                "http://localhost:5500",
                "http://evil.example",
            ]:
                self.assertNotIn(
                    "Access-Control-Allow-Private-Network",
                    run.build_cors_headers(origin),
                )

    def test_no_origin_header_receives_no_cors_headers(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(run.build_cors_headers(None), {})

    def test_configured_allowed_origins_are_parsed(self):
        with mock.patch.dict(
            os.environ,
            {"ZEROSOC_ALLOWED_ORIGINS": "http://a.test:5500, http://b.test:5500 "},
            clear=True,
        ):
            self.assertEqual(
                run.get_allowed_origins(),
                ["http://a.test:5500", "http://b.test:5500"],
            )
            self.assertEqual(run.build_cors_headers("http://c.test"), {})
            self.assertEqual(
                run.build_cors_headers("http://a.test:5500").get(
                    "Access-Control-Allow-Origin"
                ),
                "http://a.test:5500",
            )


if __name__ == "__main__":
    unittest.main()
