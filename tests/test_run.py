import json
import csv
import http.client
import io
import os
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from http.server import HTTPServer
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


# =========================================================================
# ZS-2: HTTP/Auth integration coverage at the real handler boundary
# =========================================================================
#
# These tests exercise the actual ``run.ZeroSOCHandler`` request path -- socket
# read, header parsing, ``do_GET``/``do_OPTIONS`` dispatch, ``normalize_route``,
# ``requires_auth`` + ``is_authorized`` enforcement, the ``end_headers`` CORS
# injection, and JSON response serialization -- rather than calling helper
# functions in isolation.
#
# Boundary exercised: a real loopback ``http.server.HTTPServer`` bound to
# ``127.0.0.1`` on an ephemeral OS-assigned port (``0``), driven with the
# standard-library ``http.client``. The server is started directly (bypassing
# ``run_server``) so no configuration is read at startup, and it is shut down
# deterministically via ``addCleanup``.
#
# Isolation:
#   * ``run.get_system_info`` is patched to a synthetic, host-independent dict.
#     It also doubles as a reach-marker: for authorized requests it must be
#     called; for unauthorized requests it must NOT be called, proving the
#     protected operation was never executed.
#   * ``run.log_request`` is patched out so no request touches the production
#     request log file or SQLite database.
#   * ``run.ZeroSOCHandler.log_message`` is silenced to keep stderr clean.
#   * ``run.DATA_DIR``/``run.DB_FILE`` are pointed at a throwaway temp dir as a
#     defensive guard against any incidental persistence.
#   * Environment (API key, allowed origins) is patched per test with
#     ``mock.patch.dict(..., clear=True)``, guaranteeing restoration and
#     guaranteeing the developer's real API key is never used.
#
# No test opens an external connection, binds a LAN interface, scans a network,
# or contacts a webhook.

# Unmistakably test-only credentials and origins -- never the real secret.
INTEGRATION_API_KEY = "zs2-integration-test-key-not-a-real-secret"
INTEGRATION_WRONG_KEY = "zs2-integration-wrong-key-also-not-real"
ALLOWED_ORIGIN = "https://allowed.zs2.test"
DISALLOWED_ORIGIN = "https://disallowed.zs2.test"

SYNTHETIC_SYSTEM_INFO = {
    "hostname": "synthetic-zs2-test-host",
    "platform": "synthetic-test-os",
    "marker": "zs2-synthetic-system-info",
}

PROTECTED_SYSTEM_ROUTES = ("/system", "/api/v1/system")

# Route forms proving trailing slashes and query strings never bypass auth.
PROTECTED_ROUTE_VARIANTS = (
    "/system",
    "/system/",
    "/system?view=summary",
    "/system/?view=summary",
    "/api/v1/system",
    "/api/v1/system/",
    "/api/v1/system?view=summary",
    "/api/v1/system/?view=summary",
)

# Documented public aliases that must stay reachable without a key.
PUBLIC_ROUTE_VARIANTS = (
    "/health",
    "/health/",
    "/health?probe=1",
    "/api/v1/health",
    "/api/v1/health/",
    "/status",
    "/status/",
    "/status?probe=1",
    "/api/v1/status",
    "/api/v1/status/",
)


class _CapturedResponse:
    """A minimal, case-insensitive view over a captured HTTP response."""

    def __init__(self, status, header_pairs, body):
        self.status = status
        self.header_pairs = list(header_pairs)
        self.body = body

    def get_header(self, name):
        lowered = name.lower()
        for key, value in self.header_pairs:
            if key.lower() == lowered:
                return value
        return None

    def has_header(self, name):
        return self.get_header(name) is not None

    def json(self):
        return json.loads(self.body)


class ZeroSOCHandlerIntegrationTestCase(unittest.TestCase):
    """Shared loopback-server harness for real handler-boundary tests."""

    def setUp(self):
        # Defensive persistence isolation: point data/DB at a throwaway dir so
        # no request can touch the production database even incidentally.
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)

        original_data_dir = run.DATA_DIR
        original_db_file = run.DB_FILE
        run.DATA_DIR = self._temp_dir.name
        run.DB_FILE = str(Path(self._temp_dir.name) / "zs2-integration.db")

        def _restore_paths():
            run.DATA_DIR = original_data_dir
            run.DB_FILE = original_db_file

        self.addCleanup(_restore_paths)

        # Host isolation + reach marker.
        system_patcher = mock.patch.object(
            run, "get_system_info", return_value=dict(SYNTHETIC_SYSTEM_INFO)
        )
        self.mock_system_info = system_patcher.start()
        self.addCleanup(system_patcher.stop)

        # No production log file / DB writes for any request under test.
        log_patcher = mock.patch.object(run, "log_request")
        self.mock_log_request = log_patcher.start()
        self.addCleanup(log_patcher.stop)

        # Silence BaseHTTPRequestHandler's stderr logging without altering the
        # real request-handling behavior.
        message_patcher = mock.patch.object(
            run.ZeroSOCHandler, "log_message", lambda *args, **kwargs: None
        )
        message_patcher.start()
        self.addCleanup(message_patcher.stop)

        # Real handler, real socket, loopback only, ephemeral port.
        self.server = HTTPServer(("127.0.0.1", 0), run.ZeroSOCHandler)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.server_thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)

    def request(self, method, path, api_key=None, origin=None, extra_headers=None):
        """Issue a real request to the loopback handler and capture the reply."""
        headers = dict(extra_headers or {})
        if api_key is not None:
            headers[run.API_KEY_HEADER] = api_key
        if origin is not None:
            headers["Origin"] = origin

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, headers=headers)
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            return _CapturedResponse(response.status, response.getheaders(), body)
        finally:
            connection.close()

    # -- shared assertion helpers ----------------------------------------

    def assert_reached_system_handler(self, response):
        self.assertEqual(response.status, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["status_code"], 200)
        self.assertEqual(payload["data"], SYNTHETIC_SYSTEM_INFO)
        self.assertEqual(self.mock_system_info.call_count, 1)

    def assert_unauthorized_and_operation_skipped(self, response):
        self.assertEqual(response.status, 401)
        payload = response.json()
        self.assertFalse(payload["success"])
        self.assertEqual(payload["status_code"], 401)
        self.assertEqual(payload["error"]["message"], "Missing or invalid API key")
        # The protected operation must never have run.
        self.mock_system_info.assert_not_called()
        # The response must not disclose the configured key, echo the supplied
        # key, or leak environment/internal exception detail.
        self.assertNotIn(INTEGRATION_API_KEY, response.body)
        self.assertNotIn(INTEGRATION_WRONG_KEY, response.body)
        self.assertNotIn("ZEROSOC_API_KEY", response.body)
        self.assertNotIn("Traceback", response.body)

    def assert_no_cors_origin(self, response):
        self.assertIsNone(response.get_header("Access-Control-Allow-Origin"))

    def assert_cors_origin(self, response, origin):
        self.assertEqual(
            response.get_header("Access-Control-Allow-Origin"), origin
        )
        self.assertEqual(response.get_header("Vary"), "Origin")

    def assert_no_permissive_cors(self, response):
        origin_header = response.get_header("Access-Control-Allow-Origin")
        self.assertNotEqual(origin_header, "*")
        self.assertFalse(response.has_header("Access-Control-Allow-Credentials"))
        self.assertFalse(
            response.has_header("Access-Control-Allow-Private-Network")
        )


class ZeroSOCHandlerAuthIntegrationTests(ZeroSOCHandlerIntegrationTestCase):
    """API-key authentication enforced at the real request handler."""

    def test_missing_key_on_protected_route_is_unauthorized(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            for route in PROTECTED_SYSTEM_ROUTES:
                with self.subTest(route=route):
                    self.mock_system_info.reset_mock()
                    response = self.request("GET", route)
                    self.assert_unauthorized_and_operation_skipped(response)

    def test_incorrect_key_on_protected_route_is_unauthorized(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            for route in PROTECTED_SYSTEM_ROUTES:
                with self.subTest(route=route):
                    self.mock_system_info.reset_mock()
                    response = self.request(
                        "GET", route, api_key=INTEGRATION_WRONG_KEY
                    )
                    self.assert_unauthorized_and_operation_skipped(response)

    def test_correct_key_reaches_protected_system_handler(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            for route in PROTECTED_SYSTEM_ROUTES:
                with self.subTest(route=route):
                    self.mock_system_info.reset_mock()
                    response = self.request(
                        "GET", route, api_key=INTEGRATION_API_KEY
                    )
                    self.assert_reached_system_handler(response)

    def test_protected_route_matrix_normalization(self):
        """Trailing slashes and query strings never change the auth decision."""
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            for path in PROTECTED_ROUTE_VARIANTS:
                with self.subTest(path=path, case="missing-key"):
                    self.mock_system_info.reset_mock()
                    self.assert_unauthorized_and_operation_skipped(
                        self.request("GET", path)
                    )

                with self.subTest(path=path, case="incorrect-key"):
                    self.mock_system_info.reset_mock()
                    self.assert_unauthorized_and_operation_skipped(
                        self.request("GET", path, api_key=INTEGRATION_WRONG_KEY)
                    )

                with self.subTest(path=path, case="correct-key"):
                    self.mock_system_info.reset_mock()
                    self.assert_reached_system_handler(
                        self.request("GET", path, api_key=INTEGRATION_API_KEY)
                    )

    def test_fail_closed_when_server_key_unconfigured(self):
        """No configured server key => every request fails closed with 401."""
        with mock.patch.dict(os.environ, {}, clear=True):
            for route in PROTECTED_SYSTEM_ROUTES:
                with self.subTest(route=route):
                    self.mock_system_info.reset_mock()
                    # Even a plausible client key cannot authorize when the
                    # server has no key configured.
                    response = self.request(
                        "GET", route, api_key=INTEGRATION_API_KEY
                    )
                    self.assert_unauthorized_and_operation_skipped(response)

    def test_fail_closed_when_server_key_blank(self):
        """A whitespace-only server key is treated as unconfigured (401)."""
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": "   "}, clear=True
        ):
            for route in PROTECTED_SYSTEM_ROUTES:
                with self.subTest(route=route):
                    self.mock_system_info.reset_mock()
                    response = self.request(
                        "GET", route, api_key=INTEGRATION_API_KEY
                    )
                    self.assert_unauthorized_and_operation_skipped(response)

    def test_unauthorized_response_is_valid_json_and_leaks_nothing(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            response = self.request(
                "GET", "/api/v1/system", api_key=INTEGRATION_WRONG_KEY
            )
            self.assertEqual(response.status, 401)
            self.assertEqual(
                response.get_header("Content-Type"), "application/json"
            )
            # Valid JSON with the established contract, disclosing no secret.
            payload = response.json()
            self.assertEqual(
                payload["error"]["message"], "Missing or invalid API key"
            )
            self.assertIsNone(payload["data"])
            self.assertNotIn(INTEGRATION_API_KEY, response.body)
            self.assertNotIn(INTEGRATION_WRONG_KEY, response.body)

    def test_public_alias_routes_remain_public(self):
        """Documented health/status aliases stay reachable with no key."""
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            for path in PUBLIC_ROUTE_VARIANTS:
                with self.subTest(path=path):
                    response = self.request("GET", path)
                    self.assertEqual(
                        response.status, 200, msg=f"{path} should be public"
                    )
                    payload = response.json()
                    self.assertTrue(payload["success"])
                    self.assertEqual(payload["data"]["status"], "ok")

    def test_public_access_does_not_expand_to_protected_routes(self):
        """A missing key stays public for aliases yet protected for /system."""
        with mock.patch.dict(
            os.environ, {"ZEROSOC_API_KEY": INTEGRATION_API_KEY}, clear=True
        ):
            self.assertEqual(self.request("GET", "/health").status, 200)
            self.mock_system_info.reset_mock()
            self.assert_unauthorized_and_operation_skipped(
                self.request("GET", "/system")
            )


class ZeroSOCHandlerCorsIntegrationTests(ZeroSOCHandlerIntegrationTestCase):
    """CORS response behavior through the real ``end_headers`` path."""

    def _cors_env(self):
        return mock.patch.dict(
            os.environ,
            {
                "ZEROSOC_API_KEY": INTEGRATION_API_KEY,
                "ZEROSOC_ALLOWED_ORIGINS": ALLOWED_ORIGIN,
            },
            clear=True,
        )

    def test_allowed_origin_is_reflected_with_vary(self):
        with self._cors_env():
            response = self.request("GET", "/health", origin=ALLOWED_ORIGIN)
            self.assert_cors_origin(response, ALLOWED_ORIGIN)
            self.assert_no_permissive_cors(response)

    def test_disallowed_origin_is_not_reflected(self):
        with self._cors_env():
            response = self.request("GET", "/health", origin=DISALLOWED_ORIGIN)
            self.assert_no_cors_origin(response)
            self.assert_no_permissive_cors(response)

    def test_no_origin_header_receives_no_cors_grant(self):
        with self._cors_env():
            response = self.request("GET", "/health")
            self.assert_no_cors_origin(response)
            self.assert_no_permissive_cors(response)

    def test_lookalike_origins_are_rejected(self):
        lookalikes = (
            ALLOWED_ORIGIN + ".attacker.test",   # suffix expansion
            "https://x" + ALLOWED_ORIGIN[len("https://"):],  # prefix expansion
            ALLOWED_ORIGIN + "/",                 # trailing slash
            "http://allowed.zs2.test",            # scheme mismatch
            "null",                               # opaque origin
        )
        with self._cors_env():
            for origin in lookalikes:
                with self.subTest(origin=origin):
                    response = self.request("GET", "/health", origin=origin)
                    self.assert_no_cors_origin(response)
                    self.assert_no_permissive_cors(response)

    def test_credentials_and_private_network_are_never_granted(self):
        with self._cors_env():
            for origin in (ALLOWED_ORIGIN, DISALLOWED_ORIGIN, None):
                with self.subTest(origin=origin):
                    response = self.request("GET", "/health", origin=origin)
                    self.assert_no_permissive_cors(response)

    def test_auth_failure_is_not_more_permissive_than_success(self):
        with self._cors_env():
            success = self.request("GET", "/health", origin=ALLOWED_ORIGIN)
            self.mock_system_info.reset_mock()
            failure = self.request(
                "GET",
                "/api/v1/system",
                origin=ALLOWED_ORIGIN,
                api_key=INTEGRATION_WRONG_KEY,
            )
            self.assertEqual(failure.status, 401)
            self.mock_system_info.assert_not_called()
            # The 401 grants the same (allow-listed) origin and nothing more.
            self.assertEqual(
                failure.get_header("Access-Control-Allow-Origin"),
                success.get_header("Access-Control-Allow-Origin"),
            )
            self.assert_no_permissive_cors(failure)


class ZeroSOCHandlerOptionsIntegrationTests(ZeroSOCHandlerIntegrationTestCase):
    """OPTIONS / preflight behavior through the real handler."""

    def _cors_env(self):
        return mock.patch.dict(
            os.environ,
            {
                "ZEROSOC_API_KEY": INTEGRATION_API_KEY,
                "ZEROSOC_ALLOWED_ORIGINS": ALLOWED_ORIGIN,
            },
            clear=True,
        )

    def test_allowed_origin_preflight_returns_conservative_headers(self):
        with self._cors_env():
            response = self.request(
                "OPTIONS", "/api/v1/system", origin=ALLOWED_ORIGIN
            )
            self.assertEqual(response.status, 204)
            self.assert_cors_origin(response, ALLOWED_ORIGIN)
            self.assertEqual(
                response.get_header("Access-Control-Allow-Methods"),
                "GET, POST, OPTIONS",
            )
            self.assertEqual(
                response.get_header("Access-Control-Allow-Headers"),
                "Content-Type, X-API-Key",
            )
            self.assert_no_permissive_cors(response)
            # Preflight must never execute the protected operation or leak keys.
            self.mock_system_info.assert_not_called()
            self.assertNotIn(INTEGRATION_API_KEY, response.body)

    def test_disallowed_origin_preflight_is_not_reflected(self):
        with self._cors_env():
            response = self.request(
                "OPTIONS", "/api/v1/system", origin=DISALLOWED_ORIGIN
            )
            self.assertEqual(response.status, 204)
            self.assert_no_cors_origin(response)
            self.assert_no_permissive_cors(response)

    def test_no_origin_preflight_gains_no_allowance(self):
        with self._cors_env():
            response = self.request("OPTIONS", "/api/v1/system")
            self.assertEqual(response.status, 204)
            self.assert_no_cors_origin(response)
            self.assert_no_permissive_cors(response)

    def test_preflight_is_coherent_across_route_variants(self):
        variants = (
            "/api/v1/system",
            "/api/v1/system/",
            "/api/v1/system?view=summary",
        )
        with self._cors_env():
            for path in variants:
                with self.subTest(path=path):
                    allowed = self.request(
                        "OPTIONS", path, origin=ALLOWED_ORIGIN
                    )
                    self.assertEqual(allowed.status, 204)
                    self.assert_cors_origin(allowed, ALLOWED_ORIGIN)
                    self.assert_no_permissive_cors(allowed)
                    self.mock_system_info.assert_not_called()

                    denied = self.request(
                        "OPTIONS", path, origin=DISALLOWED_ORIGIN
                    )
                    self.assertEqual(denied.status, 204)
                    self.assert_no_cors_origin(denied)
                    self.assert_no_permissive_cors(denied)


# =========================================================================
# ZS-3: Request-size and general input-validation hardening
# =========================================================================
#
# These tests exercise the real ``run.ZeroSOCHandler`` POST path -- the central
# ``read_json_object_body`` validation boundary, ``do_POST`` dispatch, field
# validation, and the JSON error contract -- against a live loopback server.
#
# Boundary exercised: a real ``http.server.HTTPServer`` bound to ``127.0.0.1``
# on an ephemeral OS-assigned port (``0``), driven with ``http.client`` and, for
# framing cases ``http.client`` cannot represent (missing/blank/duplicate/negative
# Content-Length, bare Transfer-Encoding, truncated bodies), a small bounded raw
# loopback socket helper with a hard read timeout so nothing blocks indefinitely.
#
# Isolation:
#   * ``run.DATA_DIR``/``run.DB_FILE`` point at a throwaway temp dir and the
#     schema is created there, so real event writes go to a disposable database
#     and can be counted to prove invalid requests cause no side effects.
#   * ``run.log_request`` is patched out so no request touches the production
#     request log file or database.
#   * ``run.ZeroSOCHandler.log_message`` is silenced to keep stderr clean.
#   * The API key and request-size limit are set per test with
#     ``mock.patch.dict(..., clear=True)`` using unmistakably synthetic values,
#     so the developer's real key is never used and env state is always restored.
#
# No test opens an external connection, binds a LAN interface, scans a network,
# or contacts a webhook.

ZS3_API_KEY = "zs3-input-validation-test-key-not-a-real-secret"
ZS3_WRONG_KEY = "zs3-input-validation-wrong-key-also-not-real"
ZS3_ALLOWED_ORIGIN = "https://allowed.zs3.test"
ZS3_DISALLOWED_ORIGIN = "https://disallowed.zs3.test"


class ZeroSOCMaxRequestBytesConfigTests(unittest.TestCase):
    """Configuration boundary for ZEROSOC_MAX_REQUEST_BYTES."""

    def test_default_is_returned_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                run.get_max_request_bytes(), run.DEFAULT_MAX_REQUEST_BYTES
            )

    def test_valid_positive_integer_is_accepted(self):
        with mock.patch.dict(
            os.environ, {"ZEROSOC_MAX_REQUEST_BYTES": "1024"}, clear=True
        ):
            self.assertEqual(run.get_max_request_bytes(), 1024)

    def test_blank_value_falls_back_to_default(self):
        # Blank/whitespace is treated as unset -> default, matching the
        # established get_configured_* helper style.
        for blank in ("", "   ", "\t"):
            with self.subTest(value=blank):
                with mock.patch.dict(
                    os.environ, {"ZEROSOC_MAX_REQUEST_BYTES": blank}, clear=True
                ):
                    self.assertEqual(
                        run.get_max_request_bytes(), run.DEFAULT_MAX_REQUEST_BYTES
                    )

    def test_zero_negative_and_nonnumeric_are_rejected(self):
        for bad_value in ("0", "-1", "12.5", "abc", "0x10", "1_000"):
            with self.subTest(value=bad_value):
                with mock.patch.dict(
                    os.environ,
                    {"ZEROSOC_MAX_REQUEST_BYTES": bad_value},
                    clear=True,
                ):
                    with self.assertRaises(run.ConfigurationError):
                        run.get_max_request_bytes()

    def test_value_above_ceiling_is_rejected(self):
        over = str(run.MAX_REQUEST_BYTES_CEILING + 1)
        with mock.patch.dict(
            os.environ, {"ZEROSOC_MAX_REQUEST_BYTES": over}, clear=True
        ):
            with self.assertRaises(run.ConfigurationError):
                run.get_max_request_bytes()

    def test_config_error_does_not_leak_the_rejected_value(self):
        secret_like = "9999999999999"  # over ceiling, stands in for a bad value
        with mock.patch.dict(
            os.environ,
            {"ZEROSOC_MAX_REQUEST_BYTES": secret_like},
            clear=True,
        ):
            with self.assertRaises(run.ConfigurationError) as ctx:
                run.get_max_request_bytes()
        message = str(ctx.exception)
        self.assertIn("ZEROSOC_MAX_REQUEST_BYTES", message)
        self.assertNotIn(secret_like, message)


class ZeroSOCEventPayloadValidationUnitTests(unittest.TestCase):
    """Unit-level coverage of the POST /api/v1/events field validator."""

    def test_empty_object_fills_defaults(self):
        fields = run.validate_create_event_payload({})
        self.assertEqual(fields["event_type"], run.DEFAULT_EVENT_TYPE)
        self.assertEqual(fields["severity"], run.DEFAULT_EVENT_SEVERITY)
        self.assertEqual(fields["source"], run.DEFAULT_EVENT_SOURCE)
        self.assertEqual(fields["message"], run.DEFAULT_EVENT_MESSAGE)

    def test_valid_full_payload_is_cleaned(self):
        fields = run.validate_create_event_payload({
            "event_type": "  auth-failure  ",
            "severity": "HIGH",
            "source": " 10.0.0.5 ",
            "message": "  Repeated failed login  ",
            "unknown": "ignored",
        })
        self.assertEqual(fields["event_type"], "auth-failure")
        self.assertEqual(fields["severity"], "high")
        self.assertEqual(fields["source"], "10.0.0.5")
        self.assertEqual(fields["message"], "Repeated failed login")

    def test_null_fields_fall_back_to_defaults(self):
        fields = run.validate_create_event_payload({
            "event_type": None,
            "severity": None,
            "source": None,
            "message": None,
        })
        self.assertEqual(fields["event_type"], run.DEFAULT_EVENT_TYPE)
        self.assertEqual(fields["severity"], run.DEFAULT_EVENT_SEVERITY)

    def test_non_string_scalar_fields_are_rejected(self):
        for key, value in (
            ("event_type", 5),
            ("event_type", True),
            ("event_type", ["x"]),
            ("event_type", {"a": 1}),
            ("source", 10),
            ("message", 3.5),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(run.RequestValidationError) as ctx:
                    run.validate_create_event_payload({key: value})
                self.assertEqual(ctx.exception.status_code, 400)

    def test_blank_strings_are_rejected(self):
        for key in ("event_type", "source", "message"):
            with self.subTest(key=key):
                with self.assertRaises(run.RequestValidationError):
                    run.validate_create_event_payload({key: "   "})

    def test_severity_enum_is_enforced(self):
        for value in run.EVENT_SEVERITIES:
            with self.subTest(value=value):
                fields = run.validate_create_event_payload({"severity": value})
                self.assertEqual(fields["severity"], value)

        for bad in ("urgent", "SEV1", "informational", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(run.RequestValidationError):
                    run.validate_create_event_payload({"severity": bad})

    def test_length_bounds_are_enforced(self):
        cases = (
            ("event_type", run.MAX_EVENT_TYPE_LENGTH),
            ("source", run.MAX_EVENT_SOURCE_LENGTH),
            ("message", run.MAX_EVENT_MESSAGE_LENGTH),
        )
        for key, max_len in cases:
            with self.subTest(key=key, boundary="at-max"):
                fields = run.validate_create_event_payload({key: "a" * max_len})
                self.assertEqual(fields[key], "a" * max_len)

            with self.subTest(key=key, boundary="over-max"):
                with self.assertRaises(run.RequestValidationError):
                    run.validate_create_event_payload({key: "a" * (max_len + 1)})

    def test_non_object_root_is_rejected(self):
        for root in ([], "x", 5, True, None):
            with self.subTest(root=root):
                with self.assertRaises(run.RequestValidationError):
                    run.validate_create_event_payload(root)


class ZeroSOCPostIntegrationTestCase(unittest.TestCase):
    """Shared loopback-server harness for POST body-validation tests."""

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)

        original_data_dir = run.DATA_DIR
        original_db_file = run.DB_FILE
        run.DATA_DIR = self._temp_dir.name
        run.DB_FILE = str(Path(self._temp_dir.name) / "zs3-integration.db")
        run.init_database()

        def _restore_paths():
            run.DATA_DIR = original_data_dir
            run.DB_FILE = original_db_file

        self.addCleanup(_restore_paths)

        # No production log file / DB writes for the request log.
        log_patcher = mock.patch.object(run, "log_request")
        self.mock_log_request = log_patcher.start()
        self.addCleanup(log_patcher.stop)

        message_patcher = mock.patch.object(
            run.ZeroSOCHandler, "log_message", lambda *args, **kwargs: None
        )
        message_patcher.start()
        self.addCleanup(message_patcher.stop)

        self.server = HTTPServer(("127.0.0.1", 0), run.ZeroSOCHandler)
        self.port = self.server.server_address[1]
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self.server_thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)

    # -- request helpers -------------------------------------------------

    def post(
        self,
        path,
        body,
        api_key=ZS3_API_KEY,
        content_type="application/json",
        origin=None,
        extra_headers=None,
    ):
        """Issue a real POST via http.client (sets Content-Length for us)."""
        headers = dict(extra_headers or {})
        if api_key is not None:
            headers[run.API_KEY_HEADER] = api_key
        if content_type is not None:
            headers["Content-Type"] = content_type
        if origin is not None:
            headers["Origin"] = origin

        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read().decode("utf-8")
            return _CapturedResponse(
                response.status, response.getheaders(), response_body
            )
        finally:
            connection.close()

    def raw_exchange(self, request_bytes, send_body=b"", read_timeout=5):
        """
        Send a hand-crafted request over a raw loopback socket for framing cases
        http.client cannot express, then read the full reply until the server
        closes the connection. The write side is shut down after sending so a
        deliberately short body cannot make the handler block.

        Returns (status_code, raw_reply_bytes, server_closed_connection).
        """
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=read_timeout)
        try:
            sock.sendall(request_bytes + send_body)
            sock.shutdown(socket.SHUT_WR)

            chunks = []
            server_closed = False
            while True:
                data = sock.recv(4096)
                if not data:
                    server_closed = True
                    break
                chunks.append(data)

            raw = b"".join(chunks)
            status = None
            if raw.startswith(b"HTTP/"):
                try:
                    status = int(raw.split(b"\r\n", 1)[0].split(b" ")[1])
                except (IndexError, ValueError):
                    status = None
            return status, raw, server_closed
        finally:
            sock.close()

    def build_raw_request(self, headers_lines, api_key=ZS3_API_KEY):
        """
        Build request-line + headers (no body) ending with a blank line.

        A valid API key is included by default so framing tests reach the body
        validation boundary rather than stopping at the auth gate; pass
        api_key=None to omit it.
        """
        lines = ["POST /api/v1/events HTTP/1.1", f"Host: 127.0.0.1:{self.port}"]
        if api_key is not None:
            lines.append(f"{run.API_KEY_HEADER}: {api_key}")
        lines.extend(headers_lines)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    # -- assertion / data helpers ----------------------------------------

    def count_events(self):
        conn = run.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS total FROM security_events")
            return cursor.fetchone()["total"]
        finally:
            conn.close()

    def make_event_body(self, target_length):
        """A valid event JSON object padded to exactly target_length bytes."""
        prefix = b'{"event_type":"manual","pad":"'
        suffix = b'"}'
        pad = target_length - len(prefix) - len(suffix)
        self.assertGreaterEqual(pad, 0, "target_length too small for a valid body")
        return prefix + (b"a" * pad) + suffix

    def assert_clean_error(self, response, *forbidden):
        """A validation error must be valid JSON and leak no internals."""
        payload = response.json()
        self.assertFalse(payload["success"])
        self.assertEqual(
            response.get_header("Content-Type"), "application/json"
        )
        self.assertIsNone(payload["data"])
        self.assertIsInstance(payload["error"]["message"], str)
        for token in ("Traceback", "JSONDecodeError", "File \"", "line ",
                      "ZEROSOC_API_KEY", ZS3_API_KEY, ZS3_WRONG_KEY):
            self.assertNotIn(token, response.body)
        for token in forbidden:
            self.assertNotIn(token, response.body)

    def _env(self, **overrides):
        env = {"ZEROSOC_API_KEY": ZS3_API_KEY}
        env.update(overrides)
        return mock.patch.dict(os.environ, env, clear=True)


class ZeroSOCRequestSizeTests(ZeroSOCPostIntegrationTestCase):
    """Request-body size limiting via ZEROSOC_MAX_REQUEST_BYTES."""

    def test_body_exactly_at_maximum_passes_size_gate(self):
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="512"):
            response = self.post("/api/v1/events", self.make_event_body(512))
            self.assertEqual(response.status, 201)
            self.assertEqual(self.count_events(), 1)

    def test_body_one_byte_over_maximum_returns_413(self):
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="512"):
            response = self.post("/api/v1/events", self.make_event_body(513))
            self.assertEqual(response.status, 413)
            self.assert_clean_error(response)
            # 413 must not run the protected operation.
            self.assertEqual(self.count_events(), 0)

    def test_large_declared_content_length_is_rejected_without_reading(self):
        # Declare a body far larger than the limit but send almost nothing.
        # The handler must reject on the declared size alone, promptly, without
        # attempting to buffer the declared payload (guarded by read_timeout).
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="512"):
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: 50000000",
            ])
            status, raw, server_closed = self.raw_exchange(request, send_body=b"{}")
            self.assertEqual(status, 413)
            self.assertTrue(server_closed)
            self.assertEqual(self.count_events(), 0)

    def test_oversized_rejection_is_valid_json_without_body_echo(self):
        secret_marker = "supersecret-marker-value-in-body"
        body = self.make_event_body(2000)
        # Embed a marker we can prove is never reflected back.
        body = body[:-2] + f',"leak":"{secret_marker}"'.encode() + body[-2:]
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="512"):
            response = self.post("/api/v1/events", body)
            self.assertEqual(response.status, 413)
            self.assert_clean_error(response, secret_marker)

    def test_invalid_configured_maximum_returns_generic_500(self):
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="not-a-number"):
            response = self.post("/api/v1/events", b'{"event_type":"manual"}')
            self.assertEqual(response.status, 500)
            self.assertEqual(
                response.json()["error"]["message"], "Server configuration error"
            )
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)


class ZeroSOCRequestFramingTests(ZeroSOCPostIntegrationTestCase):
    """Content-Length / Transfer-Encoding framing hardening (raw sockets)."""

    def test_missing_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request(["Content-Type: application/json"])
            status, _, closed = self.raw_exchange(request, send_body=b'{"a":1}')
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            self.assertEqual(self.count_events(), 0)

    def test_blank_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length:",
            ])
            status, _, closed = self.raw_exchange(request)
            self.assertEqual(status, 400)
            self.assertTrue(closed)

    def test_non_integer_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: twelve",
            ])
            status, _, closed = self.raw_exchange(request, send_body=b'{}')
            self.assertEqual(status, 400)
            self.assertTrue(closed)

    def test_negative_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: -5",
            ])
            status, _, closed = self.raw_exchange(request, send_body=b'{}')
            self.assertEqual(status, 400)
            self.assertTrue(closed)

    def test_duplicate_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: 2",
                "Content-Length: 2",
            ])
            status, _, closed = self.raw_exchange(request, send_body=b'{}')
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            self.assertEqual(self.count_events(), 0)

    def test_transfer_encoding_chunked_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Transfer-Encoding: chunked",
            ])
            status, _, closed = self.raw_exchange(request, send_body=b"0\r\n\r\n")
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            self.assertEqual(self.count_events(), 0)

    def test_transfer_encoding_with_content_length_is_rejected(self):
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Transfer-Encoding: chunked",
                "Content-Length: 2",
            ])
            status, _, closed = self.raw_exchange(request, send_body=b'{}')
            self.assertEqual(status, 400)
            self.assertTrue(closed)

    def test_zero_length_body_is_rejected_as_empty(self):
        with self._env():
            response = self.post("/api/v1/events", b"")
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_truncated_body_does_not_hang_and_is_rejected(self):
        # Declare more bytes than we send, then close the write side. The
        # bounded read returns the partial body (it must not block) and the
        # partial JSON is rejected as malformed.
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: 40",
            ])
            status, _, closed = self.raw_exchange(
                request, send_body=b'{"event_type":"man'
            )
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            self.assertEqual(self.count_events(), 0)

    def test_truncated_valid_json_is_rejected_without_side_effects(self):
        # A short read must be rejected even when the received prefix happens
        # to be independently valid JSON; declared framing is authoritative.
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: 10",
            ])
            status, raw, closed = self.raw_exchange(request, send_body=b"{}")
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            self.assertIn(b'"message": "Request body is incomplete"', raw)
            self.assertEqual(self.count_events(), 0)

    def test_rejected_request_closes_connection_and_is_not_reinterpreted(self):
        # A framing rejection must close the connection so trailing bytes are
        # never misread as a second request. We pipeline a valid-looking second
        # request line; the server must answer only the first and then close.
        with self._env():
            request = self.build_raw_request([
                "Content-Type: application/json",
                "Content-Length: -1",
            ])
            trailing = b"GET /api/v1/health HTTP/1.1\r\nHost: x\r\n\r\n"
            status, raw, closed = self.raw_exchange(request, send_body=trailing)
            self.assertEqual(status, 400)
            self.assertTrue(closed)
            # Exactly one HTTP response status line was produced -- the pipelined
            # second request was never served on the (now closed) connection.
            # (Counting "HTTP/1.0 " avoids matching the "BaseHTTP/" Server header.)
            self.assertEqual(raw.count(b"HTTP/1.0 "), 1)
            self.assertNotIn(b'"status_code": 200', raw)


class ZeroSOCContentTypeAndJsonTests(ZeroSOCPostIntegrationTestCase):
    """Content-Type and JSON syntax / root-shape hardening."""

    def test_valid_application_json_is_accepted(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"event_type":"manual","severity":"low"}'
            )
            self.assertEqual(response.status, 201)
            self.assertEqual(self.count_events(), 1)

    def test_json_with_charset_parameter_is_accepted(self):
        with self._env():
            response = self.post(
                "/api/v1/events",
                b'{"event_type":"manual"}',
                content_type="application/json; charset=utf-8",
            )
            self.assertEqual(response.status, 201)

    def test_missing_content_type_is_rejected(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"event_type":"manual"}', content_type=None
            )
            self.assertEqual(response.status, 415)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_wrong_media_type_returns_415(self):
        for ctype in ("text/plain", "application/x-www-form-urlencoded",
                      "multipart/form-data", "application/xml"):
            with self.subTest(content_type=ctype), self._env():
                response = self.post(
                    "/api/v1/events", b'{"event_type":"manual"}',
                    content_type=ctype,
                )
                self.assertEqual(response.status, 415)
                self.assertEqual(self.count_events(), 0)

    def test_malformed_json_returns_400(self):
        with self._env():
            response = self.post("/api/v1/events", b'{"event_type": ')
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_trailing_garbage_after_json_is_rejected(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"event_type":"manual"} trailing'
            )
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_invalid_utf8_body_returns_safe_client_error(self):
        with self._env():
            response = self.post("/api/v1/events", b"\xff\xfe\xfa")
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_whitespace_only_body_is_rejected(self):
        with self._env():
            response = self.post("/api/v1/events", b"    \n\t  ")
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_non_object_json_roots_are_rejected(self):
        for root in (b"[1,2,3]", b'"a string"', b"42", b"true", b"null"):
            with self.subTest(root=root), self._env():
                response = self.post("/api/v1/events", root)
                self.assertEqual(response.status, 400)
                self.assert_clean_error(response)
                self.assertEqual(self.count_events(), 0)


class ZeroSOCEventFieldValidationHandlerTests(ZeroSOCPostIntegrationTestCase):
    """POST /api/v1/events field validation at the real handler."""

    def test_empty_object_creates_event_with_defaults(self):
        with self._env():
            response = self.post("/api/v1/events", b"{}")
            self.assertEqual(response.status, 201)
            event = response.json()["data"]["event"]
            self.assertEqual(event["event_type"], run.DEFAULT_EVENT_TYPE)
            self.assertEqual(event["severity"], run.DEFAULT_EVENT_SEVERITY)
            self.assertEqual(self.count_events(), 1)

    def test_valid_full_event_is_created(self):
        with self._env():
            body = json.dumps({
                "event_type": "auth-failure",
                "severity": "high",
                "source": "10.0.0.5",
                "message": "Repeated failed login from test",
            }).encode()
            response = self.post("/api/v1/events", body)
            self.assertEqual(response.status, 201)
            event = response.json()["data"]["event"]
            self.assertEqual(event["event_type"], "auth-failure")
            self.assertEqual(event["severity"], "high")
            self.assertEqual(self.count_events(), 1)

    def test_invalid_severity_is_rejected(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"severity":"urgent"}'
            )
            self.assertEqual(response.status, 400)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_each_valid_severity_is_accepted(self):
        for severity in ("critical", "high", "medium", "low"):
            with self.subTest(severity=severity), self._env():
                response = self.post(
                    "/api/v1/events",
                    json.dumps({"severity": severity}).encode(),
                )
                self.assertEqual(response.status, 201)

    def test_wrong_field_types_are_rejected(self):
        for body in (b'{"event_type": 5}', b'{"event_type": true}',
                     b'{"source": ["x"]}', b'{"message": {"a": 1}}'):
            with self.subTest(body=body), self._env():
                response = self.post("/api/v1/events", body)
                self.assertEqual(response.status, 400)
                self.assertEqual(self.count_events(), 0)

    def test_blank_required_string_is_rejected(self):
        with self._env():
            response = self.post("/api/v1/events", b'{"event_type":"   "}')
            self.assertEqual(response.status, 400)
            self.assertEqual(self.count_events(), 0)

    def test_event_type_length_boundary(self):
        with self._env():
            at_max = json.dumps(
                {"event_type": "a" * run.MAX_EVENT_TYPE_LENGTH}
            ).encode()
            self.assertEqual(self.post("/api/v1/events", at_max).status, 201)

        with self._env():
            over_max = json.dumps(
                {"event_type": "a" * (run.MAX_EVENT_TYPE_LENGTH + 1)}
            ).encode()
            response = self.post("/api/v1/events", over_max)
            self.assertEqual(response.status, 400)

    def test_unknown_fields_are_ignored(self):
        with self._env():
            response = self.post(
                "/api/v1/events",
                b'{"event_type":"manual","totally_unknown":"whatever"}',
            )
            self.assertEqual(response.status, 201)
            self.assertEqual(self.count_events(), 1)

    def test_null_field_falls_back_to_default(self):
        with self._env():
            response = self.post("/api/v1/events", b'{"event_type": null}')
            self.assertEqual(response.status, 201)
            event = response.json()["data"]["event"]
            self.assertEqual(event["event_type"], run.DEFAULT_EVENT_TYPE)


class ZeroSOCSharedBoundaryTests(ZeroSOCPostIntegrationTestCase):
    """The validation boundary applies to every JSON-writing POST route."""

    def test_notifications_endpoint_shares_the_boundary(self):
        with self._env():
            # Valid object -> reaches the handler (no unresolved alerts -> 200).
            ok = self.post("/api/v1/alerts/notifications", b'{"channel":"local"}')
            self.assertEqual(ok.status, 200)

            # Array root rejected by the shared boundary.
            bad_root = self.post("/api/v1/alerts/notifications", b"[1,2]")
            self.assertEqual(bad_root.status, 400)

            # Wrong media type rejected by the shared boundary.
            bad_ctype = self.post(
                "/api/v1/alerts/notifications", b"{}", content_type="text/plain"
            )
            self.assertEqual(bad_ctype.status, 415)

    def test_unknown_post_route_still_validates_body_then_404s(self):
        with self._env():
            response = self.post("/api/v1/does-not-exist", b"{}")
            self.assertEqual(response.status, 404)
            # A malformed body on an unknown route is still a 400 (boundary runs
            # before route dispatch for all POSTs).
            malformed = self.post("/api/v1/does-not-exist", b"{bad")
            self.assertEqual(malformed.status, 400)


class ZeroSOCPostAuthOrderingTests(ZeroSOCPostIntegrationTestCase):
    """Authentication runs before body validation on protected POST routes."""

    def test_missing_key_is_unauthorized_without_creating_event(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"event_type":"manual"}', api_key=None
            )
            self.assertEqual(response.status, 401)
            self.assertEqual(
                response.json()["error"]["message"], "Missing or invalid API key"
            )
            self.assertEqual(self.count_events(), 0)

    def test_wrong_key_is_unauthorized_and_generic(self):
        with self._env():
            response = self.post(
                "/api/v1/events", b'{"event_type":"manual"}',
                api_key=ZS3_WRONG_KEY,
            )
            self.assertEqual(response.status, 401)
            self.assert_clean_error(response)
            self.assertEqual(self.count_events(), 0)

    def test_unauthorized_oversized_body_is_not_read_or_processed(self):
        # Auth precedes body validation: a wrong key with a huge declared body
        # must fail closed with 401, never buffering the body, never writing.
        with self._env(ZEROSOC_MAX_REQUEST_BYTES="512"):
            request = (
                "POST /api/v1/events HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"{run.API_KEY_HEADER}: {ZS3_WRONG_KEY}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 50000000\r\n\r\n"
            ).encode("ascii")
            status, _, _ = self.raw_exchange(request, send_body=b"{}")
            self.assertEqual(status, 401)
            self.assertEqual(self.count_events(), 0)

    def test_valid_key_reaches_handler(self):
        with self._env():
            response = self.post("/api/v1/events", b'{"event_type":"manual"}')
            self.assertEqual(response.status, 201)
            self.assertEqual(self.count_events(), 1)


class ZeroSOCValidationCorsRegressionTests(ZeroSOCPostIntegrationTestCase):
    """Validation errors preserve exact-match CORS and never widen it."""

    def _cors_env(self, **overrides):
        env = {
            "ZEROSOC_API_KEY": ZS3_API_KEY,
            "ZEROSOC_ALLOWED_ORIGINS": ZS3_ALLOWED_ORIGIN,
        }
        env.update(overrides)
        return mock.patch.dict(os.environ, env, clear=True)

    def test_validation_error_reflects_only_allowlisted_origin(self):
        with self._cors_env():
            response = self.post(
                "/api/v1/events", b"[1,2,3]", origin=ZS3_ALLOWED_ORIGIN
            )
            self.assertEqual(response.status, 400)
            self.assertEqual(
                response.get_header("Access-Control-Allow-Origin"),
                ZS3_ALLOWED_ORIGIN,
            )
            self.assertEqual(response.get_header("Vary"), "Origin")
            self.assertNotEqual(
                response.get_header("Access-Control-Allow-Origin"), "*"
            )
            self.assertFalse(
                response.has_header("Access-Control-Allow-Private-Network")
            )
            self.assertFalse(
                response.has_header("Access-Control-Allow-Credentials")
            )

    def test_validation_error_grants_no_cors_to_disallowed_origin(self):
        with self._cors_env():
            response = self.post(
                "/api/v1/events", b"[1,2,3]", origin=ZS3_DISALLOWED_ORIGIN
            )
            self.assertEqual(response.status, 400)
            self.assertIsNone(
                response.get_header("Access-Control-Allow-Origin")
            )
            self.assertFalse(
                response.has_header("Access-Control-Allow-Private-Network")
            )

    def test_error_is_not_more_permissive_than_success(self):
        with self._cors_env():
            success = self.post(
                "/api/v1/events", b'{"event_type":"manual"}',
                origin=ZS3_ALLOWED_ORIGIN,
            )
            failure = self.post(
                "/api/v1/events", b"[1,2,3]", origin=ZS3_ALLOWED_ORIGIN
            )
            self.assertEqual(success.status, 201)
            self.assertEqual(failure.status, 400)
            self.assertEqual(
                failure.get_header("Access-Control-Allow-Origin"),
                success.get_header("Access-Control-Allow-Origin"),
            )


if __name__ == "__main__":
    unittest.main()
