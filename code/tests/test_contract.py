from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.identity import RESOURCE, normalize
from ghost_audit.models import AuditResult, Observation, Request, Subject
from ghost_audit.planner import plan
from ghost_audit.policy import Policy
from ghost_audit.output import read_output, write_output
from ghost_audit.parsers import log_attributes, parse_log, sql_connection

TIME = "2026-04-02T12:00:00Z"


def request() -> Request:
    return Request(case_id="custom_101", email="alex@example.test", requested_at="2026-04-01T12:00:00Z",
                   reported_status="COMPLETE", reported_at="2026-04-02T11:00:00Z", audit_at=TIME,
                   request_text="Please delete my account permanently.")


def subject() -> Subject:
    return Subject(user_id="user_101", identifiers=["user_101", "alex@example.test"], names=["Alex Example"], audit_ids=[])


def observation(resource: str = "account_101", category: str = "USER_PROFILE", state: str = "PRESENT",
                replica: str = "", fields: dict | None = None, **kwargs) -> Observation:
    return Observation(observation_id=f"observation-{resource}-{replica}", evidence_id="evidence_custom",
                       locator="fixture:1", system_id={"DATA_FLOW": "integration_service", "BACKUP_ARCHIVE": "backup_service",
                       "ACCOUNT_TOMBSTONE": "identity_service", "ANALYTICS_PROFILE": "analytics_platform",
                       "SECURITY_AUDIT_LOG": "security_service"}.get(category, "account_service"),
                       resource_id=resource, category=category, observed_at=TIME, captured_at=TIME,
                       state=state, replica=replica, identifiers=["user_101"], fields=fields or {}, **kwargs)


def policy() -> Policy:
    return Policy([{"rule_id": "custom_rule", "data_category": category, "condition": "Always", "required_action": action}
                   for category, action in {"USER_PROFILE": "DELETE", "ACCOUNT_TOMBSTONE": "REDACT",
                                            "ANALYTICS_PROFILE": "ANONYMIZE", "SECURITY_AUDIT_LOG": "RETAIN",
                                            "SUPPORT_MESSAGE": "REDACT"}.items()])


class PolicyScenarios(unittest.TestCase):
    def test_surviving_replica_blocks_completion(self):
        primary = observation(state="ABSENT", replica="primary")
        replica = observation(replica="regional", fields={"email": "alex@example.test"})
        states, unresolved = policy().reconstruct([primary, replica], request(), subject())
        result = plan(request(), states)
        self.assertFalse(unresolved)
        self.assertEqual(result.deletion_status.value, "INCOMPLETE")
        self.assertEqual(result.steps[0].operation, "REPORT_REMAINING_RECORD")
        self.assertEqual(result.steps[0].evidence_id, replica.evidence_id)

    def test_generic_primary_read_does_not_erase_a_replica(self):
        replica = observation(replica="regional", fields={"email": "alex@example.test"})
        replica.observed_at = "2026-04-02T10:00:00Z"
        states, _ = policy().reconstruct([replica, observation(state="ABSENT")], request(), subject())
        self.assertFalse(states[0].compliant)

    def test_tombstone_keeps_only_stable_reference(self):
        tombstone = observation("tombstone_101", "ACCOUNT_TOMBSTONE", fields={
            "subject_reference": "user_101", "name": None, "email": None, "phone": None, "email_hash": None})
        states, _ = policy().reconstruct([tombstone], request(), subject())
        self.assertTrue(states[0].compliant)
        self.assertEqual(plan(request(), states).steps[0].operation, "VERIFY_RECORD_REDACTED")

    def test_exposed_tombstone_is_redacted_not_deleted(self):
        tombstone = observation("tombstone_101", "ACCOUNT_TOMBSTONE", fields={"subject_reference": "user_101", "email_hash": "a" * 64})
        states, _ = policy().reconstruct([tombstone], request(), subject())
        operations = [s.operation for s in plan(request(), states).steps]
        self.assertIn("REDACT_RECORD", operations)
        self.assertNotIn("DELETE_RECORD", operations)

    def test_anonymization_removes_stable_subject_link(self):
        analytics = observation("analytics_101", "ANALYTICS_PROFILE", fields={"email": None, "customer_reference": "user_101"})
        states, _ = policy().reconstruct([analytics], request(), subject())
        self.assertFalse(states[0].compliant)
        self.assertEqual(plan(request(), states).steps[1].operation, "ANONYMIZE_RECORD")

    def test_anonymized_analytics_record_can_remain(self):
        analytics = observation("analytics_101", "ANALYTICS_PROFILE", fields={"email": None, "customer_reference": None})
        states, _ = policy().reconstruct([analytics], request(), subject())
        self.assertTrue(states[0].compliant)

    def test_security_retention_is_not_pii_violation(self):
        audit = observation("audit_record_101", "SECURITY_AUDIT_LOG", fields={"email": "alex@example.test", "retention_until": "2030-01-01T00:00:00Z"})
        states, _ = policy().reconstruct([audit], request(), subject())
        result = plan(request(), states)
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertEqual(result.steps[0].operation, "VERIFY_RECORD_PRESENT")

    def test_retained_record_need_not_exist_in_every_replica(self):
        absent = observation("audit_record_101", "SECURITY_AUDIT_LOG", state="ABSENT", replica="regional")
        present = observation("audit_record_101", "SECURITY_AUDIT_LOG", replica="primary")
        states, _ = policy().reconstruct([absent, present], request(), subject())
        self.assertTrue(states[0].compliant)

    def test_missing_retained_record_has_no_invented_operation(self):
        missing = observation("audit_record_101", "SECURITY_AUDIT_LOG", state="ABSENT")
        states, _ = policy().reconstruct([missing], request(), subject())
        with self.assertRaisesRegex(ValueError, "No permitted remediation"):
            plan(request(), states)

    def test_flows_and_restores_are_stopped_before_records(self):
        facts = [observation(), observation("data_flow_101", "DATA_FLOW", state="ACTIVE"),
                 observation("backup_101", "BACKUP_ARCHIVE", state="ACTIVE")]
        states, _ = policy().reconstruct(facts, request(), subject())
        result = plan(request(), states)
        remediation = [s for s in result.steps if s.phase == "REMEDIATION"]
        self.assertEqual([s.operation for s in remediation], ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"])
        self.assertTrue(all(s.evidence_id == "" for s in result.steps if s.phase != "FINDING"))

    def test_late_capture_of_early_observation_is_never_cited(self):
        late = observation(state="ABSENT")
        late.observed_at = "2026-04-02T11:30:00Z"
        late.captured_at = "2026-04-03T00:00:00Z"
        self.assertTrue(late.eligible(TIME))
        self.assertFalse(late.citable(TIME))
        states, _ = policy().reconstruct([late], request(), subject())
        self.assertFalse(states[0].citation)

    def test_observation_after_cutoff_never_changes_the_state(self):
        after = observation(state="ABSENT")
        after.observed_at = "2026-04-02T12:30:00Z"
        after.captured_at = "2026-04-02T12:30:00Z"
        states, _ = policy().reconstruct([observation(fields={"email": "alex@example.test"}), after], request(), subject())
        self.assertFalse(states[0].compliant)

    def test_non_deletion_has_no_actions(self):
        result = plan(request(), [], non_deletion=True)
        self.assertEqual(result.deletion_status.value, "NOT_APPLICABLE")
        self.assertEqual(result.steps, [])

    def test_missing_redaction_record_is_not_reported_as_exposed_pii(self):
        missing = observation("tombstone_101", "ACCOUNT_TOMBSTONE", state="ABSENT")
        states, unresolved = policy().reconstruct([missing], request(), subject())
        self.assertTrue(unresolved)
        with self.assertRaisesRegex(ValueError, "missing"):
            plan(request(), states)

    def test_absent_flow_cannot_copy_data(self):
        flow = observation("data_flow_101", "DATA_FLOW", state="ABSENT")
        states, _ = policy().reconstruct([flow], request(), subject())
        self.assertTrue(states[0].compliant)

    def test_redacted_label_does_not_override_visible_email(self):
        tombstone = observation("tombstone_101", "ACCOUNT_TOMBSTONE", state="REDACTED",
                                fields={"email": "alex@example.test"}, explicit_state=True)
        states, _ = policy().reconstruct([tombstone], request(), subject())
        self.assertFalse(states[0].compliant)

    def test_other_customers_pii_in_shared_message_is_preserved(self):
        shared = observation("support_101", "SUPPORT_MESSAGE", fields={
            "subject_reference": "user_101", "requester_email": "other@example.test",
            "message_text": "The other customer requested updates at other@example.test."})
        states, _ = policy().reconstruct([shared], request(), subject())
        self.assertTrue(states[0].compliant)


class ParserScenarios(unittest.TestCase):
    def test_resource_extraction_does_not_match_service_names(self):
        self.assertEqual(RESOURCE.findall("account_service read account_101 via analytics_platform"), ["account_101"])

    def test_email_normalization_preserves_distinct_addresses(self):
        self.assertEqual(normalize(" Alex+old@Example.TEST "), "alex+old@example.test")
        self.assertNotEqual(normalize("a.lex@example.test"), normalize("alex@example.test"))

    def test_cloud_nested_message_is_decoded(self):
        line = TIME + ' requestId=t-101 function=account_service message=' + json.dumps('event="profile_lookup_completed" resource_id="account_101" rows="1"')
        attributes = log_attributes(line)
        self.assertEqual(attributes["resource_id"], "account_101")
        self.assertEqual(attributes["event"], "profile_lookup_completed")

    def test_cache_miss_does_not_override_successful_read(self):
        lines = [f'{TIME} service=security_service trace_id=t1 event=audit_record_read_started subject_ref=user_101',
                 f'{TIME} service=security_service trace_id=t1 event=cache_lookup result=miss',
                 f'{TIME} service=security_service trace_id=t1 event=audit_record_read_completed resource_id=audit_record_101 rows=1']
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "fixture.log"
            path.write_text("\n".join(lines), encoding="utf-8")
            parsed = parse_log(path, {"file_id": "evidence_custom", "captured_at": TIME, "origin": "security_service"})
        self.assertEqual(len(parsed.observations), 1)
        self.assertEqual(parsed.observations[0].state, "PRESENT")
        self.assertEqual(parsed.observations[0].identifiers, ["user_101"])

    def test_interleaved_traces_keep_ownership_separate(self):
        lines = [f'{TIME} service=account_service trace_id=t1 event=profile_lookup_started lookup_key=alex@example.test',
                 f'{TIME} service=account_service trace_id=t2 event=profile_lookup_started lookup_key=other@example.test',
                 f'{TIME} service=account_service trace_id=t1 event=profile_lookup_completed resource_id=account_101 rows=0 http_status=404',
                 f'{TIME} service=account_service trace_id=t2 event=profile_lookup_completed resource_id=account_202 rows=1']
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "fixture.log"
            path.write_text("\n".join(lines), encoding="utf-8")
            parsed = parse_log(path, {"file_id": "evidence_custom", "captured_at": TIME, "origin": "account_service"})
        self.assertEqual(parsed.observations[0].identifiers, ["alex@example.test"])
        self.assertEqual(parsed.observations[1].identifiers, ["other@example.test"])

    def test_legacy_contact_index_requires_delete(self):
        lines = [f'{TIME} service=support_replica trace_id=t1 event=contact_query_started lookup_key=alex@example.test',
                 f'{TIME} service=support_replica trace_id=t1 event=contact_query_completed resource_id=support_101 rows=1']
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "fixture.log"
            path.write_text("\n".join(lines), encoding="utf-8")
            parsed = parse_log(path, {"file_id": "evidence_custom", "captured_at": TIME, "origin": "support_platform"})
        self.assertEqual(parsed.observations[0].category, "SECONDARY_IDENTIFIER")
        self.assertEqual(parsed.observations[0].system_id, "support_platform")
        self.assertEqual(parsed.observations[0].replica, "support_replica")

    def test_pipe_delimited_log_lines_are_parsed(self):
        line = TIME + ' | INFO | account_service | tr-1 | profile_lookup_completed | resource_id="account_101" rows="0" http_status="404"'
        attributes = log_attributes(line)
        self.assertEqual((attributes["service"], attributes["trace_id"], attributes["event"]),
                         ("account_service", "tr-1", "profile_lookup_completed"))
        self.assertEqual(attributes["resource_id"], "account_101")

    def parse(self, lines, origin="account_service"):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "fixture.log"
            path.write_text(chr(10).join(lines), encoding="utf-8")
            return parse_log(path, {"file_id": "evidence_custom", "captured_at": TIME, "origin": origin})

    def test_record_lookup_uses_its_explicit_result_and_declared_system(self):
        parsed = self.parse([
            f'{TIME} INFO service=search_index_service event=record_lookup seq=1 system="account_service" '
            'resource_id="account_101" record_type="USER_PROFILE" result="NOT_FOUND" subject_reference="alex@example.test"'])
        found = parsed.observations[0]
        self.assertEqual((found.system_id, found.category, found.state), ("account_service", "USER_PROFILE", "ABSENT"))
        self.assertEqual(found.identifiers, ["alex@example.test"])

    def test_restore_authorization_and_download_checks_map_to_states(self):
        parsed = self.parse([
            f'{TIME} level=INFO service=backup_service trace_id=t1 event=restore_authorization_completed resource_id=backup_101 decision=deny',
            f'{TIME} level=INFO service=export_service trace_id=t2 event=export_download_check_completed resource_id=export_101 available=true'])
        self.assertEqual([o.state for o in parsed.observations], ["BLOCKED", "PRESENT"])

    def test_deletion_marker_check_keeps_the_contact_index_category(self):
        parsed = self.parse([
            f'{TIME} level=DEBUG service=support_replica trace_id=t1 event=contact_query_started lookup_key=alex@example.test',
            f'{TIME} level=INFO service=support_replica trace_id=t1 event=contact_query_completed resource_id=support_101 rows=1',
            f'{TIME} level=WARN service=support_replica trace_id=t1 event=deletion_marker_check resource_id=support_101 marker_found=false'],
            origin="support_platform")
        self.assertEqual({o.category for o in parsed.observations}, {"SECONDARY_IDENTIFIER"})
        self.assertEqual(parsed.observations[-1].state, "PRESENT")

    def test_log_resource_prefix_overrides_a_misleading_service_name(self):
        parsed = self.parse([f'{TIME} requestId=t1 function=profile_service message=' +
                             json.dumps('event="profile_lookup_completed" resource_id="account_101" rows="0" http_status="404"')])
        self.assertEqual(parsed.observations[0].system_id, "account_service")

    def test_sql_disk_attachment_is_denied(self):
        with self.assertRaises(Exception):
            sql_connection("ATTACH DATABASE 'file:forbidden.db?mode=memory' AS other;")

    def test_sql_allows_foreign_key_setup(self):
        connection = sql_connection("PRAGMA foreign_keys=ON; CREATE TABLE x (id TEXT); INSERT INTO x VALUES ('example');")
        self.assertEqual(connection.execute("SELECT count(*) FROM x").fetchone()[0], 1)
        connection.close()


class OutputContract(unittest.TestCase):
    def test_round_trip_is_deterministic(self):
        states, _ = policy().reconstruct([observation()], request(), subject())
        result = plan(request(), states)
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "output.csv"
            write_output(path, [result], [request()])
            before = path.read_bytes()
            self.assertEqual(read_output(path), [result])
            write_output(path, [result], [request()])
            self.assertEqual(path.read_bytes(), before)

    def test_wrong_phase_and_state_rejected(self):
        with self.assertRaises(ValueError):
            AuditResult(case_id="custom_101", deletion_status="COMPLETE", steps=[{
                "step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_101",
                "operation": "VERIFY_RECORD_ABSENT", "state": "PRESENT", "evidence_id": "evidence_custom"}])

    def test_csv_is_not_published_when_cases_are_missing(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            path = Path(temporary) / "output.csv"
            path.write_text("previous", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_output(path, [], [request()])
            self.assertEqual(path.read_text(encoding="utf-8"), "previous")

    def test_complete_requires_cited_verifications(self):
        states, _ = policy().reconstruct([observation(state="ABSENT")], request(), subject())
        data = plan(request(), states).model_dump(mode="json")
        data["steps"][0]["evidence_id"] = ""
        with self.assertRaises(ValueError):
            AuditResult.model_validate(data)
