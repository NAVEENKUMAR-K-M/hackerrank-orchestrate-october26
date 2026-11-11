from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.evidence import EvidenceIndex
from ghost_audit.identity import Identities
from ghost_audit.linking import WorkflowLinker, attach_linker
from ghost_audit.planner import plan
from ghost_audit.policy import Policy
from ghost_audit.storage import Dataset
from test_agent import write_csv

REQUEST_FIELDS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
ACTIVITY_FIELDS = ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id",
                   "reported_result", "details"]


def stamp(day: int, hour: int, minute: int = 0) -> str:
    return f"2026-05-{day:02d}T{hour:02d}:{minute:02d}:00Z"


class World:
    """A tiny batch: each case's own records sit in one export, accounts are identity-free 404 stubs."""

    def __init__(self, root: Path, cases: list[dict], events: list[dict], accounts: list[str],
                 capture: str = None, remaining: bool = False):
        evidence = root / "evidence"
        evidence.mkdir()
        write_csv(root / "user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"], [
            {"user_id": f"user_{n}", "name": f"Person {n}", "email": f"person{n}@example.test",
             "phone": f"+1 202 555 01{n:02d}", "email_hash": f"{n:064x}", "updated_at": "2026-01-01T00:00:00Z"}
            for n in range(1, len(cases) + 1)])
        write_csv(root / "user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], [])
        write_csv(root / "system_activity.csv", ACTIVITY_FIELDS, events)
        write_csv(root / "deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [
            {"rule_id": "r1", "data_category": "USER_PROFILE", "condition": "Always", "required_action": "DELETE"},
            {"rule_id": "r2", "data_category": "SECURITY_AUDIT_LOG", "condition": "Within retention", "required_action": "RETAIN"},
            {"rule_id": "r3", "data_category": "SEARCH_INDEX_ENTRY", "condition": "Always", "required_action": "DELETE"}])
        rows = [{"case_id": c["case_id"], "email": f"person{n}@example.test", "requested_at": stamp(1, 9),
                 "reported_status": c["status"], "reported_at": c["reported_at"], "audit_at": stamp(20, 12),
                 "request_text": "Please delete my account permanently."} for n, c in enumerate(cases, 1)]
        write_csv(root / "deletion_requests.csv", REQUEST_FIELDS, rows)
        write_csv(root / "sample_deletion_requests.csv", REQUEST_FIELDS, [])
        records = [{"recorded_at": stamp(10, 8), "system": "security_service", "resource_id": f"audit_record_{n}",
                    "record_type": "SECURITY_AUDIT_LOG", "result": "FOUND", "subject_reference": f"user_{n}",
                    "retention_until": "2034-01-01T00:00:00Z"} for n in range(1, len(cases) + 1)]
        records += [{"recorded_at": stamp(10, 8), "system": "account_service", "resource_id": account,
                     "record_type": "USER_PROFILE", "result": "NOT_FOUND"} for account in accounts]
        if remaining:   # a surviving search document makes the first request provisionally incomplete
            records.append({"recorded_at": stamp(10, 8), "system": "search_service", "resource_id": "search_77",
                            "record_type": "SEARCH_INDEX_ENTRY", "result": "FOUND",
                            "subject_reference": "person1@example.test"})
        (evidence / "export.json").write_text(json.dumps({"exported_at": capture or stamp(10, 9), "records": records}),
                                              encoding="utf-8")
        write_csv(root / "evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [
            {"file_id": "evidence_export", "file_path": "evidence/export.json", "origin": "account_service",
             "captured_at": capture or stamp(10, 9)}])
        self.dataset = Dataset(root)
        self.index = EvidenceIndex(self.dataset, root / "cache")
        self.index.build()
        self.linker = attach_linker(self.index, self.dataset)
        self.identities = Identities(self.dataset)
        self.policy = Policy(self.dataset.csv("deletion_rules.csv"))

    def request(self, case_id: str):
        return next(r for r in self.dataset.requests() if r.case_id == case_id)

    def links(self, case_id: str) -> list[str]:
        return [link.resource_id for link in self.linker.links_for(case_id)]


def delete_event(number: int, resource: str, when: str, result: str) -> dict:
    return {"activity_id": f"activity_{number}", "event_time": when, "event_type": "DELETE_RECORD",
            "source_system": "deletion_worker", "target_system": "account_service", "resource_id": resource,
            "reported_result": result, "details": f"Deletion worker submitted primary profile {resource} to account_service."}


class WorkflowLinkScenarios(unittest.TestCase):
    def build(self, cases, events, accounts, **kwargs):
        temporary = tempfile.TemporaryDirectory(prefix="ghost-tests-")
        self.addCleanup(temporary.cleanup)
        return World(Path(temporary.name), cases, events, accounts, **kwargs)

    def test_unique_timing_and_claim_agreement_links_the_identity_free_account(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "COMPLETE", "reported_at": stamp(5, 12)},
             {"case_id": "custom_2", "status": "NOT_STARTED", "reported_at": stamp(7, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "SUCCESS"),
             delete_event(2, "account_9002", stamp(7, 11, 5), "FAILED")],
            ["account_9001", "account_9002"])
        self.assertEqual(world.links("custom_1"), ["account_9001"])
        self.assertEqual(world.links("custom_2"), ["account_9002"])
        request = world.request("custom_1")
        subject = world.identities.resolve(request)
        found = world.index.discover(subject, request)
        states, unresolved = world.policy.reconstruct(found["observations"], request, subject)
        self.assertFalse(unresolved)
        result = plan(request, states)
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertIn(("VERIFY_RECORD_ABSENT", "account_9001", "evidence_export"),
                      [(s.operation, s.resource_id, s.evidence_id) for s in result.steps])

    def test_equally_plausible_pair_is_matched_in_sorted_order_as_a_marked_heuristic(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "NOT_STARTED", "reported_at": stamp(5, 12)},
             {"case_id": "custom_2", "status": "NOT_STARTED", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "FAILED"),
             delete_event(2, "account_9002", stamp(5, 11, 5), "FAILED")],
            ["account_9001", "account_9002"])
        self.assertEqual([l.resource_id for l in world.index.linker.links_for("custom_1")], ["account_9001"])
        self.assertEqual([l.resource_id for l in world.index.linker.links_for("custom_2")], ["account_9002"])
        self.assertTrue(all(l.rule.endswith("-tiebreak") for c in ("custom_1", "custom_2")
                            for l in world.index.linker.links_for(c)))

    def test_three_way_ties_are_left_unlinked(self):
        world = self.build(
            [{"case_id": f"custom_{n}", "status": "NOT_STARTED", "reported_at": stamp(5, 12)} for n in (1, 2, 3)],
            [delete_event(n, f"account_900{n}", stamp(5, 11, n), "FAILED") for n in (1, 2, 3)],
            [f"account_900{n}" for n in (1, 2, 3)])
        for n in (1, 2, 3):
            self.assertEqual(world.index.linker.links_for(f"custom_{n}"), [])

    def test_result_that_contradicts_the_reported_status_is_not_linked(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "COMPLETE", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "FAILED")], ["account_9001"])
        self.assertEqual(world.links("custom_1"), [])

    def test_event_outside_the_lead_window_is_not_linked(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "COMPLETE", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 7, 0), "SUCCESS")], ["account_9001"])
        self.assertEqual(world.links("custom_1"), [])

    def test_resource_already_linked_by_content_is_not_taken(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "COMPLETE", "reported_at": stamp(5, 12)},
             {"case_id": "custom_2", "status": "COMPLETE", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "SUCCESS"),
             delete_event(2, "account_9002", stamp(5, 11, 5), "SUCCESS")],
            ["account_9001", "account_9002"])
        # The first account is claimed by content once its stub carries person1's identity.
        record = world.index.by_resource["account_9001"][0]
        record.identifiers = ["person1@example.test"]
        world.index._reindex()
        self.assertEqual(world.links("custom_1"), [])
        self.assertEqual(world.links("custom_2"), ["account_9002"])

    def test_link_without_a_readback_is_a_verification_target_that_cannot_be_cited(self):
        world = self.build(
            [{"case_id": "custom_1", "status": "NOT_STARTED", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "FAILED")], [], remaining=True)
        self.assertEqual(world.links("custom_1"), ["account_9001"])
        request = world.request("custom_1")
        subject = world.identities.resolve(request)
        found = world.index.discover(subject, request)
        synthetic = [o for o in found["observations"] if o.kind == "inferred"]
        self.assertEqual(len(synthetic), 1)
        self.assertFalse(synthetic[0].citable(request.audit_at))
        states, _ = world.policy.reconstruct(found["observations"], request, subject)
        result = plan(request, states)
        self.assertEqual(result.deletion_status.value, "INCOMPLETE")
        verification = [s for s in result.steps if s.resource_id == "account_9001"]
        self.assertEqual([(s.operation, s.evidence_id) for s in verification], [("VERIFY_RECORD_ABSENT", "")])

    def test_synthetic_target_is_never_reported_as_remaining_data(self):
        states_world = self.build(
            [{"case_id": "custom_1", "status": "NOT_STARTED", "reported_at": stamp(5, 12)}],
            [delete_event(1, "account_9001", stamp(5, 11, 0), "FAILED")], [], remaining=True)
        request = states_world.request("custom_1")
        subject = states_world.identities.resolve(request)
        found = states_world.index.discover(subject, request)
        states, _ = states_world.policy.reconstruct(found["observations"], request, subject)
        inferred = next(s for s in states if s.resource_id == "account_9001")
        self.assertTrue(inferred.compliant)
        self.assertEqual(inferred.citation, "")

    def test_assignment_is_unique_or_absent(self):
        edges = {"a": {"x"}, "b": {"x", "y"}, "c": {"y", "z"}}
        self.assertEqual(WorkflowLinker._unique_assignment(edges), {"a": "x", "b": "y", "c": "z"})
        self.assertEqual(WorkflowLinker._unique_assignment({"a": {"x", "y"}, "b": {"x", "y"}}), {})

    def test_two_requests_with_one_shared_candidate_are_not_ordered_into_ownership(self):
        self.assertEqual(WorkflowLinker._unique_assignment({"a": {"x"}, "b": {"x"}}), {})
        self.assertEqual(WorkflowLinker._unique_assignment({"b": {"x"}, "a": {"x"}}), {})

    def test_infeasible_group_does_not_block_an_independent_proven_assignment(self):
        self.assertEqual(WorkflowLinker._unique_assignment({"a": {"x"}, "b": {"x"}, "c": {"z"}}), {"c": "z"})

    def test_only_forced_edge_survives_when_another_request_has_equal_alternatives(self):
        self.assertEqual(WorkflowLinker._unique_assignment({"a": {"x"}, "b": {"x", "y", "z"}}), {"a": "x"})


if __name__ == "__main__":
    unittest.main()


class CatalogClaimFallback(unittest.TestCase):
    def test_catalog_row_is_used_only_when_no_readback_exists(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            world = World(Path(temporary), [{"case_id": "custom_1", "status": "NOT_STARTED", "reported_at": stamp(5, 12)}],
                          [], [])
            world.index.activity.append({
                "activity_id": "activity_catalog", "event_time": stamp(6, 8), "event_type": "LINK_RESOURCE_IDENTITY",
                "source_system": "data_catalog", "target_system": "marketing_platform", "resource_id": "marketing_001",
                "reported_result": "SUCCESS",
                "details": "Data catalog linked marketing_001 (marketing_001) to person1@example.test and user_1."})
            world.index.activity_by_identifier["person1@example.test"].append(world.index.activity[-1])
            request = world.request("custom_1")
            subject = world.identities.resolve(request)
            found = world.index.discover(subject, request, temporal=False)
            claims = [o for o in found["observations"] if o.evidence_id == "activity_catalog"]
            # The fixture has a real readback (the audit record), so the catalog row must not be used.
            self.assertEqual(claims, [])
