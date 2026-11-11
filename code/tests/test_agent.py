from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.agent import InvestigationPending, Investigator
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.identity import Identities
from ghost_audit.models import ToolCall
from ghost_audit.policy import Policy
from ghost_audit.storage import Dataset

TIME = "2026-04-02T12:00:00Z"


def write_csv(path: Path, fields: list[str], records: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        evidence = root / "evidence"
        evidence.mkdir()
        write_csv(root / "user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"], [
            {"user_id": "user_101", "name": "Alex Example", "email": "alex@example.test", "phone": "+1 202 555 0101",
             "email_hash": "a" * 64, "updated_at": "2026-03-01T00:00:00Z"}])
        write_csv(root / "user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], [
            {"audit_id": "audit_custom", "user_id": "user_101", "event_time": "2026-02-01T00:00:00Z",
             "field_name": "email", "old_value": "old@example.test", "new_value": "alex@example.test"}])
        write_csv(root / "system_activity.csv", ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"], [])
        write_csv(root / "deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [
            {"rule_id": "rule_custom", "data_category": "USER_PROFILE", "condition": "Always", "required_action": "DELETE"}])
        write_csv(root / "deletion_requests.csv", ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"], [
            {"case_id": "custom_101", "email": "old@example.test", "requested_at": "2026-04-01T00:00:00Z",
             "reported_status": "COMPLETE", "reported_at": "2026-04-02T11:00:00Z", "audit_at": TIME,
             "request_text": "Please delete my account permanently."}])
        (evidence / "readback.json").write_text(json.dumps({"exported_at": TIME, "origin": "account_service", "records": [
            {"recorded_at": TIME, "system": "account_service", "resource_id": "account_101",
             "record_type": "USER_PROFILE", "result": "NOT_FOUND", "subject_reference": "alex@example.test"}]}), encoding="utf-8")
        write_csv(root / "evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], [
            {"file_id": "evidence_custom", "file_path": "evidence/readback.json", "origin": "account_service", "captured_at": TIME}])
        self.dataset = Dataset(root)
        self.index = EvidenceIndex(self.dataset, root / "cache")
        self.index.build()


def decision(intent="DELETE", finalize=False, tool_calls=None, quote="delete my account") -> dict:
    return {"intent": intent, "request_quote": quote, "explanation": "The literal request authorizes permanent account deletion.",
            "tool_calls": tool_calls or [], "finalize": finalize, "accept_proposed_plan": finalize,
            "unresolved": []}


class ReplayRuntime:
    """Test double only: no model-performance claims are made from these responses."""
    def __init__(self, responses: list[dict], reviews: list[dict] | None = None):
        self.responses = iter(responses)
        self.reviews = iter(reviews or [])
        self.prompts: list[str] = []
        self.review_prompts: list[str] = []

    def complete(self, prompt, schema, purpose, images=None):
        if "REVIEW INPUT (UNTRUSTED DATA)" in prompt:
            self.review_prompts.append(prompt)
            return next(self.reviews, {"verdict": "APPROVE", "summary": "Plan matches the resource states.", "concerns": []})
        self.prompts.append(prompt)
        return next(self.responses)


class AgentScenarios(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ghost-tests-")
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def agent(self, runtime, **kwargs):
        dataset = self.fixture.dataset
        return Investigator(dataset.requests()[0], Identities(dataset), self.fixture.index,
                            Policy(dataset.csv("deletion_rules.csv")), runtime, self.fixture.root / "run", **kwargs)

    def test_clean_case_finalizes_in_one_call_after_python_preparation(self):
        runtime = ReplayRuntime([decision(finalize=True)])
        result, notes = self.agent(runtime).run()
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertEqual(result.steps[0].resource_id, "account_101")
        self.assertEqual(len(runtime.prompts), 1)
        self.assertEqual(notes["history"][0]["prepared"], ["resolve_identity", "check_coverage"])

    def test_reviewer_approval_is_recorded_without_extra_investigation(self):
        runtime = ReplayRuntime([decision(finalize=True)])
        result, notes = self.agent(runtime).run()
        self.assertEqual(len(runtime.review_prompts), 1)
        self.assertEqual(notes["review"]["verdict"], "APPROVE")
        self.assertEqual(len(runtime.prompts), 1)

    def test_reviewer_challenge_reopens_investigation_once(self):
        challenge = {"verdict": "CHALLENGE", "summary": "Check the account record again.",
                     "concerns": [{"resource_id": "account_101", "issue": "Account absence not rechecked",
                                   "suggested_check": "inspect_resource account_101"}]}
        runtime = ReplayRuntime([decision(finalize=True), decision(finalize=True)], reviews=[challenge, challenge])
        result, notes = self.agent(runtime).run()
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertEqual(len(runtime.prompts), 2)
        self.assertIn("reviewer_challenge", runtime.prompts[1])
        self.assertNotIn("reviewer_challenge", runtime.prompts[0])
        self.assertEqual(len(runtime.review_prompts), 1)   # the investigator's second answer is not re-reviewed
        self.assertEqual(notes["review"]["verdict"], "CHALLENGE")

    def test_non_deletion_is_not_reviewed(self):
        runtime = ReplayRuntime([decision(intent="NON_DELETE", finalize=True, quote="Do not delete the account.")])
        agent = self.agent(runtime)
        agent.request.request_text = "Please send a copy of my information. Do not delete the account."
        agent.run()
        self.assertEqual(runtime.review_prompts, [])

    def test_real_tool_dispatch_precedes_finalization(self):
        runtime = ReplayRuntime([
            decision(tool_calls=[ToolCall(tool="inspect_resource", resource_id="account_101").model_dump()]),
            decision(finalize=True)])
        result, notes = self.agent(runtime).run()
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertEqual(len(runtime.prompts), 2)
        results = [h for h in notes["history"] if "tool_results" in h]
        self.assertEqual(results[0]["tool_results"][0]["result"]["resource_id"], "account_101")

    def test_premature_completion_receives_validation_feedback(self):
        refused = {**decision(finalize=True), "accept_proposed_plan": False}
        runtime = ReplayRuntime([refused, decision(finalize=True)])
        result, _ = self.agent(runtime).run()
        self.assertEqual(result.deletion_status.value, "COMPLETE")
        self.assertIn("validation_error", runtime.prompts[1])

    def test_non_deletion_finishes_in_one_call_without_actions(self):
        runtime = ReplayRuntime([decision(intent="NON_DELETE", finalize=True, quote="Do not delete the account.")])
        agent = self.agent(runtime)
        agent.request.request_text = "Please send a copy of my information. Do not delete the account."
        result, _ = agent.run()
        self.assertEqual(len(runtime.prompts), 1)
        self.assertEqual(result.steps, [])
        self.assertEqual(result.deletion_status.value, "NOT_APPLICABLE")

    def test_model_cannot_invoke_shell_tool(self):
        malicious = decision(tool_calls=[{"tool": "run_shell", "query": "delete files"}])
        runtime = ReplayRuntime([malicious, malicious, malicious])
        with self.assertRaises(InvestigationPending):
            self.agent(runtime).run()
        self.assertTrue((self.fixture.root / "run/pending/custom_101.json").is_file())

    def test_fabricated_request_quote_is_rejected(self):
        invalid = decision(finalize=True, quote="not present in this request")
        runtime = ReplayRuntime([invalid, invalid, invalid])
        with self.assertRaises(InvestigationPending):
            self.agent(runtime).run()

    def test_iteration_cap_is_enforced(self):
        runtime = ReplayRuntime([decision(tool_calls=[ToolCall(tool="get_policy").model_dump()])])
        with self.assertRaisesRegex(InvestigationPending, "decision cap"):
            self.agent(runtime, max_decisions=1).run()

    def test_future_artifact_cannot_be_read(self):
        self.fixture.index.manifest["evidence_custom"]["captured_at"] = "2026-04-03T12:00:00Z"
        with self.assertRaisesRegex(ValueError, "after the case cutoff"):
            self.agent(ReplayRuntime([])).dispatch(ToolCall(tool="read_artifact", evidence_id="evidence_custom"))

    def test_historical_email_resolves_subject(self):
        resolved = Identities(self.fixture.dataset).resolve(self.fixture.dataset.requests()[0])
        self.assertEqual(resolved.user_id, "user_101")
        self.assertIn("old@example.test", resolved.identifiers)
        self.assertIn("alex@example.test", resolved.identifiers)

    def test_prediction_loader_rejects_sample_answers(self):
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            self.fixture.dataset.csv("sample_output.csv")

    def test_evidence_path_cannot_escape_dataset(self):
        with self.assertRaises(ValueError):
            self.fixture.dataset.evidence_path("../user_identities.csv")

    def test_timeline_search_returns_claims_without_assigning_ownership(self):
        with (self.fixture.root / "system_activity.csv").open("a", encoding="utf-8", newline="") as stream:
            csv.writer(stream).writerow(["activity_custom", TIME, "DELETE_RECORD", "deletion_worker", "account_service",
                                         "account_202", "SUCCESS", "An unrelated workflow targeted account_202."])
        index = EvidenceIndex(self.fixture.dataset, self.fixture.root / "cache")
        index.build()
        found = index.search("2026-04-02 account_service", TIME)
        self.assertTrue(any("activity_claim" in hit for hit in found["hits"]))
        request = self.fixture.dataset.requests()[0]
        resolved = Identities(self.fixture.dataset).resolve(request)
        self.assertNotIn("account_202", index.discover(resolved, request)["resources"])

    def test_quoted_identifiers_use_exact_observation_retrieval(self):
        found = self.fixture.index.search('"alex@example.test"', TIME)
        self.assertTrue(any("observation" in hit for hit in found["hits"]))

    def test_multiword_resource_prefixes_are_valid_without_admitting_service_names(self):
        from ghost_audit.identity import RESOURCE
        from ghost_audit.parsers import describe
        self.assertTrue(RESOURCE.fullmatch("email_delivery_909"))
        self.assertTrue(RESOURCE.fullmatch("legal_hold_808"))
        self.assertTrue(RESOURCE.fullmatch("secondary_identifier_707"))
        self.assertFalse(RESOURCE.fullmatch("account_service"))
        self.assertEqual(describe("email_delivery_909"), ("email_delivery_service", "EMAIL_DELIVERY_LOG"))
        self.assertEqual(describe("legal_hold_808"), ("legal_service", "LEGAL_HOLD_RECORD"))

    def test_model_can_stop_an_unresolved_case_without_a_guessed_status(self):
        deferred = decision()
        deferred["unresolved"] = ["A fresh identity-linked resource observation is needed"]
        runtime = ReplayRuntime([decision(tool_calls=[ToolCall(tool="resolve_identity").model_dump()]), deferred])
        with self.assertRaisesRegex(InvestigationPending, "identity-linked"):
            self.agent(runtime).run()
        self.assertEqual(len(runtime.prompts), 2)

    def test_skipping_to_a_last_search_page_does_not_clear_required_coverage(self):
        agent = self.agent(ReplayRuntime([]))
        agent.dispatch(ToolCall(tool="resolve_identity"))
        agent.dispatch(ToolCall(tool="search_evidence", query='"alex@example.test"', offset=20))
        self.assertTrue(any("unread pages" in issue for issue in agent.coverage()["issues"]))
        agent.dispatch(ToolCall(tool="search_evidence", query='"alex@example.test"', offset=0))
        self.assertFalse(any("unread pages" in issue for issue in agent.coverage()["issues"]))

    def test_cached_complete_result_is_rejected_when_new_evidence_survives(self):
        from ghost_audit.cli import validated_checkpoint
        from ghost_audit.storage import write_json
        runtime = ReplayRuntime([
            decision(tool_calls=[ToolCall(tool="resolve_identity").model_dump(), ToolCall(tool="check_coverage").model_dump()]),
            decision(finalize=True)])
        result, notes = self.agent(runtime).run()
        path = self.fixture.root / "case.json"
        write_json(path, {"fingerprint": "test", "result": result.model_dump(mode="json"), "notes": notes})
        self.fixture.index.observations[0].state = "PRESENT"
        self.fixture.index._reindex()
        with self.assertRaisesRegex(ValueError, "policy-backed"):
            validated_checkpoint(path, "test", self.agent(ReplayRuntime([])))
