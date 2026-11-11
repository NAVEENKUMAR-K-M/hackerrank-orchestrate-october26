"""Grounded extraction validation using explicit protocol test doubles."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_agent import Fixture, TIME
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.runtime import RuntimeUnavailable


def extraction() -> dict:
    return {"facts": [{"system_id": "account_service", "resource_id": "account_101", "category": "USER_PROFILE",
                       "observed_at": TIME, "state": "ABSENT", "identifiers": ["alex@example.test"],
                       "supporting_text": '"result": "NOT_FOUND"', "uncertain": False}],
            "explanation": "The source contains an explicit not-found readback for the profile."}


class ExtractionRuntime:
    model = "sonnet"

    def __init__(self, responses: list[dict]):
        self.responses = iter(responses)
        self.prompts: list[str] = []

    def complete(self, prompt, schema, purpose, images=None):
        self.prompts.append(prompt)
        return next(self.responses)


class ExtractionScenarios(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ghost-tests-")
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_future_fact_is_repaired_with_validation_feedback(self):
        bad = extraction()
        bad["facts"][0]["observed_at"] = "2026-04-03T12:00:00Z"
        runtime = ExtractionRuntime([bad, extraction()])
        self.fixture.index.interpret("evidence_custom", runtime)
        self.assertEqual(len(runtime.prompts), 2)
        self.assertIn("after evidence capture", runtime.prompts[1])

    def test_invented_quote_exhausts_bounded_repairs(self):
        bad = extraction()
        bad["facts"][0]["supporting_text"] = "This sentence was never in the supplied evidence."
        runtime = ExtractionRuntime([bad, bad, bad])
        before = len(self.fixture.index.observations)
        with self.assertRaisesRegex(RuntimeUnavailable, "repair budget exhausted"):
            self.fixture.index.interpret("evidence_custom", runtime)
        self.assertEqual(len(runtime.prompts), 3)
        self.assertEqual(len(self.fixture.index.observations), before)

    def test_unprinted_resource_requires_catalog_binding(self):
        bad = extraction()
        bad["facts"][0]["resource_id"] = "account_999"
        runtime = ExtractionRuntime([bad, bad, bad])
        with self.assertRaisesRegex(RuntimeUnavailable, "no catalog binding"):
            self.fixture.index.interpret("evidence_custom", runtime)

    def test_interpreted_structured_facts_survive_rebuild(self):
        path = self.fixture.root / "evidence/readback.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["note"] = "A follow-up read found account_202 absent for alex@example.test."
        path.write_text(json.dumps(data), encoding="utf-8")
        self.fixture.index.build()
        extra = extraction()
        extra["facts"][0].update(resource_id="account_202", supporting_text=data["note"])
        self.fixture.index.interpret("evidence_custom", ExtractionRuntime([extra]))
        rebuilt = EvidenceIndex(self.fixture.dataset, self.fixture.root / "cache")
        rebuilt.build()
        self.assertTrue(any(o.locator.startswith("interpreted:") for o in rebuilt.observations))

    def test_model_cannot_overwrite_a_structured_readback(self):
        wrong = extraction()
        wrong["facts"][0]["state"] = "PRESENT"
        self.fixture.index.interpret("evidence_custom", ExtractionRuntime([wrong]))
        self.assertEqual({o.state for o in self.fixture.index.by_resource["account_101"]}, {"ABSENT"})

    def test_invented_category_is_not_accepted(self):
        bad = extraction()
        bad["facts"][0]["category"] = "DELETE_EVERYTHING"
        runtime = ExtractionRuntime([bad, bad, bad])
        with self.assertRaisesRegex(RuntimeUnavailable, "not supplied"):
            self.fixture.index.interpret("evidence_custom", runtime)

    def test_customer_uploaded_file_is_attachment_even_when_it_contains_request_prose(self):
        from ghost_audit.models import Extraction
        from ghost_audit.policy import Policy
        from test_agent import write_csv
        write_csv(self.fixture.root / "deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [
            {"rule_id": "custom_attachment", "data_category": "SUPPORT_ATTACHMENT", "condition": "Subject only", "required_action": "DELETE"},
            {"rule_id": "custom_message", "data_category": "SUPPORT_MESSAGE", "condition": "Shared conversation", "required_action": "REDACT"}])
        artifact = self.fixture.index.artifacts["evidence_custom"]
        text = "support_909 for alex@example.test. Customer request: correct my address. Attachment properties and upload history. file correction.pdf; uploader customer"
        artifact.update(text=text, path=self.fixture.root / "evidence/attachment.pdf")
        data = extraction()
        data["facts"][0].update(system_id="support_platform", resource_id="support_909", category="SUPPORT_MESSAGE", state="PRESENT", supporting_text=text)
        observations = self.fixture.index._extracted_observations("evidence_custom", Extraction.model_validate(data), [])
        self.assertEqual(observations[0].category, "SUPPORT_ATTACHMENT")
        self.assertEqual(Policy(self.fixture.dataset.csv("deletion_rules.csv")).action(observations[0], self.fixture.dataset.requests()[0]), "DELETE")
        artifact["text"] = "support_909 for alex@example.test. Shared conversation: see correction.pdf uploaded by the customer."
        data["facts"][0]["supporting_text"] = artifact["text"]
        observations = self.fixture.index._extracted_observations("evidence_custom", Extraction.model_validate(data), [])
        self.assertEqual(observations[0].category, "SUPPORT_MESSAGE")

    def test_visual_fact_with_historical_identifier_reaches_discovery(self):
        from ghost_audit.models import Extraction
        from ghost_audit.identity import Identities
        artifact = self.fixture.index.artifacts["evidence_custom"]
        text = "Account account_202; owner old@example.test; user_101; status active"
        artifact.update(text=text, path=self.fixture.root / "evidence/account.png")
        data = extraction()
        data["facts"][0].update(resource_id="account_202", state="PRESENT", identifiers=["old@example.test", "user_101"], supporting_text=text)
        self.fixture.index.observations += self.fixture.index._extracted_observations("evidence_custom", Extraction.model_validate(data), [])
        self.fixture.index._reindex()
        request = self.fixture.dataset.requests()[0]
        found = self.fixture.index.discover(Identities(self.fixture.dataset).resolve(request), request)
        self.assertIn("account_202", found["resources"])

    def test_retained_reference_screen_needs_field_readbacks_to_prove_redaction(self):
        from test_agent import write_csv
        write_csv(self.fixture.root / "deletion_rules.csv", ["rule_id", "data_category", "condition", "required_action"], [
            {"rule_id": "custom_tombstone", "data_category": "ACCOUNT_TOMBSTONE", "condition": "Stable reference", "required_action": "REDACT"}])
        artifact = self.fixture.index.artifacts["evidence_custom"]
        artifact.update(text="Customer reference registry: tombstone_202 user_101 retained reference.", path=self.fixture.root / "evidence/reference.png")
        bad = extraction()
        bad["facts"][0].update(system_id="identity_service", resource_id="tombstone_202", category="ACCOUNT_TOMBSTONE", state="REDACTED", identifiers=["user_101"], supporting_text=artifact["text"])
        runtime = ExtractionRuntime([bad, {"facts": [], "explanation": "The reference view does not show identifier field readbacks."}])
        self.fixture.index.interpret("evidence_custom", runtime)
        self.assertEqual(len(runtime.prompts), 2)
        self.assertFalse(self.fixture.index.by_resource.get("tombstone_202"))
        text = "tombstone_202 user_101 full_name: null email: null phone: null email_hash: null"
        artifact["text"] = text
        bad["facts"][0]["supporting_text"] = text
        self.fixture.index.interpret("evidence_custom", ExtractionRuntime([bad]))
        self.assertEqual(self.fixture.index.by_resource["tombstone_202"][0].state, "REDACTED")
