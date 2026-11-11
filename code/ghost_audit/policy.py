"""Supplied-policy application; required retention is never treated as ghost PII."""
from __future__ import annotations

import json
from collections import defaultdict

from .identity import identifiers_in, normalize
from .models import Observation, Request, ResourceState, Subject, utc

DIRECT_FIELDS = {"name", "full_name", "display_name", "email", "phone", "email_hash", "customer_email",
                 "requester_name", "requester_email", "requester_phone", "owner_email", "owner_phone"}
LINK_FIELDS = {"user_id", "customer_reference", "subject_reference", "subject_selector"}
EMPTY_MARKERS = {"", "null", "none", "[redacted]", "redacted", "anonymous", "[anonymous]"}


def has_value(value: object) -> bool:
    return value is not None and str(value).strip().casefold() not in EMPTY_MARKERS


def exposed(observation: Observation, subject: Subject, unlink: bool = False) -> bool:
    fields = observation.fields
    names = {normalize(n) for n in subject.names}
    aliases = set(subject.identifiers)
    for key, value in fields.items():
        if key in DIRECT_FIELDS and has_value(value):
            if observation.category == "SUPPORT_MESSAGE" and normalize(str(value)) not in aliases | names:
                continue
            return True
        if unlink and key in LINK_FIELDS and has_value(value):
            if key == "subject_reference" and fields.get("_lookup_metadata"):
                continue
            return True
        if key in {"message_text", "message_excerpt", "body", "payload", "content"}:
            text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
            if identifiers_in(value) & aliases or any(name and name in normalize(text) for name in names):
                return True
    return False


def compliant(observation: Observation, action: str, subject: Subject) -> bool:
    state = observation.state
    if state == "UNKNOWN":
        return False
    if action == "DELETE":
        return state == "ABSENT"
    if action == "DISABLE":
        return state in {"DISABLED", "ABSENT"}
    if action == "BLOCK":
        return state == "BLOCKED"
    if action == "RETAIN":
        return state != "ABSENT"
    if state == "ABSENT":
        return False  # Redaction and anonymization preserve the required record.
    if action in {"REDACT", "ANONYMIZE"}:
        if state == "IDENTIFIABLE":
            return False
        if exposed(observation, subject, unlink=action == "ANONYMIZE"):
            return False
        if observation.explicit_state:
            return state == ("ANONYMIZED" if action == "ANONYMIZE" else "REDACTED")
        return True
    return False


class Policy:
    def __init__(self, rules: list[dict[str, str]]):
        self.rules = rules
        self.by_category = {row["data_category"]: row for row in rules}

    def action(self, observation: Observation, request: Request) -> str:
        if observation.category == "DATA_FLOW":
            return "DISABLE"
        if observation.category == "BACKUP_ARCHIVE":
            return "BLOCK"
        rule = self.by_category.get(observation.category)
        if rule is None:
            raise ValueError(f"No supplied policy for category {observation.category}")
        if observation.category == "SECURITY_AUDIT_LOG":
            until = observation.fields.get("retention_until")
            if until and utc(str(until)) < utc(request.audit_at):
                raise ValueError("Expired security retention has no supplied replacement action")
        if observation.category == "LEGAL_HOLD_RECORD" and observation.fields.get("hold_active") is False:
            raise ValueError("Inactive legal hold has no supplied replacement action")
        return rule["required_action"]

    def reconstruct(self, observations: list[Observation], request: Request,
                    subject: Subject) -> tuple[list[ResourceState], list[str]]:
        grouped: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        for observation in observations:
            if observation.kind in {"observation", "inferred"} and observation.eligible(request.audit_at):
                grouped[observation.system_id, observation.resource_id].append(observation)
        states, unresolved = [], []
        for (system, resource), history in sorted(grouped.items()):
            copies = self._latest_copies(history)
            try:
                action = self.action(copies[0], request)
                present = [o for o in copies if o.state != "ABSENT"]
                considered = present if action in {"RETAIN", "REDACT", "ANONYMIZE", "BLOCK", "DISABLE"} and present else copies
                if not present and action in {"RETAIN", "REDACT", "ANONYMIZE", "BLOCK"}:
                    unresolved.append(f"{resource}: required preserved record is missing; no supplied recreation operation exists")
                bad = [o for o in considered if not compliant(o, action, subject)]
                if action == "RETAIN" and present:
                    bad = []
                selected = max(bad or considered, key=lambda o: (utc(o.observed_at), utc(o.captured_at), o.evidence_id))
                if selected.state == "UNKNOWN":
                    unresolved.append(f"{resource}: observed state is unknown")
                # Cite evidence captured by the cutoff that shows the same verdict as the selected state.
                citable = [o for o in history if o.citable(request.audit_at)
                           and compliant(o, action, subject) == (not bad)]
                proof = max(citable, key=lambda o: (selected.evidence_id == o.evidence_id, utc(o.observed_at),
                                                    utc(o.captured_at), o.evidence_id), default=None)
                states.append(ResourceState(system_id=system, resource_id=resource, category=selected.category,
                                            required_action=action, observation=selected, copies=copies,
                                            compliant=not bad, citation=proof.evidence_id if proof else "",
                                            issue="" if not bad else f"Required {action}; observed {selected.state}"))
            except ValueError as exc:
                unresolved.append(f"{resource}: {exc}")
        return states, unresolved

    @staticmethod
    def _latest_copies(history: list[Observation]) -> list[Observation]:
        by_copy: dict[str, Observation] = {}
        for observation in sorted(history, key=lambda o: (utc(o.observed_at), utc(o.captured_at), o.evidence_id)):
            previous = by_copy.get(observation.replica)
            if previous is None or (utc(observation.observed_at), utc(observation.captured_at)) >= (
                    utc(previous.observed_at), utc(previous.captured_at)):
                by_copy[observation.replica] = observation
        return list(by_copy.values())
