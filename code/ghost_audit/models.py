"""The public output contract and provenance-bearing internal records."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


OPERATIONS: dict[str, tuple[str, str, int]] = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT", 0),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT", 1),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE", 2),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE", 3),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED", 0),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED", 1),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT", 2),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED", 3),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED", 4),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT", 0),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT", 1),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED", 2),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED", 3),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED", 4),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED", 5),
}
PHASES = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def utc(value: str | datetime) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include its timezone")
    return parsed.astimezone(timezone.utc)


class Request(StrictModel):
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str

    @model_validator(mode="after")
    def timestamps(self) -> Request:
        if not utc(self.requested_at) <= utc(self.reported_at) <= utc(self.audit_at):
            raise ValueError("Request timestamps are out of order")
        return self


class Step(StrictModel):
    step_no: int = Field(ge=1)
    phase: Literal["FINDING", "REMEDIATION", "VERIFICATION"]
    system_id: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    operation: str
    state: str
    evidence_id: str

    @model_validator(mode="after")
    def operation_contract(self) -> Step:
        contract = OPERATIONS.get(self.operation)
        if contract is None or (self.phase, self.state) != contract[:2]:
            raise ValueError("Invalid phase/operation/state combination")
        return self

    def order_key(self) -> tuple[int, int, str, str]:
        return PHASES[self.phase], OPERATIONS[self.operation][2], self.system_id, self.resource_id


class AuditResult(StrictModel):
    case_id: str
    deletion_status: Status
    steps: list[Step]

    @model_validator(mode="after")
    def serialization_contract(self) -> AuditResult:
        if [s.step_no for s in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("Step numbers must start at 1 and be consecutive")
        if self.steps != sorted(self.steps, key=Step.order_key):
            raise ValueError("Steps are not in canonical order")
        if len({(s.phase, s.system_id, s.resource_id, s.operation) for s in self.steps}) != len(self.steps):
            raise ValueError("Duplicate steps")
        if self.deletion_status == Status.NOT_APPLICABLE and self.steps:
            raise ValueError("Non-deletion requests must have no steps")
        if self.deletion_status != Status.NOT_APPLICABLE and not self.steps:
            raise ValueError("Deletion decisions require evidence-backed coverage")
        if self.deletion_status == Status.COMPLETE:
            if any(s.phase != "VERIFICATION" or not s.evidence_id for s in self.steps):
                raise ValueError("COMPLETE permits only evidence-backed verification")
        if self.deletion_status == Status.INCOMPLETE:
            if {s.phase for s in self.steps} != set(PHASES):
                raise ValueError("INCOMPLETE requires all three phases")
            for step in self.steps:
                if (step.phase == "FINDING") != bool(step.evidence_id):
                    raise ValueError("Only findings may cite evidence in INCOMPLETE")
        return self


class Observation(StrictModel):
    observation_id: str
    evidence_id: str
    locator: str
    system_id: str
    resource_id: str
    category: str
    observed_at: str
    captured_at: str
    state: str
    replica: str = ""
    identifiers: list[str] = Field(default_factory=list)
    fields: dict[str, Any] = Field(default_factory=dict)
    kind: Literal["observation", "claim", "inferred"] = "observation"
    explicit_state: bool = False

    def eligible(self, cutoff: str) -> bool:
        """The recorded state existed at the cutoff, even if an export of it was captured later."""
        return utc(self.observed_at) <= utc(cutoff)

    def citable(self, cutoff: str) -> bool:
        """Only evidence captured by the cutoff may be cited as proof."""
        return bool(self.evidence_id) and self.eligible(cutoff) and utc(self.captured_at) <= utc(cutoff)


class SnapshotScope(StrictModel):
    evidence_id: str
    locator: str
    system_id: str
    category: str
    captured_at: str
    observed_at: str
    replica: str = ""
    resources: list[str]
    complete: bool


class Subject(StrictModel):
    user_id: str
    identifiers: list[str]
    names: list[str]
    audit_ids: list[str]


class ResourceState(StrictModel):
    system_id: str
    resource_id: str
    category: str
    required_action: str
    observation: Observation
    copies: list[Observation]
    compliant: bool
    issue: str = ""
    citation: str = ""


class ToolCall(StrictModel):
    tool: Literal["resolve_identity", "search_evidence", "inspect_resource", "read_artifact", "get_policy", "check_coverage"]
    query: str = ""
    resource_id: str = ""
    evidence_id: str = ""
    offset: int = Field(default=0, ge=0)


class AgentDecision(StrictModel):
    intent: Literal["DELETE", "NON_DELETE", "UNCERTAIN"]
    request_quote: str
    explanation: str = Field(min_length=12)
    tool_calls: list[ToolCall] = Field(max_length=6)
    finalize: bool
    accept_proposed_plan: bool
    unresolved: list[str]

    @model_validator(mode="after")
    def decision_contract(self) -> AgentDecision:
        if self.finalize and (self.tool_calls or self.unresolved or self.intent == "UNCERTAIN"):
            raise ValueError("Cannot finalize with pending tools, uncertainty, or unresolved questions")
        return self


class ReviewConcern(StrictModel):
    resource_id: str
    issue: str = Field(min_length=8)
    suggested_check: str


class ReviewVerdict(StrictModel):
    verdict: Literal["APPROVE", "CHALLENGE"]
    summary: str = Field(min_length=8)
    concerns: list[ReviewConcern] = Field(max_length=6)


class ExtractionFact(StrictModel):
    system_id: str
    resource_id: str
    category: str
    observed_at: str
    state: Literal["PRESENT", "ABSENT", "IDENTIFIABLE", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED", "UNKNOWN"]
    identifiers: list[str]
    supporting_text: str
    uncertain: bool


class Extraction(StrictModel):
    facts: list[ExtractionFact]
    explanation: str
