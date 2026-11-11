"""Deterministic remediation planning and semantic citation validation."""
from __future__ import annotations

from .models import AuditResult, OPERATIONS, Request, ResourceState, Status, Step

VERIFY = {"DELETE": "VERIFY_RECORD_ABSENT", "RETAIN": "VERIFY_RECORD_PRESENT",
          "REDACT": "VERIFY_RECORD_REDACTED", "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
          "DISABLE": "VERIFY_DATA_FLOW_DISABLED", "BLOCK": "VERIFY_RESTORE_BLOCKED"}
REMEDIATE = {"DELETE": "DELETE_RECORD", "REDACT": "REDACT_RECORD", "ANONYMIZE": "ANONYMIZE_RECORD",
             "DISABLE": "DISABLE_DATA_FLOW", "BLOCK": "BLOCK_RESTORE"}
FIND = {"DELETE": "REPORT_REMAINING_RECORD", "REDACT": "REPORT_EXPOSED_PII",
        "ANONYMIZE": "REPORT_EXPOSED_PII", "DISABLE": "REPORT_ACTIVE_DATA_FLOW", "BLOCK": "REPORT_RESTORE_RISK"}


def plan(request: Request, states: list[ResourceState], non_deletion: bool = False) -> AuditResult:
    if non_deletion:
        return AuditResult(case_id=request.case_id, deletion_status=Status.NOT_APPLICABLE, steps=[])
    if not states:
        raise ValueError("No proven resource states; cannot finalize deletion")
    bad = [state for state in states if not state.compliant]
    steps: list[Step] = []
    for state in bad:
        if state.observation.state == "ABSENT" and state.required_action in {"REDACT", "ANONYMIZE", "BLOCK"}:
            raise ValueError(f"Required preserved record {state.resource_id} is missing; cannot invent a recreation operation")
        if state.required_action not in REMEDIATE:
            raise ValueError(f"No permitted remediation for missing retained resource {state.resource_id}")
        _add(steps, state, FIND[state.required_action], state.citation)
        _add(steps, state, REMEDIATE[state.required_action], "")
    for state in states:
        _add(steps, state, VERIFY[state.required_action], "" if bad else state.citation)
    steps.sort(key=Step.order_key)
    for number, step in enumerate(steps, 1):
        step.step_no = number
    return AuditResult(case_id=request.case_id, deletion_status=Status.INCOMPLETE if bad else Status.COMPLETE,
                       steps=steps)


def _add(steps: list[Step], state: ResourceState, operation: str, evidence: str) -> None:
    phase, result, _ = OPERATIONS[operation]
    steps.append(Step(step_no=1, phase=phase, system_id=state.system_id, resource_id=state.resource_id,
                      operation=operation, state=result, evidence_id=evidence))


def validate_grounding(result: AuditResult, request: Request, states: list[ResourceState]) -> None:
    # Reconstruct the expected plan independently of model prose and reject any unsupported step.
    expected = plan(request, states, result.deletion_status == Status.NOT_APPLICABLE)
    if expected != result:
        raise ValueError("Audit differs from the policy-backed resource plan")
    known = {(state.system_id, state.resource_id): state for state in states}
    for step in result.steps:
        state = known[step.system_id, step.resource_id]
        if step.evidence_id and step.evidence_id != state.citation:
            raise ValueError("Citation does not establish this resource's eligible state")
