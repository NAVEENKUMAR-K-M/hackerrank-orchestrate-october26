"""Public CSV serialization and independent structural/evidence checks."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .evidence import EvidenceIndex
from .models import AuditResult, Request, utc
from .identity import Identities
from .policy import Policy
from .planner import validate_grounding
from .storage import atomic_text

HEADER = ["case_id", "deletion_status", "steps_json"]


def write_output(path: Path, results: list[AuditResult], requests: list[Request]) -> None:
    ordered = sorted(results, key=lambda r: r.case_id)
    if [r.case_id for r in ordered] != sorted(r.case_id for r in requests):
        raise ValueError("Results do not match every requested case exactly once")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(HEADER)
    for result in ordered:
        writer.writerow([result.case_id, result.deletion_status.value,
                         json.dumps([s.model_dump() for s in result.steps], ensure_ascii=False, separators=(",", ":"))])
    atomic_text(path, stream.getvalue())


def read_output(path: Path) -> list[AuditResult]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != HEADER:
            raise ValueError("Output CSV header is not the exact required contract")
        return [AuditResult(case_id=row["case_id"], deletion_status=row["deletion_status"],
                            steps=json.loads(row["steps_json"])) for row in reader]


def validate_output(path: Path, requests: list[Request], index: EvidenceIndex) -> dict[str, int]:
    results = read_output(path)
    return validate_results(results, requests, index)


def validate_results(results: list[AuditResult], requests: list[Request], index: EvidenceIndex) -> dict[str, int]:
    if [r.case_id for r in results] != sorted(r.case_id for r in requests):
        raise ValueError("Output rows must be sorted and cover the exact input case IDs")
    by_case = {r.case_id: r for r in requests}
    identities = Identities(index.dataset)
    policy = Policy(index.dataset.csv("deletion_rules.csv"))
    citations = 0
    for result in results:
        request = by_case[result.case_id]
        if result.deletion_status.value != "NOT_APPLICABLE":
            subject = identities.resolve(request)
            discovery = index.discover(subject, request)
            states, unresolved = policy.reconstruct(discovery["observations"], request, subject)
            if unresolved:
                raise ValueError(f"Unresolved evidence in {result.case_id}: {unresolved}")
            validate_grounding(result, request, states)
        for step in result.steps:
            if not step.evidence_id:
                continue
            manifest = index.manifest.get(step.evidence_id)
            if manifest and utc(manifest["captured_at"]) > utc(request.audit_at):
                raise ValueError(f"Future citation in {result.case_id}")
            if step.evidence_id.startswith("activity_"):
                claim = [r for r in index.activity if r["activity_id"] == step.evidence_id
                         and r["resource_id"] == step.resource_id and utc(r["event_time"]) <= utc(request.audit_at)]
                if not claim:
                    raise ValueError(f"Activity citation does not match its resource in {result.case_id}")
                citations += 1
                continue
            proofs = [o for o in index.by_resource.get(step.resource_id, [])
                      if o.system_id == step.system_id and o.evidence_id == step.evidence_id and o.citable(request.audit_at)]
            scopes = [s for s in index.scopes if s.evidence_id == step.evidence_id and s.complete
                      and s.system_id in {"*", step.system_id} and utc(s.captured_at) <= utc(request.audit_at)
                      and utc(s.observed_at) <= utc(request.audit_at) and step.resource_id not in s.resources]
            if not proofs and not (step.operation == "VERIFY_RECORD_ABSENT" and scopes):
                raise ValueError(f"Citation does not prove resource state in {result.case_id}")
            citations += 1
    return {"rows": len(results), "steps": sum(len(r.steps) for r in results), "citations": citations}
