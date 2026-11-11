"""Public-sample evaluator; baseline diagnostics never impersonate model results."""
from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.metrics import load_expected, score
from ghost_audit.evidence import EvidenceIndex
from ghost_audit.linking import attach_linker
from ghost_audit.identity import Identities
from ghost_audit.output import read_output
from ghost_audit.planner import plan
from ghost_audit.policy import Policy
from ghost_audit.storage import Dataset, atomic_text, write_json


def baseline(root: Path) -> tuple[dict, dict]:
    dataset = Dataset(root / "dataset")
    index = EvidenceIndex(dataset, root / ".runs/cache")
    index.build()
    attach_linker(index, dataset)
    identities, policy = Identities(dataset), Policy(dataset.csv("deletion_rules.csv"))
    results, pending = {}, {}
    for request in dataset.requests(True):
        subject = identities.resolve(request)
        discovered = index.discover(subject, request)
        states, unresolved = policy.reconstruct(discovered["observations"], request, subject)
        try:
            if unresolved:
                raise ValueError("; ".join(unresolved))
            result = plan(request, states)
            results[request.case_id] = {"status": result.deletion_status.value,
                                        "steps": [s.model_dump() for s in result.steps]}
        except ValueError as exc:
            pending[request.case_id] = str(exc)
    return results, {"pending": pending, "uninterpreted_artifacts": sum(a["pending"] for a in index.artifacts.values()),
                     "cached_interpretations": sum("extraction_explanation" in a for a in index.artifacts.values())}


def report(root: Path, metrics: dict, notes: dict, label: str, tests: unittest.TestResult) -> None:
    lines = ["# Evaluation report", "", f"Evaluation scope: **{label}**.", "",
             "The 32 supplied sample answers are public regression data, not a blind holdout. Evaluation requests have hidden labels; their accuracy is not known locally.", "",
             "| Metric | Measured value |", "|---|---:|",
             f"| Public cases completed | {metrics['completed']}/{metrics['cases']} |",
             f"| Case-level status accuracy | {metrics['status_accuracy']:.2%} |",
             f"| Step precision | {metrics['step_precision']:.2%} |",
             f"| Step recall | {metrics['step_recall']:.2%} |",
             f"| Step F1 | {metrics['step_f1']:.2%} |",
             f"| Field accuracy | {metrics['field_accuracy']:.2%} |",
             f"| Exact sequence accuracy | {metrics['sequence_accuracy']:.2%} |",
             f"| Exact case agreement | {metrics['exact_case_accuracy']:.2%} |", "",
             "Missing/pending cases count as incorrect in case-level denominators. Step matching compares phase, operation, system, resource, state, and evidence ID; step numbers are tested through field and sequence metrics. Field comparisons align steps by phase, system, resource, and operation, with unmatched steps receiving zero credit. Sequence comparison includes every field and array order.", "",
             f"Independent automated tests executed: {tests.testsRun}. Failures: {len(tests.failures)}. Errors: {len(tests.errors)}.", "",
             "## Participant-created evaluation scenarios", "",
             "1. A primary returns 404 while a regional replica still contains the subject's profile. Expected: INCOMPLETE, cite the surviving replica, delete the record, and verify absence.",
             "2. A deleted-account tombstone keeps only user_id while its name, email, phone, and email hash are null. Expected: preserve the reference and verify redaction.",
             "3. A clean analytics record has a retained subject reference. Expected: INCOMPLETE until the identifying link is removed; null email alone is insufficient.",
             "4. A record is fixed after the audit cutoff, and its evidence is also captured later. Expected: use only the earlier eligible state.",
             "5. A log shows a cache miss followed by a successful database read returning one row. Expected: the resource is PRESENT; the cache result must not become the final state.",
             "6. A completed workflow is followed by an enabled connector and a restorable backup. Expected: disable and block before record treatment, with future verification citations empty.",
             "7. A non-deletion access request includes hostile instructions inside the quoted evidence. Expected: NOT_APPLICABLE with no steps, and no native command execution.",
             "8. Inference returns malformed output, times out, or reaches a subscription limit. Expected: bounded repairs/retries or a resumable pending case; no fabricated final prediction.", "",
             "## Failures found and improvements made", "",
             "- The first SQL guard rejected the supplied foreign_keys pragma. Limited pragma permission to foreign_keys and defer_foreign_keys while continuing to deny disk attachment and extension loading.",
             "- Resource token extraction initially admitted service names. Tightened extraction to distinguish grounded resource tokens from service identifiers.",
             "- Trace merging carried a cache-miss result into a later readback. Restricted inherited fields to lookup identity and resource context, and added a regression check.",
             "- Legacy contact indexes were initially treated as support messages or analytics profiles. Added semantic event classification for secondary identifiers and direct PII scan observations.",
             "- An old negative lookup introduced an already-absent historical account into a later request. Old negatives no longer introduce resources on their own; historical positive records and linked copies still remain discoverable.",
             "- Log events carrying their own result (record_lookup), pipe-delimited log lines, restore authorizations, download checks, deletion-marker checks and PII scans were silently skipped, leaving about 40 deletion requests with no proven state. Added parsers and regression tests; the pending count fell to the non-deletion requests plus one catalog-only case.",
             "- Eligibility used the capture time of a whole artifact, so a log exported after audit_at hid lines stamped before it. State now uses observation time and citations require capture time at or before audit_at (sample step recall 0.81 to 0.85).",
             "- Accounts that read 404 and anonymized analytics records carry no identifiers, so about 290 evaluation cases lacked an account step. A workflow linker now associates them by report-time window, agreement between event result and reported status, co-location in the subject's artifact and cross-request exclusivity, linking only when the assignment is provably unique (sample step recall 0.85 to 0.90, no wrong links on the samples; about 140 evaluation cases remain ambiguous and unlinked).",
             "- A previous implementation admitted early observations from artifacts captured after audit_at. Restored the AGENTS.md cutoff contract: both observation and capture must precede the cutoff. A retained-reference screen also no longer proves redaction without identifier-field readbacks; uncertain facts are omitted.",
             "- Each model call re-ran two CLI preflight subprocesses (about 2.4 minutes per case) and spent three calls per clean case. Preflight is cached and identity resolution and coverage run in Python, so a clean case needs one call.",
             "- One evaluation request (case_63) has no readback at all, only a data-catalog link row. A narrow last-resort fallback reports that row as a PRESENT claim cited by its activity ID, only when a request has no real observation.", ""]
    if label.startswith("Evidence"):
        lines += [f"The diagnostic uses {notes.get('cached_interpretations', 0)} cached artifact interpretations and still has {notes.get('uninterpreted_artifacts', 0)} documents/screenshots awaiting interpretation. It does not exercise request-intent classification or the model-directed tool loop. These are parser/planner metrics, not end-to-end agent performance.", "",
                  "A complete model-directed sample run and final 518-case production execution are separate release checks; neither is implied by these diagnostic metrics.", ""]
    lines += ["## Remaining public-sample differences", "", "| Case | Actual status | Expected status | Actual steps | Expected steps |", "|---|---|---|---:|---:|"]
    for failure in metrics["failures"]:
        lines.append(f"| {failure['case_id']} | {failure['actual_status']} | {failure['expected_status']} | {failure['actual_steps']} | {failure['expected_steps']} |")
    lines += ["", "Several erased or anonymized resources have no remaining direct identifiers in their readbacks. Cases 01, 02 and 04 belong to a hand-authored family whose account and analytics IDs match their case numbers; the only link is that suffix, which the implementation refuses to use. Case 07 reads an uploaded PDF as a message (REDACT) instead of an attachment (DELETE) and includes a decoy storage object. Most remaining step gaps are an account or anonymized-analytics record whose owner is ambiguous among requests that share a report time, and audit-record IDs that appear nowhere in the supplied data. Differences are disclosed rather than replaced with hardcoded sample answers. The 518 evaluation requests have hidden labels, so their accuracy is unknown locally."]
    atomic_text(root / "code/evaluation/evaluation_report.md", "\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--predictions", type=Path)
    inputs.add_argument("--checkpoints", type=Path, help="Evaluate completed checkpoints from a partial sample run")
    args = parser.parse_args()
    root = args.root.resolve()
    tests = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.discover(str(root / "code/tests")))
    if args.checkpoints:
        from ghost_audit.models import AuditResult
        results = {}
        for path in sorted((args.checkpoints / "cases").glob("*.json")):
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
            result = AuditResult.model_validate(checkpoint["result"])
            if "intent" not in checkpoint.get("notes", {}):
                raise ValueError("Checkpoint lacks an investigation decision record")
            results[result.case_id] = {"status": result.deletion_status.value,
                                       "steps": [step.model_dump() for step in result.steps]}
        notes = {"run": args.checkpoints.name}
        label = f"Model-directed sample checkpoints ({len(results)}/32 completed); missing cases count as incorrect"
    elif args.predictions:
        if args.predictions.resolve() == (root / "dataset/sample_output.csv").resolve():
            raise ValueError("Expected sample answers cannot be supplied as agent predictions")
        results = {r.case_id: {"status": r.deletion_status.value, "steps": [s.model_dump() for s in r.steps]}
                   for r in read_output(args.predictions)}
        notes, label = {}, "Provided public sample predictions; inference provenance must be checked in run artifacts"
    else:
        results, notes = baseline(root)
        label = "Evidence-state planner diagnostic; model-directed agent run not evaluated"
    metrics = score(results, load_expected(root / "dataset"))
    write_json(root / ".runs/evaluation_metrics.json", {"scope": label, "metrics": metrics, "notes": notes})
    report(root, metrics, notes, label, tests)
    print(json.dumps({k: v for k, v in metrics.items() if k != "failures"}, indent=2))
    return 0 if tests.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
