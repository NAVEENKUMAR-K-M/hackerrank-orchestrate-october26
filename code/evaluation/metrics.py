"""Transparent public-sample metrics; missing cases remain in denominators."""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
IDENTITY = ("phase", "system_id", "resource_id", "operation")


def load_expected(dataset: Path) -> dict[str, dict[str, Any]]:
    # Only the evaluator opens public answers. The agent has no dependency on this module.
    with (dataset / "sample_output.csv").open(encoding="utf-8-sig", newline="") as stream:
        return {r["case_id"]: {"status": r["deletion_status"], "steps": json.loads(r["steps_json"])}
                for r in csv.DictReader(stream)}


def score(actual: dict[str, dict[str, Any]], expected: dict[str, dict[str, Any]]) -> dict[str, Any]:
    correct_status = exact_sequence = exact_case = true_steps = actual_steps = expected_steps = 0
    correct_fields = total_fields = 0
    failures = []
    for case, golden in sorted(expected.items()):
        prediction = actual.get(case, {"status": "PENDING", "steps": []})
        got, wanted = prediction["steps"], golden["steps"]
        status_ok = prediction["status"] == golden["status"]
        sequence_ok = case in actual and got == wanted
        correct_status += status_ok
        exact_sequence += sequence_ok
        exact_case += status_ok and sequence_ok
        got_counter = Counter(tuple(s[k] for k in FIELDS if k != "step_no") for s in got)
        wanted_counter = Counter(tuple(s[k] for k in FIELDS if k != "step_no") for s in wanted)
        true_steps += sum((got_counter & wanted_counter).values())
        actual_steps += len(got)
        expected_steps += len(wanted)
        got_by_key = {tuple(s[k] for k in IDENTITY): s for s in got}
        wanted_by_key = {tuple(s[k] for k in IDENTITY): s for s in wanted}
        for key in got_by_key.keys() | wanted_by_key.keys():
            total_fields += len(FIELDS)
            if key in got_by_key and key in wanted_by_key:
                correct_fields += sum(got_by_key[key][field] == wanted_by_key[key][field] for field in FIELDS)
        if not status_ok or not sequence_ok:
            failures.append({"case_id": case, "status_correct": status_ok, "actual_status": prediction["status"],
                             "expected_status": golden["status"], "actual_steps": len(got), "expected_steps": len(wanted)})
    precision = true_steps / actual_steps if actual_steps else 0
    recall = true_steps / expected_steps if expected_steps else 0
    return {"cases": len(expected), "completed": len(actual), "status_correct": correct_status,
            "status_accuracy": correct_status / len(expected), "sequence_correct": exact_sequence,
            "sequence_accuracy": exact_sequence / len(expected), "exact_case_accuracy": exact_case / len(expected),
            "step_precision": precision, "step_recall": recall,
            "step_f1": 2 * precision * recall / (precision + recall) if precision + recall else 0,
            "field_accuracy": correct_fields / total_fields if total_fields else 0,
            "actual_steps": actual_steps, "expected_steps": expected_steps, "failures": failures}
