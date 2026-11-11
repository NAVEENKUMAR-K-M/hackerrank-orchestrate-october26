"""Runnable terminal workflow with resumable, validated case checkpoints."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import InvestigationPending, Investigator
from .evidence import EvidenceIndex
from .linking import attach_linker
from .identity import Identities
from .models import AuditResult
from .planner import validate_grounding
from .output import validate_output, validate_results, write_output
from .policy import Policy
from .reports import package, usage_report
from .runtime import DEFAULT_MODEL, CodexRuntime, RuntimeUnavailable
from .storage import Dataset, digest, write_json


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists: evidence-grounded deletion audits")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("preflight", help="Inspect installation and subscription authentication without making a model call")
    index = commands.add_parser("index", help="Parse participant evidence and summarize indexed observations")
    index.add_argument("--vision", action="store_true", help="Interpret visual/doc evidence using Codex; uses subscription allowance")
    audit = commands.add_parser("audit", help="Investigate requests; write the final CSV only after complete validation")
    audit.add_argument("--samples", action="store_true")
    audit.add_argument("--limit", type=int, default=0)
    audit.add_argument("--case-id", default="")
    audit.add_argument("--max-decisions", type=int, default=8)
    audit.add_argument("--timeout", type=int, default=180)
    audit.add_argument("--smoke", action="store_true", help="Test model structured output before processing evidence")
    validate = commands.add_parser("validate")
    validate.add_argument("--output", type=Path)
    validate.add_argument("--samples", action="store_true")
    commands.add_parser("package", help="Create code.zip only after validating a complete final CSV")
    return parser


def source_fingerprint(root: Path) -> str:
    return digest([(p.name, digest(p.read_bytes())) for p in sorted((root / "code/ghost_audit").glob("*.py"))])


def make_index(root: Path, dataset: Dataset, model: str, runtime: CodexRuntime | None = None) -> EvidenceIndex:
    index = EvidenceIndex(dataset, root / ".runs/cache", model)
    index.build(runtime)
    attach_linker(index, dataset)
    return index


def validated_checkpoint(path: Path, fingerprint: str, investigator: Investigator) -> AuditResult:
    cached = json.loads(path.read_text(encoding="utf-8"))
    if cached["fingerprint"] != fingerprint:
        raise ValueError("Checkpoint fingerprint mismatch")
    result = AuditResult.model_validate(cached["result"])
    if result.case_id != investigator.request.case_id:
        raise ValueError("Checkpoint case ID mismatch")
    notes = cached.get("notes", {})
    quote = notes.get("request_quote", "")
    if not quote or quote not in investigator.request.request_text:
        raise ValueError("Checkpoint has no grounded intent quote")
    if result.deletion_status.value == "NOT_APPLICABLE":
        if notes.get("intent") != "NON_DELETE":
            raise ValueError("Checkpoint has inconsistent request intent")
    else:
        from .models import ToolCall
        investigator.dispatch(ToolCall(tool="resolve_identity"))
        if notes.get("intent") != "DELETE" or not investigator.coverage()["can_finalize"]:
            raise ValueError("Checkpoint no longer has complete evidence coverage")
        validate_grounding(result, investigator.request, investigator.states)
    return result


def run_audit(args: argparse.Namespace, root: Path, dataset: Dataset) -> int:
    if args.limit < 0 or args.max_decisions < 1 or args.timeout < 1:
        raise ValueError("Limit must be nonnegative; decision and timeout budgets must be positive")
    all_requests = dataset.requests(args.samples)
    expected_rows = 32 if args.samples else 518
    if len(all_requests) != expected_rows:
        raise ValueError(f"Expected {expected_rows} input requests, found {len(all_requests)}")
    input_hash, code_hash = dataset.fingerprint(args.samples), source_fingerprint(root)
    fingerprint = digest([input_hash, code_hash, args.model,
                          args.max_decisions, args.timeout])
    run_dir = root / ".runs" / (("samples-" if args.samples else "full-") + fingerprint[:16])
    runtime = CodexRuntime(run_dir, args.model, args.timeout)
    preflight = runtime.preflight()
    write_json(run_dir / "preflight.json", preflight)
    if not preflight["authenticated"]:
        usage_report(root, run_dir, 0)
        print(json.dumps(preflight, indent=2))
        print("Authentication required. Sign in through Codex CLI: codex login.", file=sys.stderr)
        return 2
    if args.smoke:
        response = runtime.complete("Return the JSON object {\"ready\":true}. Do not use tools.",
                                    {"type": "object", "properties": {"ready": {"type": "boolean"}},
                                     "required": ["ready"], "additionalProperties": False}, "runtime_smoke")
        if response != {"ready": True}:
            raise RuntimeUnavailable("Structured-output smoke check did not pass")
        print("Codex structured-output smoke check passed.", flush=True)
    print("Indexing evidence and interpreting documents/screenshots...", flush=True)
    try:
        index = make_index(root, dataset, args.model, runtime)
    except RuntimeUnavailable as exc:
        usage_report(root, run_dir, 0)
        write_json(run_dir / "run_summary.json", {"final": False, "pending_index": True, "reason": str(exc)})
        print(f"Evidence indexing checkpointed: {exc}", file=sys.stderr)
        return 2
    identities, policy = Identities(dataset), Policy(dataset.csv("deletion_rules.csv"))
    requests = [r for r in all_requests if not args.case_id or r.case_id == args.case_id]
    if args.case_id and not requests:
        raise ValueError("Unknown requested case ID")
    if args.limit:
        requests = requests[:args.limit]
    results: list[AuditResult] = []
    pending = []
    for number, request in enumerate(requests, 1):
        checkpoint = run_dir / "cases" / f"{request.case_id}.json"
        try:
            investigator = Investigator(request, identities, index, policy, runtime, run_dir, args.max_decisions)
            result = None
            if checkpoint.is_file():
                try:
                    result = validated_checkpoint(checkpoint, fingerprint, investigator)
                    print(f"[{number}/{len(requests)}] {request.case_id}: resumed and revalidated", flush=True)
                except ValueError:
                    print(f"[{number}/{len(requests)}] {request.case_id}: stale checkpoint; reinvestigating", flush=True)
                    investigator = Investigator(request, identities, index, policy, runtime, run_dir, args.max_decisions)
            if result is None:
                result, notes = investigator.run()
                write_json(checkpoint, {"fingerprint": fingerprint, "result": result.model_dump(mode="json"),
                                        "evidence_signature": digest(notes["resource_states"]), "notes": notes})
                print(f"[{number}/{len(requests)}] {request.case_id}: {result.deletion_status.value}", flush=True)
            results.append(result)
        except InvestigationPending as exc:
            pending.append({"case_id": request.case_id, "reason": str(exc)})
            print(f"[{number}/{len(requests)}] {request.case_id}: pending review", flush=True)
        except RuntimeUnavailable as exc:
            pending.append({"case_id": request.case_id, "reason": str(exc)})
            write_json(run_dir / "pending_cases.json", pending)
            usage_report(root, run_dir, len(results))
            print(f"Run checkpointed: {exc}", file=sys.stderr)
            return 2
    write_json(run_dir / "pending_cases.json", pending)
    complete = not pending and len(results) == len(all_requests)
    final = complete and not args.samples and len(results) == 518
    usage_report(root, run_dir, len(results), final)
    metadata = {"fingerprint": fingerprint, "model": args.model, "case_count": len(results),
                "requested_cases": len(all_requests), "pending": len(pending), "final": final,
                "source_fingerprint": code_hash, "dataset_fingerprint": input_hash}
    if complete:
        if source_fingerprint(root) != code_hash or dataset.fingerprint(args.samples) != input_hash:
            raise ValueError("Source or dataset changed during the run; resume with the new fingerprint")
        target = run_dir / "sample_output.csv" if args.samples else root / "output.csv"
        metadata["validation"] = validate_results(results, all_requests, index)
        write_output(target, results, all_requests)
        metadata["output"] = str(target)
        metadata["output_sha256"] = digest(target.read_bytes())
        write_json(root / ".runs" / ("latest_samples.json" if args.samples else "latest_full.json"),
                   {"run_dir": str(run_dir), **metadata})
    write_json(run_dir / "run_summary.json", metadata)
    print(json.dumps(metadata, indent=2))
    if not complete:
        print("Final output was not written: cases remain pending or this was a limited run.", file=sys.stderr)
    return 0 if complete else 2


def main(argv: list[str] | None = None) -> int:
    args = arguments().parse_args(argv)
    root = args.root.resolve()
    dataset = Dataset(root / "dataset")
    try:
        if args.command == "preflight":
            info = CodexRuntime(root / ".runs/preflight", args.model).preflight()
            print(json.dumps(info, indent=2))
            return 0 if info["authenticated"] else 2
        if args.command == "audit":
            return run_audit(args, root, dataset)
        if args.command == "index":
            runtime = CodexRuntime(root / ".runs/index", args.model) if args.vision else None
            index = make_index(root, dataset, args.model, runtime)
            print(json.dumps({"files": len(index.manifest), "observations": len(index.observations),
                              "snapshot_scopes": len(index.scopes),
                              "pending_interpretation": [k for k, a in index.artifacts.items() if a["pending"]]}, indent=2))
            return 0
        index = make_index(root, dataset, args.model)
        if args.command == "validate":
            path = args.output or root / "output.csv"
            print(json.dumps(validate_output(path, dataset.requests(args.samples), index), indent=2))
            return 0
        if args.command == "package":
            latest = root / ".runs/latest_full.json"
            if not latest.is_file() or not json.loads(latest.read_text(encoding="utf-8")).get("final"):
                raise ValueError("No completed full-dataset run manifest exists")
            production = json.loads(latest.read_text(encoding="utf-8"))
            if production.get("source_fingerprint") != source_fingerprint(root) or production.get("dataset_fingerprint") != dataset.fingerprint():
                raise ValueError("Source or dataset differs from the completed production run")
            if production.get("output_sha256") != digest((root / "output.csv").read_bytes()):
                raise ValueError("Output differs from the validated production artifact")
            usage = (root / "code/evaluation/usage_report.md").read_text(encoding="utf-8")
            if "Final 518-case output generated: **yes**" not in usage or Path(production["run_dir"]).name not in usage:
                raise ValueError("Usage report does not describe the completed production run")
            validation = validate_output(root / "output.csv", dataset.requests(), index)
            print(json.dumps(package(root, validation["rows"] == 518), indent=2))
            return 0
    except (OSError, ValueError, RuntimeUnavailable) as exc:
        print(f"Audit error: {exc}", file=sys.stderr)
        return 2
    return 2
