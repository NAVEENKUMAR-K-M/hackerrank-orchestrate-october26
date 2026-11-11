"""Measured usage and release artifacts; never fabricate unavailable metrics."""
from __future__ import annotations

import json
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from .storage import atomic_text, digest, write_json


def usage_report(root: Path, run_dir: Path, case_count: int, final: bool = False) -> None:
    entries = []
    path = run_dir / "usage.jsonl"
    if path.is_file():
        entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    models: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    counted_invocations: set[str] = set()
    started: set[str] = set()
    finished: set[str] = set()
    own_keys = {r.get("cache_key") for r in entries if r.get("success") and not r.get("cache_hit")}
    replayed_keys: set[str] = set()
    for record in entries:
        counts = models[record["model"]]
        counts["cache_hits"] += int(record.get("cache_hit", False))
        key = record.get("cache_key")
        origins = record.get("origin_usage", []) if key not in own_keys and key not in replayed_keys else []
        if origins:
            replayed_keys.add(key)
        for origin in origins:
            # A replayed answer was produced by an earlier invocation; its measured usage still belongs to this output.
            counts["replayed_invocations"] += 1
            counts["replayed_turns"] += origin.get("turns", 1)
            for key in ("input_tokens", "cache_creation_input_tokens", "cached_input_tokens", "output_tokens", "cost_usd"):
                counts["replayed_" + key] += origin.get(key, 0)
        invocation = record.get("invocation_id")
        if not record.get("cache_hit", False) and (invocation is None or invocation not in counted_invocations):
            counts["invocations"] += 1
            if invocation:
                counted_invocations.add(invocation)
        if record.get("event") == "invocation_started":
            started.add(invocation)
        elif record.get("event") == "invocation_finished":
            finished.add(invocation)
            counts["failures"] += int(not record.get("success", False))
        counts["completed_turns"] += record.get("turns", 0)
        for key in ("input_tokens", "cache_creation_input_tokens", "cached_input_tokens", "output_tokens", "cost_usd"):
            counts[key] += record.get(key, 0)
    lines = ["# Usage report", "", f"Run: `{run_dir.name}`. Final 518-case output generated: **{'yes' if final else 'no'}**.", "",
             f"Completed requests in this run: {case_count}. Provider: Anthropic through the Claude Code CLI (`claude -p`) with a Claude subscription login.", "",
             "| Model requested | CLI invocations | Failed invocations | Model turns | Uncached input | Cache-write input | Cache-read input | Output tokens | List-price cost (USD) | Application cache hits |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    totals: dict[str, float] = defaultdict(float)

    def row(label: str, c: dict[str, float]) -> str:
        return (f"| {label} | {int(c['invocations'])} | {int(c['failures'])} | {int(c['completed_turns'])} | {int(c['input_tokens'])} | "
                f"{int(c['cache_creation_input_tokens'])} | {int(c['cached_input_tokens'])} | {int(c['output_tokens'])} | "
                f"{c['cost_usd']:.4f} | {int(c['cache_hits'])} |")
    for model, counts in sorted(models.items()):
        lines.append(row(model, counts))
        for key, value in counts.items():
            totals[key] += value
    lines.append(row("Overall (this run's own invocations)", totals))
    replay = {k[9:]: v for k, v in totals.items() if k.startswith("replayed_")}
    if replay.get("invocations"):
        lines += ["", "Answers replayed from the application cache were produced by earlier invocations (the interrupted first pass "
                  "and the sample runs share one cache). Their originally measured usage, summed from the cache records:", "",
                  "| Source | CLI invocations | Model turns | Uncached input | Cache-write input | Cache-read input | Output tokens | List-price cost (USD) |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|",
                  f"| Replayed answers (original usage) | {int(replay['invocations'])} | {int(replay['turns'])} | {int(replay['input_tokens'])} | "
                  f"{int(replay['cache_creation_input_tokens'])} | {int(replay['cached_input_tokens'])} | {int(replay['output_tokens'])} | {replay['cost_usd']:.4f} |"]
        for key in ("input_tokens", "cache_creation_input_tokens", "cached_input_tokens", "output_tokens", "cost_usd"):
            totals[key] += replay[key]
        totals["invocations"] += replay["invocations"]
        lines += ["", f"Combined usage behind the final output: {int(totals['invocations'])} invocations including replays."]
    tokens = int(totals["input_tokens"] + totals["cache_creation_input_tokens"]
                 + totals["cached_input_tokens"] + totals["output_tokens"])
    if case_count:
        lines += ["", f"Total tokens (all input classes plus output): {tokens}. Average per completed request: {tokens / case_count:.2f}.",
                  f"Estimated list-price cost: ${totals['cost_usd']:.4f} total, ${totals['cost_usd'] / case_count:.4f} per completed request."]
    else:
        lines += ["", f"Total reported tokens: {tokens}. Per-request averages are unavailable because no requests completed."]
    lines += ["", "Input is split into the three classes the CLI reports: uncached input, cache-write input and cache-read input. "
              "Cost is the CLI-reported list-price equivalent of those tokens at standard rates. The run authenticates with an existing "
              "Claude subscription and removes provider API keys from the child environment, so the incremental API charge is $0; "
              "the list-price figure is an estimate of what the same usage would cost on pay-as-you-go rates, not an invoice. "
              "Cache-hit rows are application-level replays and cost nothing.", "",
              "Model names above are the explicit selections passed to the CLI; resolved model identifiers are retained in usage.jsonl. "
              "CLI invocations and reported turns are observable; backend request counts that the CLI does not expose are not invented. "
              "Cached rows keep their originating usage under `origin_usage`; that earlier usage belongs to the run that created it."]
    lines += ["", f"Started invocations without a closing event: {len(started - finished)}. Their unreported tokens are unknown, not assumed to be zero."]
    if not final:
        lines += ["", "This is an interim report. It does not claim a completed full-dataset production run."]
    if not entries:
        preflight = run_dir / "preflight.json"
        configured = json.loads(preflight.read_text(encoding="utf-8")).get("model", "not recorded") if preflight.is_file() else "not recorded"
        lines += ["", f"No model inference was invoked. The configured model was `{configured}`; setup/preflight did not permit an inference run."]
    atomic_text(root / "code/evaluation/usage_report.md", "\n".join(lines) + "\n")


def package(root: Path, output_validated: bool) -> dict[str, Any]:
    if not output_validated:
        raise ValueError("Validate a completed 518-case output before packaging a submission")
    required = [root / "README.md", root / "requirements.txt",
                root / "code/evaluation/evaluation_report.md", root / "code/evaluation/usage_report.md"]
    if not all(path.is_file() for path in required):
        raise ValueError("Required README, requirements, or evaluation reports are missing")
    files = [root / "README.md", root / "requirements.txt"]
    files += sorted(path for path in (root / "code").rglob("*") if path.is_file()
                    and path.suffix in {".py", ".md", ".txt", ".toml"}
                    and "__pycache__" not in path.parts)
    if any(path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) for path in files):
        raise ValueError("Submission source must not link outside the repository")
    target = root / "code.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(root).as_posix())
        for name in ("evaluation_report.md", "usage_report.md"):
            archive.write(root / "code/evaluation" / name, "evaluation/" + name)
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None:
            raise ValueError("Submission ZIP integrity check failed")
        names = archive.namelist()
        if any(name.startswith(("dataset/", ".runs/")) or Path(name).suffix in
               {".zip", ".tar", ".gz", ".tgz", ".7z", ".rar"} for name in names):
            raise ValueError("Forbidden submission archive content")
    hashes = {name: digest((root / name).read_bytes()) for name in ("code.zip", "output.csv", "log.txt")}
    write_json(root / ".runs/submission_manifest.json", {"sha256": hashes, "archive_files": names})
    return {"archive": str(target), "files": len(names), "sha256": hashes}
