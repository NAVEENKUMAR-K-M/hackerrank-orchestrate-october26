"""Codex CLI subscription adapter for bounded, schema-constrained inference."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import digest, write_json
from .transcript import redact

DEFAULT_MODEL = "gpt-6-sol"
DEFAULT_EFFORT = "medium"
ADAPTER_VERSION = 4


class RuntimeUnavailable(RuntimeError):
    def __init__(self, message: str, usage: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.usage = usage or []


class QuotaExhausted(RuntimeUnavailable):
    pass


class RuntimeBudgetExceeded(RuntimeUnavailable):
    pass


def find_codex() -> str:
    configured = os.environ.get("CODEX_BIN")
    if configured:
        if not Path(configured).is_file():
            raise RuntimeUnavailable("CODEX_BIN does not identify an executable")
        return configured
    found = shutil.which("codex") or shutil.which("codex.cmd")
    if found:
        return found
    if os.name == "nt":
        home = Path(os.environ.get("APPDATA", "")) / "npm" / "codex.cmd"
        if home.is_file():
            return str(home)
    raise RuntimeUnavailable("Codex CLI not found. Install it or set CODEX_BIN")


def clean_environment() -> dict[str, str]:
    """Keep CLI subscription login but never pass provider credentials or parent thread IDs."""
    denied = ("OPENAI_", "ANTHROPIC_", "AZURE_", "AWS_", "GOOGLE_", "GEMINI_",
              "CLAUDE_", "CLAUDECODE", "CODEX_THREAD", "CODEX_SESSION", "LOG_TOOL", "LOG_MODEL")
    return {k: v for k, v in os.environ.items()
            if not k.upper().startswith(denied)
            and not re.search(r"TOKEN|SECRET|PASSWORD|COOKIE|API_KEY|ACCESS_KEY", k.upper())}


def strict_schema(node: Any) -> Any:
    """Codex structured output requires closed objects with all properties required."""
    if isinstance(node, list):
        return [strict_schema(value) for value in node]
    if not isinstance(node, dict):
        return node
    cleaned = {key: strict_schema(value) for key, value in node.items() if key != "default"}
    if cleaned.get("type") == "object" or "properties" in cleaned:
        properties = cleaned.get("properties", {})
        cleaned["additionalProperties"] = False
        cleaned["required"] = list(properties)
    return cleaned


def parse_events(stdout: str) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    response: dict[str, Any] | None = None
    usage: list[dict[str, Any]] = []
    trace: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        kind = event.get("type", "")
        if kind.startswith("item."):
            item = event.get("item", {})
            item_type = item.get("type", "")
            if item_type not in {"agent_message", "reasoning"}:
                raise RuntimeUnavailable("Unexpected native Codex tool use")
            if kind == "item.completed" and item_type == "agent_message":
                try:
                    candidate = json.loads(item.get("text", ""))
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeUnavailable("Codex returned malformed structured JSON") from exc
                if isinstance(candidate, dict):
                    response = candidate
            continue
        if kind == "turn.completed":
            counters = event.get("usage") or {}
            usage.append({"input_tokens": int(counters.get("input_tokens", 0)),
                          "cached_input_tokens": int(counters.get("cached_input_tokens", 0)),
                          "cache_creation_input_tokens": 0,
                          "output_tokens": int(counters.get("output_tokens", 0)),
                          "turns": 1, "cost_usd": 0.0})
        if kind in {"turn.failed", "error"}:
            trace.append({"type": kind, "message": redact(str(event.get("error", event.get("message", ""))))[:500]})
        else:
            trace.append({"type": kind})
    if response is None:
        raise RuntimeUnavailable("Codex returned no structured response", usage)
    if not usage:
        raise RuntimeUnavailable("Codex did not report token usage; refusing unmetered inference")
    return response, usage, json.dumps(trace[-30:], ensure_ascii=False)


class CodexRuntime:
    def __init__(self, run_dir: Path, model: str = DEFAULT_MODEL, timeout: int = 180,
                 effort: str = DEFAULT_EFFORT):
        self.run_dir = run_dir
        self.model = model
        self.effort = effort
        self.timeout = timeout
        self.case_deadline: float | None = None
        self.executable = find_codex()
        self._preflight: dict[str, Any] | None = None
        self.usage_path = run_dir / "usage.jsonl"
        self.cache_dir = run_dir.parent / "model_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _remaining_timeout(self, limit: float) -> float:
        if self.case_deadline is None:
            return limit
        remaining = self.case_deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeBudgetExceeded("Case investigation deadline reached")
        return min(limit, remaining)

    def preflight(self) -> dict[str, Any]:
        env = clean_environment()
        version = subprocess.run([self.executable, "--version"], capture_output=True, text=True,
                                 timeout=self._remaining_timeout(30), env=env)
        status = subprocess.run([self.executable, "login", "status"], capture_output=True, text=True,
                                timeout=self._remaining_timeout(30), env=env)
        subscription = status.returncode == 0 and "Logged in using ChatGPT" in (status.stdout + status.stderr)
        return {"executable": self.executable, "version": version.stdout.strip(),
                "authenticated": subscription,
                "login_status": "Logged in using ChatGPT" if subscription else "ChatGPT login required",
                "model": self.model, "effort": self.effort,
                "billing": "Existing ChatGPT subscription; provider API keys removed; no API fallback"}

    def _record_usage(self, record: dict[str, Any]) -> None:
        self.usage_path.parent.mkdir(parents=True, exist_ok=True)
        record["recorded_at"] = datetime.now(timezone.utc).isoformat()
        with self.usage_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    @staticmethod
    def _usage_totals(usage: list[dict[str, Any]]) -> dict[str, Any]:
        return {"turns": sum(u.get("turns", 1) for u in usage), "usage_available": bool(usage),
                "cost_usd": round(sum(u.get("cost_usd", 0.0) for u in usage), 6),
                **{key: sum(u.get(key, 0) for u in usage) for key in
                   ("input_tokens", "cache_creation_input_tokens", "cached_input_tokens", "output_tokens")}}

    def complete(self, prompt: str, schema: dict[str, Any], purpose: str,
                 images: list[Path] | None = None) -> dict[str, Any]:
        images = images or []
        if len(prompt.encode("utf-8")) > 600000:
            raise RuntimeUnavailable("Prompt exceeds bounded context budget")
        schema = strict_schema(schema)
        key = digest({"provider": "codex-cli", "prompt": prompt, "schema": schema,
                      "model": self.model, "effort": self.effort,
                      "images": [digest(p.read_bytes()) for p in images], "adapter": ADAPTER_VERSION})
        cache = self.cache_dir / f"{key}.json"
        if cache.is_file():
            cached = json.loads(cache.read_text(encoding="utf-8"))
            self._record_usage({"purpose": purpose, "model": self.model, "cache_hit": True,
                                "input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0,
                                "cache_creation_input_tokens": 0, "cost_usd": 0.0,
                                "cache_key": key, "origin_usage": cached.get("usage", [])})
            return cached["response"]
        if self._preflight is None:
            self._preflight = self.preflight()
        if not self._preflight["authenticated"]:
            raise RuntimeUnavailable("Codex CLI must be signed in with ChatGPT: codex login")
        for attempt in range(3):
            if self.case_deadline is not None and time.monotonic() >= self.case_deadline:
                raise RuntimeBudgetExceeded("Case investigation deadline reached")
            invocation_id = uuid.uuid4().hex
            self._record_usage({"event": "invocation_started", "invocation_id": invocation_id,
                                "purpose": purpose, "model": self.model, "cache_hit": False,
                                "attempt": attempt + 1, "input_tokens": 0, "output_tokens": 0,
                                "cached_input_tokens": 0, "cache_creation_input_tokens": 0,
                                "cost_usd": 0.0, "turns": 0})
            try:
                result, usage, trace = self._invoke(prompt, schema, images)
                self._record_usage({"event": "invocation_finished", "invocation_id": invocation_id,
                                    "purpose": purpose, "model": self.model, "cache_hit": False,
                                    "attempt": attempt + 1, "success": True, "cache_key": key,
                                    "resolved_models": [self.model], **self._usage_totals(usage)})
                write_json(cache, {"response": result, "usage": usage, "model": self.model,
                                   "provider": "codex-cli"})
                trace_path = self.run_dir / "traces" / f"{key}.json"
                trace_path.parent.mkdir(parents=True, exist_ok=True)
                trace_path.write_text(redact(trace), encoding="utf-8")
                return result
            except QuotaExhausted as exc:
                self._record_usage({"event": "invocation_finished", "invocation_id": invocation_id,
                                    "purpose": purpose, "model": self.model, "cache_hit": False,
                                    "attempt": attempt + 1, "success": False, "error": "subscription_limit",
                                    **self._usage_totals(exc.usage)})
                raise
            except (RuntimeUnavailable, subprocess.TimeoutExpired) as exc:
                if isinstance(exc, RuntimeBudgetExceeded):
                    raise
                message = redact(str(exc))
                self._record_usage({"event": "invocation_finished", "invocation_id": invocation_id,
                                    "purpose": purpose, "model": self.model, "cache_hit": False,
                                    "attempt": attempt + 1, "success": False, "error": message[:500],
                                    **self._usage_totals(getattr(exc, "usage", []))})
                transient = isinstance(exc, subprocess.TimeoutExpired) or any(
                    word in message.casefold() for word in
                    ("temporar", "timeout", "timed out", "connection", "overloaded", "503", "502", "529", "500"))
                if not transient or attempt == 2:
                    raise RuntimeUnavailable(message) from exc
                time.sleep((2, 8)[attempt])
        raise RuntimeUnavailable("Retry budget exhausted")

    def _invoke(self, prompt: str, schema: dict[str, Any], images: list[Path]
                ) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
        with tempfile.TemporaryDirectory(prefix="ghost-audit-") as working:
            schema_file = Path(working) / "response.schema.json"
            schema_file.write_text(json.dumps(schema, ensure_ascii=False), encoding="utf-8")
            command = [self.executable, "exec", "--ignore-user-config", "--json", "--sandbox", "read-only",
                       "--skip-git-repo-check", "--cd", working, "--model", self.model,
                       "--output-schema", str(schema_file), "-c", 'web_search="disabled"',
                       "-c", 'forced_login_method="chatgpt"',
                       "-c", f'model_reasoning_effort="{self.effort}"',
                       "-c", "skills.bundled.enabled=false", "-c", "skills.include_instructions=false",
                       "--disable", "shell_tool", "--disable", "apps", "--disable", "plugins",
                       "--disable", "memories", "--disable", "multi_agent"]
            for image in images:
                command += ["--image", str(image.resolve())]
            command += ["-"]
            instruction = ("You are a JSON component inside a deletion-audit pipeline. "
                           "Do not use native tools or external information. Follow the request and JSON schema exactly.\n\n")
            run = subprocess.run(command, input=instruction + prompt, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", cwd=working,
                                 timeout=self._remaining_timeout(self.timeout), env=clean_environment())
        diagnostics = (run.stderr + "\n" + run.stdout[-1500:]).casefold()
        if any(marker in diagnostics for marker in
               ("usage limit", "rate limit reached", "quota exceeded", "subscription limit",
                "you've hit your limit", "you have reached your limit", "limit reached")):
            raise QuotaExhausted("Subscription limit reached; saved work can be resumed")
        if run.returncode:
            raise RuntimeUnavailable(redact((run.stderr or run.stdout)[-1600:]))
        return parse_events(run.stdout)
