from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_audit.runtime import (ClaudeRuntime, QuotaExhausted, RuntimeBudgetExceeded, RuntimeUnavailable,
                                 clean_environment, normalize_usage, parse_result)
from ghost_audit.reports import package, usage_report
from ghost_audit.transcript import append_entry, redact
from evaluation.metrics import score


class RuntimeScenarios(unittest.TestCase):
    def test_api_credentials_are_not_inherited(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-only", "OPENAI_API_KEY": "test-only",
                                     "CLAUDECODE": "1", "GH_TOKEN": "test-only",
                                     "CLAUDE_CODE_OAUTH_TOKEN": "subscription-token"}):
            environment = clean_environment()
        self.assertNotIn("ANTHROPIC_API_KEY", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("CLAUDECODE", environment)
        self.assertNotIn("GH_TOKEN", environment)
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", environment)

    def test_result_parsing_and_usage_normalization(self):
        payload = {"type": "result", "usage": {"input_tokens": 2, "cache_creation_input_tokens": 30,
                                               "cache_read_input_tokens": 5, "output_tokens": 7},
                   "total_cost_usd": 0.01, "num_turns": 2, "modelUsage": {"claude-sonnet-5-5": {}}}
        parsed = parse_result("noise" + chr(10) + json.dumps({"type": "system"}) + chr(10) + json.dumps(payload))
        usage = normalize_usage(parsed)
        self.assertEqual((usage["input_tokens"], usage["cache_creation_input_tokens"],
                          usage["cached_input_tokens"], usage["output_tokens"]), (2, 30, 5, 7))
        self.assertEqual(usage["resolved_models"], ["claude-sonnet-5-5"])
        with self.assertRaises(ValueError):
            parse_result("")

    def runtime(self, path):
        with patch("ghost_audit.runtime.find_claude", return_value="test-claude"):
            return ClaudeRuntime(Path(path) / "run")

    def test_subscription_quota_is_not_retried(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch.object(runtime, "preflight", return_value={"authenticated": True}), \
                 patch.object(runtime, "_invoke", side_effect=QuotaExhausted("quota")) as invoke:
                with self.assertRaises(QuotaExhausted):
                    runtime.complete("test", {"type": "object", "properties": {}}, "custom")
                self.assertEqual(invoke.call_count, 1)

    def test_model_response_cache_avoids_new_inference(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch.object(runtime, "preflight", return_value={"authenticated": True}), \
                 patch.object(runtime, "_invoke", return_value=({"ready": True}, [{"input_tokens": 10, "output_tokens": 2}], "")) as invoke:
                first = runtime.complete("test", {"type": "object", "properties": {}}, "custom")
                second = runtime.complete("test", {"type": "object", "properties": {}}, "custom")
                self.assertEqual(first, second)
                self.assertEqual(invoke.call_count, 1)
            records = [json.loads(line) for line in runtime.usage_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(sum(r["input_tokens"] for r in records), 10)
            self.assertTrue(records[-1]["cache_hit"])

    def test_transient_failures_have_bounded_retries(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch.object(runtime, "preflight", return_value={"authenticated": True}), \
                 patch.object(runtime, "_invoke", side_effect=RuntimeUnavailable("temporary connection error")) as invoke, \
                 patch("ghost_audit.runtime.time.sleep"):
                with self.assertRaises(RuntimeUnavailable):
                    runtime.complete("test", {"type": "object", "properties": {}}, "custom")
                self.assertEqual(invoke.call_count, 3)

    def test_api_login_is_rejected_by_preflight(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            version = subprocess.CompletedProcess([], 0, "2.1.302 (Claude Code)", "")
            status = subprocess.CompletedProcess([], 0, json.dumps({"loggedIn": True, "authMethod": "api_key"}), "")
            with patch("ghost_audit.runtime.subprocess.run", side_effect=[version, status]):
                self.assertFalse(runtime.preflight()["authenticated"])

    def test_failed_attempt_retains_reported_token_usage(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            failure = RuntimeUnavailable("Unexpected native tool", [{"input_tokens": 20, "output_tokens": 3}])
            with patch.object(runtime, "preflight", return_value={"authenticated": True}), \
                 patch.object(runtime, "_invoke", side_effect=failure):
                with self.assertRaises(RuntimeUnavailable):
                    runtime.complete("test", {"type": "object", "properties": {}}, "custom")
            records = [json.loads(line) for line in runtime.usage_path.read_text(encoding="utf-8").splitlines()]
            record = records[-1]
            self.assertEqual(records[0]["event"], "invocation_started")
            self.assertEqual(record["input_tokens"], 20)
            self.assertEqual(record["output_tokens"], 3)

    def test_expired_case_budget_makes_no_model_call(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            runtime.case_deadline = 0
            with patch.object(runtime, "preflight", return_value={"authenticated": True}), \
                 patch.object(runtime, "_invoke") as invoke:
                with self.assertRaises(RuntimeBudgetExceeded):
                    runtime.complete("test", {"type": "object", "properties": {}}, "custom")
                invoke.assert_not_called()

    def completed(self, **fields):
        payload = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 2,
                   "usage": {"input_tokens": 10, "output_tokens": 2}, "total_cost_usd": 0.001,
                   "structured_output": {"ready": True}, **fields}
        return subprocess.CompletedProcess([], 0, json.dumps(payload), "")

    def test_tool_denial_is_rejected_but_usage_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch("ghost_audit.runtime.subprocess.run",
                       return_value=self.completed(permission_denials=[{"tool_name": "Bash"}])):
                with self.assertRaisesRegex(RuntimeUnavailable, "Unexpected tool") as raised:
                    runtime._invoke("test", {"type": "object"}, [])
            self.assertEqual(raised.exception.usage[0]["input_tokens"], 10)

    def test_invocation_disables_tools_and_user_configuration(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch("ghost_audit.runtime.subprocess.run", return_value=self.completed()) as run:
                response, usage, _ = runtime._invoke("test", {"type": "object"}, [])
            args = run.call_args.args[0]
            self.assertEqual(response, {"ready": True})
            self.assertEqual(usage[0]["output_tokens"], 2)
            self.assertEqual(args[args.index("--tools") + 1], "")
            for flag in ("--safe-mode", "--no-session-persistence", "--json-schema"):
                self.assertIn(flag, args)
            self.assertNotIn("ANTHROPIC_API_KEY", run.call_args.kwargs["env"])

    def test_images_use_stream_json_input(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            image = Path(temporary) / "evidence.png"
            image.write_bytes(b"PNG fake")
            with patch("ghost_audit.runtime.subprocess.run", return_value=self.completed()) as run:
                runtime._invoke("describe", {"type": "object"}, [image])
            message = json.loads(run.call_args.kwargs["input"])
            self.assertEqual([c["type"] for c in message["message"]["content"]], ["image", "text"])
            self.assertIn("stream-json", run.call_args.args[0])

    def test_subscription_limit_message_is_quota_not_transient(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            limited = self.completed(is_error=True, subtype="error", result="You've hit your limit")
            with patch("ghost_audit.runtime.subprocess.run", return_value=limited):
                with self.assertRaises(QuotaExhausted):
                    runtime._invoke("test", {"type": "object"}, [])

    def test_missing_usage_refuses_unmetered_inference(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            runtime = self.runtime(temporary)
            with patch("ghost_audit.runtime.subprocess.run", return_value=self.completed(usage=None)):
                with self.assertRaises(RuntimeUnavailable):
                    runtime._invoke("test", {"type": "object"}, [])


class TranscriptScenarios(unittest.TestCase):
    def test_sensitive_values_are_redacted_before_append(self):
        value = redact("Contact alex@example.test at +1 202 555 0101; api_key=test-value")
        self.assertNotIn("alex@example.test", value)
        self.assertNotIn("202 555", value)
        self.assertNotIn("test-value", value)

    def test_bearer_and_cookie_values_are_redacted_as_whole_credentials(self):
        value = redact("Authorization: Bearer synthetic-secret\nCookie: session=synthetic-cookie; other=value\nhttps://example.test/?code=synthetic-code")
        self.assertNotIn("synthetic-secret", value)
        self.assertNotIn("synthetic-cookie", value)
        self.assertNotIn("synthetic-code", value)
    def test_append_preserves_prior_bytes_and_literal_prompt(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            (root / "AGENTS.md").write_text("Instructions", encoding="utf-8")
            (root / "log.txt").write_bytes(b"original entry\n")
            metadata = {"tool": "test-harness", "model": "test-model-identifier", "branch": "test",
                        "repo_root": str(root), "worktree": str(root), "parent_agent": "none"}
            with patch("ghost_audit.transcript.runtime_metadata", return_value=metadata):
                append_entry(root, "Synthetic test", "Ran a synthetic test. Verified append-only behavior.",
                             ["Executed a unit test."], "A literal prompt with tool=<template> inside it.")
            written = (root / "log.txt").read_bytes()
            self.assertTrue(written.startswith(b"original entry\n"))
            self.assertNotIn(b"\r", written)
            self.assertIn(b"tool=test-harness\nmodel=test-model-identifier", written)

    def test_excluded_turn_writes_nothing(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            append_entry(root, "excluded", "not logged", [], excluded=True)
            self.assertFalse((root / "log.txt").exists())


class EvaluationScenarios(unittest.TestCase):
    def test_pending_case_is_not_dropped_from_denominator(self):
        expected = {"one": {"status": "NOT_APPLICABLE", "steps": []},
                    "two": {"status": "NOT_APPLICABLE", "steps": []}}
        metrics = score({"one": expected["one"]}, expected)
        self.assertEqual(metrics["status_accuracy"], 0.5)
        self.assertEqual(metrics["sequence_accuracy"], 0.5)

    def test_sequence_accuracy_detects_reordering(self):
        first = {"step_no": 1, "phase": "VERIFICATION", "system_id": "test", "resource_id": "account_101",
                 "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_custom"}
        second = {**first, "step_no": 2, "resource_id": "account_202"}
        expected = {"one": {"status": "COMPLETE", "steps": [first, second]}}
        actual = {"one": {"status": "COMPLETE", "steps": [second, first]}}
        metrics = score(actual, expected)
        self.assertEqual(metrics["step_precision"], 1)
        self.assertEqual(metrics["sequence_accuracy"], 0)


class PackagingScenarios(unittest.TestCase):
    def test_package_refuses_unvalidated_output(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            with self.assertRaises(ValueError):
                package(Path(temporary), False)

    def test_archive_excludes_data_credentials_and_caches(self):
        import zipfile
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            (root / "code/evaluation").mkdir(parents=True)
            (root / "code/__pycache__").mkdir()
            (root / "dataset").mkdir()
            for name in ["README.md", "requirements.txt", "output.csv", "log.txt",
                         "code/main.py", "code/evaluation/evaluation_report.md", "code/evaluation/usage_report.md",
                         "code/auth.json", "code/.env", "code/__pycache__/cached.py", "dataset/private.csv"]:
                (root / name).write_text("synthetic fixture", encoding="utf-8")
            result = package(root, True)
            with zipfile.ZipFile(result["archive"]) as archive:
                names = archive.namelist()
            self.assertNotIn("code/auth.json", names)
            self.assertNotIn("code/.env", names)
            self.assertNotIn("code/__pycache__/cached.py", names)
            self.assertFalse(any(name.startswith("dataset/") for name in names))
            self.assertIn("evaluation/evaluation_report.md", names)
            self.assertIn("code/evaluation/usage_report.md", names)


class UsageScenarios(unittest.TestCase):
    def test_replayed_origin_usage_is_counted_once_per_response(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary); run = root / "run"; run.mkdir()
            origin = {"input_tokens": 100, "cache_creation_input_tokens": 0, "cached_input_tokens": 60,
                      "output_tokens": 10, "turns": 1}
            record = {"model": "sonnet", "cache_hit": True, "cache_key": "same-answer", "origin_usage": [origin]}
            (run / "usage.jsonl").write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")
            usage_report(root, run, 2)
            report = (root / "code/evaluation/usage_report.md").read_text(encoding="utf-8")
            self.assertIn("1 invocations including replays", report)
