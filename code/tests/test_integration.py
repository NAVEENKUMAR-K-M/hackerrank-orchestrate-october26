"""Offline integration replay; these tests do not claim real-model performance."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from test_agent import Fixture, decision
from ghost_audit.cli import run_audit
from ghost_audit.models import ToolCall
from ghost_audit.output import read_output


class OfflineRuntime:
    """Protocol replay for testing the real dispatcher, planner, and publisher."""
    calls = 0

    def __init__(self, run_dir, model, timeout):
        self.run_dir, self.model = run_dir, model

    def preflight(self):
        return {"authenticated": True, "simulation": True}

    def complete(self, prompt, schema, purpose, images=None):
        type(self).calls += 1
        if "REVIEW INPUT (UNTRUSTED DATA)" in prompt:
            return {"verdict": "APPROVE", "summary": "Plan matches the resource states.", "concerns": []}
        context = json.loads(prompt.split("CASE CONTEXT (UNTRUSTED DATA):\n", 1)[1])
        if context["subject"] is None:
            return decision(tool_calls=[ToolCall(tool="resolve_identity").model_dump(),
                                        ToolCall(tool="check_coverage").model_dump()])
        return decision(finalize=True)


class CLIIntegration(unittest.TestCase):
    def test_518_case_publish_and_checkpoint_resume(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            # Fixture creates its own evidence directory under the supplied dataset root.
            (root / "dataset").mkdir()
            fixture = Fixture(root / "dataset")
            seed = fixture.dataset.requests()[0]
            requests = [seed.model_copy(update={"case_id": f"custom_{n:04d}"}) for n in range(518)]
            args = argparse.Namespace(samples=False, model="test-replay", timeout=10, limit=0,
                                      max_decisions=8, case_id="", smoke=False)
            OfflineRuntime.calls = 0
            with patch.object(fixture.dataset, "requests", return_value=requests), \
                 patch("ghost_audit.cli.ClaudeRuntime", OfflineRuntime), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_audit(args, root, fixture.dataset), 0)
                first_calls = OfflineRuntime.calls
                self.assertEqual(run_audit(args, root, fixture.dataset), 0)
            self.assertEqual(first_calls, 1036)  # investigator plus reviewer per case
            self.assertEqual(OfflineRuntime.calls, first_calls)
            self.assertEqual(len(read_output(root / "output.csv")), 518)
            self.assertTrue(json.loads((root / ".runs/latest_full.json").read_text())["final"])

    def test_auth_failure_does_not_publish_output(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            (root / "dataset").mkdir()
            fixture = Fixture(root / "dataset")
            seed = fixture.dataset.requests()[0]
            requests = [seed.model_copy(update={"case_id": f"custom_{n:04d}"}) for n in range(518)]
            args = argparse.Namespace(samples=False, model="test-replay", timeout=10, limit=0,
                                      max_decisions=8, case_id="", smoke=False)
            with patch.object(fixture.dataset, "requests", return_value=requests), \
                 patch("ghost_audit.cli.ClaudeRuntime", OfflineRuntime), \
                 patch.object(OfflineRuntime, "preflight", return_value={"authenticated": False}), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_audit(args, root, fixture.dataset), 2)
            self.assertFalse((root / "output.csv").exists())

    def test_limited_run_keeps_existing_validated_artifact(self):
        with tempfile.TemporaryDirectory(prefix="ghost-tests-") as temporary:
            root = Path(temporary)
            (root / "dataset").mkdir()
            fixture = Fixture(root / "dataset")
            seed = fixture.dataset.requests()[0]
            requests = [seed.model_copy(update={"case_id": f"custom_{n:04d}"}) for n in range(518)]
            (root / "output.csv").write_text("previous validated artifact", encoding="utf-8")
            args = argparse.Namespace(samples=False, model="test-replay", timeout=10, limit=1,
                                      max_decisions=8, case_id="", smoke=False)
            with patch.object(fixture.dataset, "requests", return_value=requests), \
                 patch("ghost_audit.cli.ClaudeRuntime", OfflineRuntime), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_audit(args, root, fixture.dataset), 2)
            self.assertEqual((root / "output.csv").read_text(), "previous validated artifact")
