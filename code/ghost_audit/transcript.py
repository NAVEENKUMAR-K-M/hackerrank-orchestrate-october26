"""Append-only development transcript; audit runs have separate telemetry."""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def redact(text: str) -> str:
    text = re.sub(r"\b(?:sk|sess)-[A-Za-z0-9_-]{12,}", "[REDACTED]", text)
    text = re.sub(r"(?im)(authorization\s*[:=]\s*)(?:(?:Bearer|Basic)\s+)?[^\s,;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?im)((?:set-)?cookie\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)([?&](?:code|access_token|refresh_token|id_token|client_secret|api_key|token)=)[^&#\s]+",
                  r"\1[REDACTED]", text)
    text = re.sub(r"(?im)((?:api[_-]?key|access[_-]?token|password|authorization)\s*[:=]\s*)[^\s,;]+",
                  r"\1[REDACTED]", text)
    text = re.sub(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+\.[A-Za-z]{2,}", "[REDACTED EMAIL]", text)
    return re.sub(r"\+\d[\d ()-]{7,}\d", "[REDACTED PHONE]", text)


def runtime_metadata(root: Path) -> dict[str, str]:
    """Read authoritative fields only; never load or emit authentication files.

    A harness that cannot be introspected (Claude Code) supplies its own exact identity through
    LOG_TOOL and LOG_MODEL; otherwise the active Codex session file is the authority.
    """
    tool, model = os.environ.get("LOG_TOOL"), os.environ.get("LOG_MODEL")
    session_id = os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_SESSION_ID")
    if not (tool and model):
        if not session_id:
            raise ValueError("An authoritative coding-session ID is required for transcript logging")
        sessions = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "sessions"
        matches = list(sessions.rglob(f"*{session_id}*.jsonl"))
        if len(matches) != 1:
            raise ValueError("Cannot uniquely locate the active coding session")
        with matches[0].open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                payload = item.get("payload", {})
                if item.get("type") == "session_meta":
                    tool = payload.get("originator")
                elif item.get("type") == "turn_context":
                    model = payload.get("model")
    if not tool or not model or model == "unknown":
        raise ValueError("Missing authoritative harness or model identifier")
    branch = subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
    return {"tool": tool, "model": model, "branch": branch or "unknown",
            "repo_root": str(root.resolve()), "worktree": str(root.resolve()), "parent_agent": "none"}


def append_entry(root: Path, title: str, summary: str, actions: list[str],
                 prompt: str | None = None, excluded: bool = False) -> None:
    if excluded:
        return
    root = root.resolve()
    if not (root / "AGENTS.md").is_file():
        raise ValueError("Log must live beside the top-level AGENTS.md")
    meta = runtime_metadata(root)
    if len(title) > 80 or "\n" in title:
        raise ValueError("Entry title must fit on one line, at most 80 characters")
    when = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    entry = f"## [{when}] {title}\n\n"
    if prompt is not None:
        entry += f"User Prompt (verbatim, secrets redacted):\n{redact(prompt)}\n\n"
    entry += f"Agent Response Summary:\n{redact(summary)}\n\nActions:\n"
    entry += "".join(f"* {redact(action)}\n" for action in actions)
    context = "".join(f"{key}={value}\n" for key, value in meta.items())
    assert len(re.findall(r"^tool=.+$", context, re.M)) == 1
    assert len(re.findall(r"^model=.+$", context, re.M)) == 1
    entry += "\nContext:\n" + context + "\n"
    entry = entry.replace("\r\n", "\n").replace("\r", "\n")
    target = (root / "AGENTS.md").parent / "log.txt"
    before = target.read_bytes() if target.exists() else b""
    encoded = (("\n" if before and not before.endswith(b"\n") else "") + entry).encode("utf-8")
    with target.open("ab") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    after = target.read_bytes()
    if after != before + encoded:
        raise RuntimeError("Transcript append verification failed; prior entries must be preserved")
    reread = after[len(before):].decode("utf-8")
    if "\r" in reread or reread.rsplit("\nContext:\n", 1)[1] != context + "\n":
        raise RuntimeError("Transcript context or line-ending verification failed")
