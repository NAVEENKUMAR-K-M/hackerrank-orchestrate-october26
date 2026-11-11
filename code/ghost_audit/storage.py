"""Atomic local artifacts and narrowly-scoped dataset access."""
from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .models import Request

INPUTS = {"deletion_requests.csv", "sample_deletion_requests.csv", "user_identities.csv",
          "user_audit_log.csv", "system_activity.csv", "deletion_rules.csv", "evidence_files.csv"}


def digest(value: bytes | str | Any) -> str:
    if not isinstance(value, (bytes, str)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def write_json(path: Path, value: Any) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


class Dataset:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def csv(self, name: str) -> list[dict[str, str]]:
        if name not in INPUTS:
            raise ValueError(f"Prediction input is not allowlisted: {name}")
        with (self.root / name).open(encoding="utf-8-sig", newline="") as stream:
            return list(csv.DictReader(stream))

    def requests(self, samples: bool = False) -> list[Request]:
        requests = [Request.model_validate(row) for row in self.csv(
            "sample_deletion_requests.csv" if samples else "deletion_requests.csv")]
        if len({r.case_id for r in requests}) != len(requests):
            raise ValueError("Duplicate request case IDs")
        return sorted(requests, key=lambda r: r.case_id)

    def evidence_path(self, relative: str) -> Path:
        path = (self.root / relative).resolve()
        evidence_root = (self.root / "evidence").resolve()
        if not path.is_relative_to(evidence_root) or not path.is_file():
            raise ValueError("Evidence path escapes dataset/evidence or does not exist")
        return path

    def fingerprint(self, samples: bool = False) -> str:
        names = sorted(INPUTS - {"sample_deletion_requests.csv", "deletion_requests.csv"})
        names.append("sample_deletion_requests.csv" if samples else "deletion_requests.csv")
        items = [(name, digest((self.root / name).read_bytes())) for name in names]
        items += [(row["file_path"], digest(self.evidence_path(row["file_path"]).read_bytes()))
                  for row in self.csv("evidence_files.csv")]
        return digest(items)
