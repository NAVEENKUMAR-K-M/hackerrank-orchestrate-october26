"""Exact, timestamp-aware identity closure without fuzzy account merging."""
from __future__ import annotations

import re
import unicodedata

from .models import Request, Subject, utc
from .storage import Dataset

EMAIL = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+\.[A-Za-z]{2,}", re.UNICODE)
RESOURCE = re.compile(r"\b(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|marketing|cache|object|notification|email_delivery|delivery|legal_hold|legal|telemetry|secondary_identifier|identifier|profile)_(?=[A-Za-z0-9]*\d)[A-Za-z0-9]+\b")
USER = re.compile(r"\buser_[A-Za-z0-9]+\b")
HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")


def normalize(value: str) -> str:
    value = unicodedata.normalize("NFKC", str(value)).strip()
    if re.fullmatch(r"\+?[\d ()-]{8,}", value):
        return re.sub(r"\D", "", value)
    return value.casefold()


def identifiers_in(value: object) -> set[str]:
    if isinstance(value, dict):
        result: set[str] = set()
        for key, item in value.items():
            result |= identifiers_in(item)
            if isinstance(item, str) and any(k in key.lower() for k in ("phone", "mobile")):
                result.add(normalize(item))
        return result
    if isinstance(value, list):
        return set().union(*(identifiers_in(item) for item in value)) if value else set()
    if not isinstance(value, str):
        return set()
    return {normalize(m.group()) for pattern in (EMAIL, USER, HASH) for m in pattern.finditer(value)}


class Identities:
    def __init__(self, dataset: Dataset):
        self.snapshots = dataset.csv("user_identities.csv")
        self.history = dataset.csv("user_audit_log.csv")

    def resolve(self, request: Request) -> Subject:
        eligible = [r for r in self.history if utc(r["event_time"]) <= utc(request.audit_at)]
        requested = normalize(request.email)
        users = {r["user_id"] for r in self.snapshots
                 if utc(r["updated_at"]) <= utc(request.audit_at) and normalize(r["email"]) == requested}
        users |= {r["user_id"] for r in eligible if r["field_name"] == "email"
                  and requested in {normalize(r["old_value"]), normalize(r["new_value"])}}
        if len(users) != 1:
            raise ValueError(f"Expected one grounded subject, resolved {len(users)} for {request.case_id}")
        user_id = next(iter(users))
        aliases = {normalize(user_id), requested}
        names: set[str] = set()
        for row in self.snapshots:
            if row["user_id"] == user_id and utc(row["updated_at"]) <= utc(request.audit_at):
                aliases |= {normalize(row[k]) for k in ("email", "phone", "email_hash") if row[k]}
                names.add(row["name"])
        audit_ids = []
        for row in eligible:
            if row["user_id"] == user_id:
                audit_ids.append(row["audit_id"])
                if row["field_name"] in {"name", "full_name"}:
                    names |= {row[k] for k in ("old_value", "new_value") if row[k]}
                else:
                    aliases |= {normalize(row[k]) for k in ("old_value", "new_value") if row[k]}
        return Subject(user_id=user_id, identifiers=sorted(aliases), names=sorted(names), audit_ids=audit_ids)
