"""Format adapters. Every state is grounded in a supplied readback or snapshot."""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .identity import identifiers_in
from .models import Observation, SnapshotScope
from .storage import digest

PARSER_VERSION = digest(Path(__file__).read_bytes())
CATEGORIES = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "profile_lookups": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "index_queries": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "exports": ("export_service", "USER_EXPORT"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "connectors": ("integration_service", "DATA_FLOW"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery_logs": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "legal_hold_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "product_telemetry": ("analytics_platform", "PRODUCT_TELEMETRY"),
    "cache_entries": ("cache_service", "CACHE_ENTRY"),
    "secondary_identifiers": ("identity_service", "SECONDARY_IDENTIFIER"),
    "support_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
}
PREFIXES = {
    "account": ("account_service", "USER_PROFILE"), "profile": ("profile_service", "USER_PROFILE"),
    "search": ("search_service", "SEARCH_INDEX_ENTRY"),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support": ("support_platform", "SUPPORT_MESSAGE"),
    "export": ("export_service", "USER_EXPORT"),
    "data_flow": ("integration_service", "DATA_FLOW"), "backup": ("backup_service", "BACKUP_ARCHIVE"),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG"),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "marketing": ("marketing_platform", "MARKETING_PROFILE"), "cache": ("cache_service", "CACHE_ENTRY"),
    "object": ("object_storage", "SUPPORT_ATTACHMENT"),
    "notification": ("notification_service", "EMAIL_DELIVERY_LOG"),
    "delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "email_delivery": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "legal": ("legal_service", "LEGAL_HOLD_RECORD"),
    "legal_hold": ("legal_service", "LEGAL_HOLD_RECORD"),
    "telemetry": ("analytics_platform", "PRODUCT_TELEMETRY"),
    "identifier": ("identity_service", "SECONDARY_IDENTIFIER"),
    "secondary_identifier": ("identity_service", "SECONDARY_IDENTIFIER"),
}
STATE_ALIASES = {"FOUND": "PRESENT", "NOT_FOUND": "ABSENT", "IDENTIFIABLE": "IDENTIFIABLE",
                 "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED", "ACTIVE": "ACTIVE",
                 "DISABLED": "DISABLED", "BLOCKED": "BLOCKED", "PRESENT": "PRESENT", "ABSENT": "ABSENT"}


def describe(resource: str, collection: str = "", system: str = "") -> tuple[str, str]:
    matched = CATEGORIES.get(collection)
    if matched:
        return system or matched[0], matched[1]
    prefix = resource.rsplit("_", 1)[0]
    matched = PREFIXES.get(prefix, (system, "UNKNOWN"))
    if system == "analytics_platform" and collection == "profiles":
        return system, "ANALYTICS_PROFILE"
    return system or matched[0], matched[1]


def flat_fields(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    for key in ("profile", "document"):
        if isinstance(value.get(key), dict):
            result.update(value[key])
    hits = value.get("hits")
    if isinstance(hits, dict) and hits.get("documents"):
        result.update(hits["documents"][0])
    return result


def truth(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value in (1, "1", "true", "True", "yes"):
        return True
    if value in (0, "0", "false", "False", "no"):
        return False
    return None


def record_state(fields: dict[str, Any], category: str) -> tuple[str, bool]:
    explicit = STATE_ALIASES.get(str(fields.get("result", "")).upper())
    if explicit:
        return explicit, True
    if str(fields.get("status_code", fields.get("http_status", ""))) == "404":
        return "ABSENT", False
    if category == "DATA_FLOW":
        enabled = truth(fields.get("enabled"))
        return ("ACTIVE" if enabled else "DISABLED", False) if enabled is not None else ("UNKNOWN", False)
    if category == "BACKUP_ARCHIVE":
        allowed = truth(fields.get("restore_allowed", fields.get("eligible")))
        if truth(fields.get("deletion_block")) is True:
            allowed = False
        return ("ACTIVE" if allowed else "BLOCKED", False) if allowed is not None else ("UNKNOWN", False)
    hits = fields.get("hits")
    if isinstance(hits, dict) and hits.get("total") == 0:
        return "ABSENT", False
    if fields.get("profile", "non_null") is None:
        return "ABSENT", False
    return "PRESENT", False


@dataclass
class Parsed:
    observations: list[Observation] = field(default_factory=list)
    scopes: list[SnapshotScope] = field(default_factory=list)
    text: str = ""
    needs_interpretation: bool = False


class Adapter:
    def __init__(self, manifest: dict[str, str]):
        self.manifest = manifest
        self.file_id = manifest["file_id"]
        self.capture = manifest["captured_at"]
        self.parsed = Parsed()

    def add(self, record: dict[str, Any], locator: str, system: str = "", collection: str = "",
            observed: str = "", replica: str = "", category: str = "") -> None:
        resource = str(record.get("resource_id", ""))
        if not resource:
            return
        # A record naming its own system outranks the store that happened to export it.
        system, inferred = describe(resource, collection, str(record.get("system") or system))
        category = category or str(record.get("record_type", inferred))
        fields = flat_fields(record)
        state, explicit = record_state(fields, category)
        if explicit and "record_type" in fields:
            fields["_lookup_metadata"] = True
        observed = observed or str(record.get("observed_at", record.get("recorded_at", self.capture)))
        self.parsed.observations.append(Observation(
            observation_id=digest([self.file_id, locator, resource, observed])[:24],
            evidence_id=self.file_id, locator=locator, system_id=system, resource_id=resource,
            category=category, observed_at=observed, captured_at=self.capture, state=state,
            replica=replica, identifiers=sorted(identifiers_in(fields)), fields=fields,
            explicit_state=explicit))

    def scope(self, system: str, category: str, locator: str, resources: list[str],
              observed: str = "", replica: str = "", complete: bool = True) -> None:
        self.parsed.scopes.append(SnapshotScope(
            evidence_id=self.file_id, locator=locator, system_id=system, category=category,
            captured_at=self.capture, observed_at=observed or self.capture,
            replica=replica, resources=resources, complete=complete))


def parse_json(path: Path, manifest: dict[str, str]) -> Parsed:
    adapter = Adapter(manifest)
    adapter.parsed.text = path.read_text(encoding="utf-8")
    data = json.loads(adapter.parsed.text)
    if "snapshots" in data:
        for i, snapshot in enumerate(data["snapshots"]):
            system, collection = snapshot["data_store"], snapshot["collection"]
            observed = snapshot.get("captured_at", adapter.capture)
            for j, record in enumerate(snapshot["records"]):
                adapter.add(record, f"$.snapshots[{i}].records[{j}]", system, collection, observed)
            # A bundled collection is not an explicit global negative lookup.
    elif "service_exports" in data:
        for system, collections in data["service_exports"].items():
            for collection, records in collections.items():
                for i, record in enumerate(records):
                    adapter.add(record, f"$.service_exports.{system}.{collection}[{i}]", system, collection)
    elif "records" in data:
        for i, record in enumerate(data["records"]):
            canonical = CATEGORIES.get(data.get("collection", ""), ("", ""))[0]
            adapter.add(record, f"$.records[{i}]", canonical,
                        data.get("collection", ""), data.get("captured_at", ""))
    else:
        adapter.parsed.needs_interpretation = True
    return adapter.parsed


def sql_connection(text: str) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA temp_store=MEMORY")
    forbidden = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_CREATE_VTABLE}
    def authorize(action: int, arg1: str, arg2: str, database: str, trigger: str) -> int:
        if action in forbidden or (action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in
                                   {"load_extension", "writefile", "readfile"}):
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA and str(arg1).lower() not in {"foreign_keys", "defer_foreign_keys"}:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    connection.set_authorizer(authorize)
    try:
        connection.executescript(text)
    except sqlite3.Error:
        connection.close()
        raise
    connection.set_authorizer(None)
    return connection


def parse_sql(path: Path, manifest: dict[str, str]) -> Parsed:
    adapter = Adapter(manifest)
    adapter.parsed.text = path.read_text(encoding="utf-8")
    connection = sql_connection(adapter.parsed.text)
    try:
        tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        scope_systems = {r[0] for r in connection.execute("SELECT origin_system FROM snapshot_scope")} if "snapshot_scope" in tables else None
        for table in tables:
            if table != "snapshot_scope":
                _sql_table(connection, table, adapter, scope_systems)
    finally:
        connection.close()
    return adapter.parsed


def _sql_table(connection: sqlite3.Connection, table: str, adapter: Adapter,
               scope_systems: set[str] | None) -> None:
    escaped = table.replace('"', '""')
    records = [dict(row) for row in connection.execute(f'SELECT * FROM "{escaped}"')]
    replica = table if any(word in table for word in ("primary", "replica")) else ""
    if records and "record_json" in records[0]:
        for row in records:
            adapter.add(json.loads(row["record_json"]), f"{table}:{row['resource_id']}",
                        row["origin_system"], row["collection_name"], adapter.capture, replica)
        adapter.scope("*", "*", table, [r["resource_id"] for r in records], replica=replica)
        return
    system, category = CATEGORIES.get(table, ("", "UNKNOWN"))
    if table.startswith("customer_profiles_"):
        system, category = CATEGORIES["customer_profiles"]
    for row in records:
        adapter.add(row, f"{table}:{row['resource_id']}", system, table, adapter.capture, replica, category)
    if system and (scope_systems is None or system in scope_systems):
        adapter.scope(system, category, table, [r["resource_id"] for r in records], replica=replica)


KV = re.compile(r'(\w+)=("(?:\\.|[^"\\])*"|[^\s]+)')
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z")
PIPE = re.compile(r"^\S+Z \| (\w+) \| (\w+) \| (\S+) \| (\w+) \| ?(.*)$")


def log_attributes(line: str) -> dict[str, Any]:
    attributes: dict[str, Any] = {}
    match = STAMP.match(line)
    if match:
        attributes["timestamp"] = match.group()
    pipe = PIPE.match(line)
    if match and line[match.end():].lstrip().startswith("{"):
        attributes.update(json.loads(line[match.end():].strip()))
    elif pipe:
        attributes.update(level=pipe[1], service=pipe[2], trace_id=pipe[3], event=pipe[4])
        for key, value in KV.findall(pipe[5]):
            try:
                attributes[key] = json.loads(value)
            except json.JSONDecodeError:
                attributes[key] = value
    else:
        for key, value in KV.findall(line):
            try:
                attributes[key] = json.loads(value)
            except json.JSONDecodeError:
                attributes[key] = value
    if "message" in attributes and isinstance(attributes["message"], str):
        attributes.update(log_attributes(attributes["message"]))
    if "function" in attributes:
        attributes.setdefault("service", attributes["function"])
    application = re.search(r"\[(?:DEBUG|INFO|WARN|ERROR)\]\s+\[([^]]+)\]\s+\[([^]]+)\]\s+(\w+):", line)
    if application:
        attributes.update(service=application[1], trace_id=application[2], event=application[3])
    syslog = re.search(r"<\d+>1\s+\S+\s+(\w+)\s+(\S+)\s+-\s+-", line)
    if syslog:
        attributes.update(service=syslog[1], trace_id=syslog[2])
    if "requestId" in attributes:
        attributes.setdefault("trace_id", attributes["requestId"])
    return attributes


def _log_state(fields: dict[str, Any], category: str) -> str:
    event = str(fields.get("event", "")).lower()
    if event == "record_lookup":
        state, explicit = record_state(fields, category)
        return state if explicit else "UNKNOWN"
    if event == "deletion_marker_check":
        marker = truth(fields.get("marker_found"))
        return "UNKNOWN" if marker is None else ("ABSENT" if marker else "PRESENT")
    if "export_download_check" in event:
        available = truth(fields.get("available"))
        return "UNKNOWN" if available is None else ("PRESENT" if available else "ABSENT")
    if event == "restore_authorization_completed":
        return {"deny": "BLOCKED", "allow": "ACTIVE"}.get(str(fields.get("decision", "")).lower(), "UNKNOWN")
    if event in {"analytics_profile_read", "message_read", "retained_order_loaded"}:
        return "PRESENT"
    if event in {"message_pii_scan", "attachment_pii_scan", "analytics_identity_scan", "email_pii_scan"}:
        return "IDENTIFIABLE" if fields.get("matched_value") or truth(fields.get("direct_identifiers")) else "UNKNOWN"
    if category == "DATA_FLOW" and ("connector" in event or "flow" in event):
        return record_state(fields, category)[0]
    if category == "BACKUP_ARCHIVE" and ("restore" in event or "backup" in event):
        return record_state(fields, category)[0]
    if not any(word in event for word in ("lookup_completed", "query_completed", "read_completed",
                                          "inspection_completed", "delivery_log_read", "export_lookup")):
        return "UNKNOWN"
    if fields.get("rows") in (0, "0") or fields.get("total_hits") in (0, "0"):
        return "ABSENT"
    if str(fields.get("result", "")).lower() in ("miss", "not_found"):
        return "ABSENT"
    return "PRESENT"


def parse_log(path: Path, manifest: dict[str, str]) -> Parsed:
    adapter = Adapter(manifest)
    adapter.parsed.text = path.read_text(encoding="utf-8")
    traces: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(adapter.parsed.text.splitlines(), 1):
        attributes = log_attributes(line)
        trace = str(attributes.get("trace_id", ""))
        inherited = {key: value for key, value in traces.get(trace, {}).items()
                     if key in {"lookup_key", "subject_key", "match_key", "subject_ref", "correlation_key", "resource_id", "_category"}}
        event = str(attributes.get("event", ""))
        if event.endswith("_started") and any(word in event for word in ("lookup", "query", "read", "scan")):
            inherited = {}
        merged = {**inherited, **attributes} if trace else attributes
        if trace:
            traces[trace] = merged
        resource = str(merged.get("resource_id", ""))
        if not resource or not merged.get("timestamp"):
            continue
        service = str(merged.get("service", ""))
        system, category = describe(resource, system=service)
        known_prefix = PREFIXES.get(resource.rsplit("_", 1)[0])
        if merged.get("system"):
            system = str(merged["system"])
        elif known_prefix and "replica" not in service:
            system = known_prefix[0]
        if merged.get("record_type"):
            category = str(merged["record_type"])
        elif known_prefix:
            category = known_prefix[1]
        replica = ""
        if "replica" in service and manifest["origin"] in {v[0] for v in CATEGORIES.values()}:
            system, replica = manifest["origin"], service
        if "contact_lookup" in str(merged.get("event", "")) or "contact_query" in str(merged.get("event", "")):
            category = "SECONDARY_IDENTIFIER"
            if trace:
                traces[trace]["_category"] = category
        elif merged.get("event") == "deletion_marker_check" and traces.get(trace, {}).get("_category"):
            category = traces[trace]["_category"]
        state = _log_state(merged, category)
        if state == "UNKNOWN":
            continue
        adapter.add(merged, f"line:{number}", system, observed=merged["timestamp"], category=category, replica=replica)
        adapter.parsed.observations[-1].state = state
    return adapter.parsed


def parse_text(path: Path, manifest: dict[str, str]) -> Parsed:
    adapter = Adapter(manifest)
    adapter.parsed.text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"^- (\S+) \| (\w+) \| (\w+) \| (\w+) \| (\w+) \| (.+)$", re.M)
    for number, match in enumerate(pattern.finditer(adapter.parsed.text), 1):
        observed, system, resource, category, result, reference = match.groups()
        adapter.add({"resource_id": resource, "record_type": category, "result": result,
                     "subject_reference": reference}, f"entry:{number}", system, observed=observed)
    adapter.parsed.needs_interpretation = not bool(adapter.parsed.observations)
    return adapter.parsed


def parse_artifact(path: Path, manifest: dict[str, str]) -> Parsed:
    parsers = {".json": parse_json, ".sql": parse_sql, ".log": parse_log, ".txt": parse_text}
    if path.suffix in parsers:
        return parsers[path.suffix](path, manifest)
    if path.suffix == ".pdf":
        from pypdf import PdfReader
        reader = PdfReader(path)
        text = "\n".join(f"PAGE {n}\n{page.extract_text() or ''}" for n, page in enumerate(reader.pages, 1))
        return Parsed(text=text, needs_interpretation=True)
    if path.suffix == ".png":
        from PIL import Image
        with Image.open(path) as image:
            image.verify()
        return Parsed(needs_interpretation=True)
    raise ValueError(f"Unsupported evidence format: {path.suffix}")
