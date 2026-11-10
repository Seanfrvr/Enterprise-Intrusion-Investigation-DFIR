#!/usr/bin/env python3
"""Offline analysis of the committed, attributed BOTSv3 fixture extracts.

This does not download BOTSv3 or query Splunk. It parses only the six small
fixture slices in ../data/fixtures and emits reproducible inventory/timeline
artifacts. The pipeline reads the committed fixture files without modifying them. The AWS source fixture has been sanitized before commit; see dataset-provenance.md.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "fixtures"
OUT = ROOT / "output"
SOURCE_MAP = {
    "01-aws-recon-bstoll.jsonl": "aws:cloudtrail",
    "02-bstoll-l-endpoint.jsonl": "_json",
    "03-bstoll-coinhive-cryptojacking.jsonl": "stream:dns",
    "04-fyodor-powershell-empire.jsonl": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "05-azure-ad-signin-anomaly.jsonl": "ms:aad:signin",
    "06-o365-cloud-account-abuse.jsonl": "ms:o365:management",
}

def read_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for filename, source_type in SOURCE_MAP.items():
        path = FIXTURES / filename
        if not path.exists():
            raise FileNotFoundError(f"Missing fixture: {path}")
        with path.open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                event["_fixture"] = filename
                event["_fixture_line"] = line_no
                event["_source_sourcetype"] = event.get("_sourcetype", source_type)
                events.append(event)
    return events

def parse_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("eventTime") or event.get("_time")
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def first(*values: Any) -> str:
    for value in values:
        if value is not None and value != "":
            if isinstance(value, (dict, list)):
                return json.dumps(value, sort_keys=True)
            return str(value)
    return ""

def normalize(event: dict[str, Any]) -> dict[str, str]:
    identity = event.get("userIdentity") or {}
    location = event.get("location") or {}
    request = event.get("requestParameters") or {}
    ts = parse_time(event)
    user = first(identity.get("userName"), event.get("userPrincipalName"),
                 event.get("UserId"), event.get("User"), event.get("Account_Name"))
    ip = first(event.get("sourceIPAddress"), event.get("ipAddress"),
               event.get("ClientIP"), event.get("src_ip"))
    action = first(event.get("eventName"), event.get("Operation"),
                   event.get("EventCode"), event.get("name"))
    target = first(request.get("bucketName"), event.get("ObjectId"),
                   event.get("SourceFileName"), event.get("Image"))
    host = first(event.get("_host"), event.get("host"), event.get("Computer"))
    return {
        "timestamp_utc": ts.isoformat().replace("+00:00", "Z") if ts else "",
        "fixture": event["_fixture"],
        "fixture_line": str(event["_fixture_line"]),
        "sourcetype": first(event.get("_source_sourcetype")),
        "host": host,
        "user": user,
        "src_ip": ip,
        "action": action,
        "target": target,
        "result": first((event.get("responseElements") or {}).get("ConsoleLogin"),
                        event.get("loginStatus"), event.get("ResultStatus"),
                        event.get("reply_code")),
        "country": first(location.get("country")),
        "event_id": first(event.get("eventID"), event.get("requestID")),
    }

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    events = read_events()
    OUT.mkdir(parents=True, exist_ok=True)

    hashes = []
    for filename in SOURCE_MAP:
        data = (FIXTURES / filename).read_bytes()
        hashes.append({"file": filename, "bytes": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "records": sum(1 for line in data.splitlines() if line.strip())})
    (OUT / "fixture-integrity.json").write_text(
        json.dumps({"scope": "committed fixture extracts only", "files": hashes},
                   indent=2) + "\n", encoding="utf-8")

    normalized = [normalize(event) for event in events]
    normalized.sort(key=lambda row: (row["timestamp_utc"] or "9999", row["fixture"], int(row["fixture_line"])))
    with (OUT / "normalized-events.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(normalized[0]) if normalized else [])
        if normalized:
            writer.writeheader()
            writer.writerows(normalized)

    source_counts = Counter(row["sourcetype"] for row in normalized)
    fixture_counts = Counter(row["fixture"] for row in normalized)
    user_sources: dict[str, set[str]] = defaultdict(set)
    ip_users: dict[str, set[str]] = defaultdict(set)
    for row in normalized:
        if row["user"] and row["sourcetype"]:
            user_sources[row["user"]].add(row["sourcetype"])
        if row["src_ip"] and row["user"]:
            ip_users[row["src_ip"]].add(row["user"])

    inventory = {
        "scope": "six selected public BOTSv3-derived fixture slices; not full index inventory",
        "total_fixture_events": len(events),
        "by_fixture": dict(sorted(fixture_counts.items())),
        "by_sourcetype": dict(sorted(source_counts.items())),
        "users_by_sourcetype": {k: sorted(v) for k, v in sorted(user_sources.items())},
        "shared_source_ips_and_users": {
            k: sorted(v) for k, v in sorted(ip_users.items()) if len(v) > 1
        },
        "limitations": [
            "Fixture slices are partial and curated; counts are not BOTSv3 dataset totals.",
            "Some endpoint and DNS fixtures lack timestamps; they remain in normalized output without an invented time.",
            "Identity and IP correlations are investigative pivots, not proof of common control or compromise.",
            "The endpoint logon fixture is a narrow excerpt and cannot establish the absence of other logon types in the full dataset."
        ]
    }
    (OUT / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")

    # Timeline rows retain source fixture and line number so every row is traceable.
    timeline = [row for row in normalized if row["timestamp_utc"]]
    (OUT / "timeline.json").write_text(json.dumps({
        "scope": "timestamped records in the committed fixture slices",
        "timezone": "UTC",
        "events": timeline
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Parsed {len(events)} records from {len(SOURCE_MAP)} fixture extracts.")
    print(f"Wrote integrity, inventory, normalized CSV and timeline to {OUT}.")
    if args.verify_only:
        print("Verification mode: fixture parsing and artifact generation completed.")

if __name__ == "__main__":
    main()
