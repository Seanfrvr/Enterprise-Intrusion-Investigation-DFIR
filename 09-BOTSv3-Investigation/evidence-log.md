# Evidence log

## Handling and provenance

The records in this workstream are six selected JSONL extracts copied without
content modification from the public source files listed in
[dataset provenance](dataset-provenance.md). Each local fixture is traceable
to an upstream Git blob SHA. The Python pipeline calculates SHA-256 for the
local bytes.

This register distinguishes **fixture records present in the repository**
from **Splunk search exports**, which have not yet been collected. Fixture
line numbers refer to the local JSONL files.

## Fixture evidence register

| Evidence ID | Source | Local fixture reference | What it supports | Status |
|---|---|---|---|---|
| F-01 | AWS CloudTrail | `01-aws-recon-bstoll.jsonl:1-20` | Console sign-ins, MFA metadata and S3 bucket ACL calls attributed to `bstoll` | Collected fixture extract |
| F-02 | Windows logon metadata | `02-bstoll-l-endpoint.jsonl:1-11` | Selected BSTOLL-L 4624 logon types and accounts | Collected fixture extract |
| F-03 | DNS | `03-bstoll-coinhive-cryptojacking.jsonl:1-12` | Queries and responses for Coinhive-related domains | Collected fixture extract |
| F-04 | Sysmon | `04-fyodor-powershell-empire.jsonl:1-4` | PowerShell process command lines on FYODOR-L and BGIST-L | Collected fixture extract |
| F-05 | Azure AD sign-in | `05-azure-ad-signin-anomaly.jsonl:1-20` | Selected successful and failed sign-in records and location/IP fields | Collected fixture extract |
| F-06 | Office 365 management | `06-o365-cloud-account-abuse.jsonl:1-16` | Anonymous sharing-link events and Exchange Set-Mailbox operations | Collected fixture extract |

These IDs refer to fixture extracts, not individual Splunk events. Use the
fixture filename and line number to locate a specific JSONL record.

## Splunk search execution log

| Hunt ID | Executed (UTC) | Exact time range | Search job ID | Result count | Status |
|---|---|---|---|---:|---|
| H-001 onward | — | — | — | — | Not executed against full index |

Do not populate this table until searches have actually been run in Splunk.
For each run, preserve the exact SPL, absolute time range, search job ID,
returned count, field validation notes and exported result filename.

## Local pipeline outputs

Running `python pipeline/analyze.py` generates:

- `output/fixture-integrity.json` — local byte counts and SHA-256 hashes.
- `output/inventory.json` — fixture-scoped record and sourcetype counts.
- `output/normalized-events.csv` — normalized view with fixture/line references.
- `output/timeline.json` — timestamped records sorted in UTC.

These are derived analysis artefacts. The original JSONL records remain the
source of truth.

## Integrity procedure

For each future Splunk export:

1. Preserve the original export without editing it.
2. Record the export format, filename, size and acquisition time.
3. Calculate SHA-256 locally.
4. Work from a separate analysis copy if transformation is required.
5. Record parsing, redaction, normalization or filtering.
6. Keep the exact SPL and time range with the export.

**Windows PowerShell**
```powershell
Get-FileHash .\\event-export.csv -Algorithm SHA256
```

**Linux**
```bash
sha256sum event-export.csv
```

Never invent or manually construct a hash.

## Screenshots

Screenshots supplement exported events and reproducible searches; they do not
replace them. Capture them after executing the searches locally. Include the
search bar, time range, result count and relevant event fields where practical.
Avoid exposing credentials, tokens or unrelated personal information.
