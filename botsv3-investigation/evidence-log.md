# Evidence log

## Handling standard

The six committed JSONL files are selected BOTSv3-derived event extracts.
Their upstream source paths and original Git blob SHAs are recorded in
[dataset provenance](dataset-provenance.md).

The AWS CloudTrail fixture has been modified to replace temporary AWS access
key identifiers with stable redaction labels after GitHub secret scanning
raised alerts. The other event fields remain as supplied by the source
extracts. The local pipeline calculates SHA-256 for the exact current files.

## Fixture register

| Evidence ID | Source | Local reference | Evidential use | Status |
|---|---|---|---|---|
| E-001 | AWS CloudTrail | [01-aws-recon-bstoll.jsonl](data/fixtures/01-aws-recon-bstoll.jsonl), lines 1 to 20 | Console sign-ins, MFA metadata and S3 ACL calls attributed to `bstoll` | Collected, AWS identifiers redacted |
| E-002 | Windows logon metadata | [02-bstoll-l-endpoint.jsonl](data/fixtures/02-bstoll-l-endpoint.jsonl), lines 1 to 11 | Selected BSTOLL-L logon records | Collected fixture extract |
| E-003 | DNS | [03-bstoll-coinhive-cryptojacking.jsonl](data/fixtures/03-bstoll-coinhive-cryptojacking.jsonl), lines 1 to 12 | Coinhive-related DNS queries and responses | Collected fixture extract |
| E-004 | Sysmon | [04-fyodor-powershell-empire.jsonl](data/fixtures/04-fyodor-powershell-empire.jsonl), lines 1 to 4 | PowerShell process creation records | Collected fixture extract |
| E-005 | Azure AD sign-ins | [05-azure-ad-signin-anomaly.jsonl](data/fixtures/05-azure-ad-signin-anomaly.jsonl), lines 1 to 20 | Selected successful and failed sign-in records | Collected fixture extract |
| E-006 | Office 365 management | [06-o365-cloud-account-abuse.jsonl](data/fixtures/06-o365-cloud-account-abuse.jsonl), lines 1 to 16 | Sharing link and Exchange mailbox operations | Collected fixture extract |

The evidence IDs refer to fixture slices. They are not finding IDs or Splunk search job identifiers.
Line numbers refer to the current committed local files.

## Reproducible local outputs

Run `python pipeline/analyze.py` from this directory. It generates:

- `output/fixture-integrity.json`
- `output/inventory.json`
- `output/normalized-events.csv`
- `output/timeline.json`

These are derived artefacts. The JSONL fixtures remain the source records.

The successful workflow run processed the six committed extracts and produced
an inventory of 83 records. The generated UTC timeline contains 36 records;
47 records have no usable timestamp and remain available in the normalized
CSV. The pipeline does not assign times to those records.

## Integrity procedure for future exports

1. Preserve the original export without editing it.
2. Record its filename, format, size and acquisition time.
3. Calculate SHA-256 before analysis.
4. Create a separate working copy for parsing, filtering or redaction.
5. Record each transformation and the output hash.
6. Retain the exact SPL and search time range with the export.

PowerShell:

```powershell
Get-FileHash .\\event-export.csv -Algorithm SHA256
```

macOS or Linux:

```bash
shasum -a 256 event-export.csv
```

Never invent a hash or reuse a hash from a different version of a file.

## Evidence traceability

Each evidence ID maps to a committed JSONL fixture and a one-based record range. The investigation report cites these IDs directly so that each observation can be traced back to its source records. Derived pipeline outputs retain fixture names and source line references.
