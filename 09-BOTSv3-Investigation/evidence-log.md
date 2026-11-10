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
| F-01 | AWS CloudTrail | \`01-aws-recon-bstoll.jsonl:1 to 20\` | Console sign-ins, MFA metadata and S3 ACL calls attributed to \`bstoll\` | Collected, AWS identifiers redacted |
| F-02 | Windows logon metadata | \`02-bstoll-l-endpoint.jsonl:1 to 11\` | Selected BSTOLL-L logon records | Collected fixture extract |
| F-03 | DNS | \`03-bstoll-coinhive-cryptojacking.jsonl:1 to 12\` | Coinhive-related DNS queries and responses | Collected fixture extract |
| F-04 | Sysmon | \`04-fyodor-powershell-empire.jsonl:1 to 4\` | PowerShell process creation records | Collected fixture extract |
| F-05 | Azure AD sign-ins | \`05-azure-ad-signin-anomaly.jsonl:1 to 20\` | Selected successful and failed sign-in records | Collected fixture extract |
| F-06 | Office 365 management | \`06-o365-cloud-account-abuse.jsonl:1 to 16\` | Sharing link and Exchange mailbox operations | Collected fixture extract |

The IDs refer to fixture slices. They are not Splunk search job identifiers.
Line numbers refer to the current committed local files.

## Full-index search register

| Hunt | Search time (UTC) | Time range | Search job ID | Result count | Status |
|---|---|---|---|---:|---|
| H-001 onward | Not run | Not established | Not available | Not available | Pending full Splunk dataset |

Do not fill this table with estimated counts. Record the exact SPL and absolute
time range after each search has been executed. Preserve the export and its
SHA-256 hash.

## Reproducible local outputs

Run \`python pipeline/analyze.py\` from this directory. It generates:

- \`output/fixture-integrity.json\`
- \`output/inventory.json\`
- \`output/normalized-events.csv\`
- \`output/timeline.json\`

These are derived artefacts. The JSONL fixtures remain the source records.

## Integrity procedure for future exports

1. Preserve the original export without editing it.
2. Record its filename, format, size and acquisition time.
3. Calculate SHA-256 before analysis.
4. Create a separate working copy for parsing, filtering or redaction.
5. Record each transformation and the output hash.
6. Retain the exact SPL and search time range with the export.

PowerShell:

\`\`\`powershell
Get-FileHash .\\event-export.csv -Algorithm SHA256
\`\`\`

macOS or Linux:

\`\`\`bash
shasum -a 256 event-export.csv
\`\`\`

Never invent a hash or reuse a hash from a different version of a file.

## Screenshots

Capture screenshots only after running the search in Splunk. Include the
search bar, time range, result count and relevant fields where practical.
Screenshots supplement exported records and do not replace them.
