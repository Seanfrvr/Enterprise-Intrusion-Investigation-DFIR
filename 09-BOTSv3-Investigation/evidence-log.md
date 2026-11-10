# Evidence Log

## Evidence handling

This log is the authoritative register for artefacts collected during the BOTSv3 investigation. Add an entry only after the underlying record or export has actually been acquired and reviewed.

Do not populate event IDs, timestamps, IP addresses, usernames, hashes or query results from assumptions or third-party walkthroughs.

## Evidence register

| Evidence ID | Source / sourcetype | Host / entity | Event time (UTC) | Search ID | Artefact | SHA-256 | Status |
|---|---|---|---|---|---|---|---|
| E-001 | Pending | Pending | Pending | Pending | Pending | Pending | Not collected |
| E-002 | Pending | Pending | Pending | Pending | Pending | Pending | Not collected |
| E-003 | Pending | Pending | Pending | Pending | Pending | Pending | Not collected |

Replace the placeholder rows with actual records. Do not leave placeholder entries in a final published evidence register.

## Search execution log

| Hunt ID | Executed (UTC) | Exact time range | SPL file / query | Search job ID | Result count | Outcome |
|---|---|---|---|---|---:|---|
| H-001 | Pending | Pending | Pending | Pending | Pending | Not executed |
| H-002 | Pending | Pending | Pending | Pending | Pending | Not executed |

## Artefact integrity

For each exported result:
1. Preserve the original export without editing it.
2. Record the export format, filename, size and acquisition time.
3. Calculate SHA-256 locally.
4. Work from a separate analysis copy if transformation is required.
5. Record any parsing, redaction, normalisation or filtering applied.
6. Keep the exact SPL and time range with the export.

Example commands for local hashing:

**Windows PowerShell**
```powershell
Get-FileHash .\event-export.csv -Algorithm SHA256
```

**Linux**
```bash
sha256sum event-export.csv
```

The resulting digest must be copied from the actual command output. Never invent or manually construct a hash.

## Event reference format

Use a stable reference for each material event, for example:

`E-001 | index=botsv3 | sourcetype=<actual sourcetype> | host=<actual host> | _time=<actual timestamp> | <event identifier>`

Include the event's relevant identifying fields. Avoid copying entire records when a focused excerpt is sufficient.

## Analyst notes

For each evidence item, document:
- Why it was collected.
- Which hypothesis it addresses.
- What it directly establishes.
- What it does not establish.
- Related evidence IDs.
- Any parsing or time-zone caveat.
- Whether another analyst can reproduce the result.

## Screenshots

Screenshots are supplementary evidence of the analyst's workflow and Splunk interface. They do not replace exported events or reproducible searches.

Capture screenshots after executing the searches locally. Include the search bar, time range, result count and relevant event fields where practical. Avoid exposing credentials, tokens or unrelated personal information.
