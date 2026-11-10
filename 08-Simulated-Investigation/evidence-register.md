# Evidence Register

<sub>Northstar Logistics · Synthetic evidence catalogue</sub>

The records below are fictional evidence descriptions created for this case study. They are not raw event exports or screenshots.

| ID | Source | Simulated observation | Supports | Limitation |
|---|---|---|---|---|
| E-001 | Windows Security, NS-DC01, Event ID 4624 | `svc-backup` network logon from NS-WS044 at 08:17 UTC | F-01 | Does not prove how credentials were obtained |
| E-002 | Windows Security, NS-FS01, Event IDs 4624/4672 | Privileged logon session at 08:19 UTC | F-01 | Privilege assignment does not by itself prove abuse |
| E-003 | Sysmon, NS-FS01, Event ID 1 | `wmiprvse.exe` spawns `cmd.exe`, followed by PowerShell | F-02 | Process lineage does not independently identify the remote operator |
| E-004 | Sysmon, NS-FS01, Event ID 1 | Host/domain discovery command line | F-02, F-03 | Command line context is required; commands may be legitimate |
| E-005 | PowerShell Operational, NS-FS01, Event ID 4104 | Script-block records enumerate users, domain and services | F-03 | Incomplete script context; no complete script hash |
| E-006 | Sysmon, NS-FS01, Event ID 10 | Unsigned temporary process accesses `lsass.exe` | F-04 | No memory image or recovered credential evidence |
| E-007 | Windows Security, NS-WEB01, Event ID 4624 | `svc-backup` network logon from NS-FS01 at 08:43 UTC | F-05 | Does not prove interactive control or malicious intent |
| E-008 | File auditing, NS-FS01 | Finance documents accessed at 08:47 UTC | F-05 | Access does not prove all file contents were read |
| E-009 | Sysmon, NS-FS01, Event ID 11 / file audit | Copies created in `C:\ProgramData\Cache\` | F-05 | Local staging does not prove exfiltration |
| E-010 | Network telemetry, NS-FS01 | Outbound TCP connection attempt to 198.51.100.27:8443 | F-06 | No payload or successful transfer evidence |

## Evidence handling standard for a real investigation

For each collected artefact, record:

- Unique evidence identifier.
- Original source system and collection method.
- Collector, collection timestamp and time zone.
- Original file name, size and cryptographic hash (SHA-256 preferred).
- Storage location and access controls.
- Any parsing, filtering, conversion or transformation performed.
- Chain-of-custody transfers and timestamps.

Preserve original exports read-only. Perform parsing and analysis on working copies. Record the exact query, time range, index, sourcetype and field extractions used to produce each result.

## Synthetic versus observed evidence

Nothing in this register should be described as personally observed, collected or validated. If this project later incorporates real lab evidence, create a separate evidence register with actual source references and hashes. Do not silently replace these synthetic entries with real data or mix the two evidence classes.
