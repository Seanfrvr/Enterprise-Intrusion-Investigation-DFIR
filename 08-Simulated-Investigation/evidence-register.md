# Evidence Register
### Northstar Logistics | Evidence Reference Catalogue

The register provides traceable references for the observations discussed in the findings. Primary event exports, raw records and collection hashes are not currently included in this portfolio version; the descriptions below are illustrative evidence summaries, not retained forensic artefacts.

| ID | Source / host | Evidence summary | Finding | Limitation |
|---|---|---|---|---|
| E-001 | Windows Security · NS-DC01 · Event ID 4624 | `svc-backup` network logon from NS-WS044 at 08:17 UTC | F-01 | Does not identify how credentials were obtained |
| E-002 | Windows Security · NS-FS01 · Event IDs 4624/4672 | Privileged logon session at 08:19 UTC | F-01 | Privileged session alone does not establish malicious use |
| E-003 | Sysmon · NS-FS01 · Event ID 1 | `WmiPrvSE.exe` process lineage to command shell and PowerShell | F-02 | Does not independently identify the remote operator |
| E-004 | Sysmon · NS-FS01 · Event ID 1 | Host and domain discovery command context | F-02, F-03 | Commands require user, parent process and host context |
| E-005 | PowerShell Operational · NS-FS01 · Event ID 4104 | Script-block content describing user, domain and service enumeration | F-03 | Full script and hash are not available |
| E-006 | Sysmon · NS-FS01 · Event ID 10 | Unusual temporary executable accesses `lsass.exe` | F-04 | No memory image or recovered credential material |
| E-007 | Windows Security · NS-WEB01 · Event ID 4624 | `svc-backup` network logon from NS-FS01 at 08:43 UTC | F-05 | Does not alone prove interactive control or malicious intent |
| E-008 | File auditing · NS-FS01 | Finance document access at 08:47 UTC | F-05 | Access does not prove full content was read |
| E-009 | Sysmon Event ID 11 / file auditing · NS-FS01 | File copies created in `C:\ProgramData\Cache\` | F-05 | Local staging does not prove exfiltration |
| E-010 | Network telemetry · NS-FS01 | Outbound TCP connection attempt to 198.51.100.27:8443 | F-06 | No payload or successful transfer evidence |

## Evidence handling requirements

For a production investigation, each artefact should include:

- Unique evidence identifier and description.
- Original source system, collection method and collector.
- Collection timestamp and time zone.
- Original file name, size and SHA-256 hash.
- Storage location, access controls and chain-of-custody history.
- Parsing, filtering, conversion or transformation steps.
- Exact query, time range, index, sourcetype and field extractions used to obtain the record.

Preserve original exports read-only and conduct analysis on working copies. Screenshots should retain enough context to identify the query, time range, source and relevant result fields while redacting sensitive information.

## Evidence status

This portfolio version contains evidence summaries rather than primary event exports or screenshots. The entries should not be treated as independently verified forensic artefacts. When primary telemetry becomes available, attach the original source references, hashes and reproducible search details to each evidence ID.
