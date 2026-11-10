# Evidence Register
### Northstar Logistics | Evidence Reference Catalogue

This register links the case findings to the source types and event records required to test them. Primary event exports, raw records, collection hashes and original screenshots are not currently retained in this portfolio version. The summaries are illustrative evidence descriptions, not preserved forensic artefacts.

| ID | Source / host | Evidence summary | Supports | Key fields / validation | Limitation |
|---|---|---|---|---|---|
| E-001 | Windows Security · NS-DC01 · Event ID 4769 | Kerberos service-ticket request associated with `svc-backup`; client address associated with NS-WS044 | F-01 | Account, client address, service name/SPN, ticket options, timestamp | Ticket request alone does not prove successful logon to NS-FS01 |
| E-002 | Windows Security · NS-FS01 · Event IDs 4624 and 4672 | Network logon for `svc-backup` from NS-WS044, followed by privileged logon record | F-01 | TargetUserName, IpAddress, LogonType, TargetLogonId, SubjectLogonId, AuthenticationPackageName | Verify matching Logon ID and event sequence; privilege assignment alone does not prove abuse |
| E-003 | Sysmon · NS-FS01 · Event ID 1 | Process lineage involving `WmiPrvSE.exe`, `cmd.exe` and PowerShell | F-02 | UtcTime, User, Image, ParentImage, CommandLine, ProcessGuid, ParentProcessGuid, hashes | Process lineage alone does not identify remote WMI client |
| E-004 | WMI-Activity Operational and network telemetry · NS-FS01 | WMI operation/client context and supporting network activity around process execution | F-02 | ClientMachine, User, Operation, ClientProcessId where logged; source/destination addresses and ports | Provider event alone may not establish full remote execution chain; event availability varies |
| E-005 | PowerShell Operational · NS-FS01 · Event ID 4104 | Script-block content describing user, domain and service enumeration | F-03 | ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal, ProcessID, User | Partial records may omit script context; no complete script hash available |
| E-006 | Sysmon · NS-FS01 · Event ID 10; endpoint file metadata | Process from temporary path accesses `lsass.exe` | F-04 | SourceImage, SourceProcessGuid, SourceProcessId, TargetImage, GrantedAccess, CallTrace, signer, SHA-256 | Event ID 10 does not prove dumping or credential recovery |
| E-007 | Windows Security · NS-WEB01 · Event ID 4624 | Network logon for `svc-backup` from NS-FS01 | F-05 | TargetUserName, IpAddress, LogonType, TargetLogonId, AuthenticationPackageName | Logon does not identify SMB, RDP, WinRM or prove interactive control |
| E-008 | Windows Security object-access audit · NS-FS01 · Event ID 4663, if configured | Access to finance documents | F-05 | ObjectName, ProcessName, SubjectUserName, SubjectLogonId, AccessMask | Requires appropriate audit policy and SACL; access does not prove full contents read |
| E-009 | Sysmon · NS-FS01 · Event ID 11 and file metadata | File creation in `C:\ProgramData\Cache\` | F-05 | TargetFilename, Image, ProcessGuid, file size, source/destination hashes and timestamps | Event ID 11 records creation, not the source file or copy mechanism |
| E-010 | Sysmon Event ID 3 plus firewall/proxy telemetry · NS-FS01 | Outbound TCP activity to 198.51.100.27:8443 | F-06 | DestinationIp, DestinationPort, Image, Initiated, action/disposition, bytes, DNS and session state | Sysmon network event does not provide payload or prove data exfiltration |

## Evidence handling requirements

For each collected artefact, record:

- Unique evidence identifier and description.
- Original source system, collection method and collector.
- Collection timestamp and time zone.
- Original file name, size and SHA-256 hash where applicable.
- Storage location, access controls and chain-of-custody history.
- Parsing, filtering, conversion or transformation steps.
- Exact query, time range, index, sourcetype and field extractions used.
- Whether the record is original, exported, parsed, redacted or derived.

Preserve original exports read-only and conduct analysis on working copies. Screenshots should show enough context to identify the query, time range, source and relevant fields. Retain the underlying event data where authorised; a screenshot alone is not a substitute for the source record.

## Evidence status

The entries in this portfolio version are evidence summaries rather than primary event exports or screenshots. They should not be treated as independently verified forensic artefacts. When primary telemetry becomes available, attach source references, hashes, collection details and reproducible search information to each evidence ID.
