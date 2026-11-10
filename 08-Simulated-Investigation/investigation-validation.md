# Investigation Validation Plan
### Northstar Logistics | Technical Review and Outstanding Evidence

This plan defines what must be collected and tested before the case narrative can be treated as a dataset-backed investigation. It is a work plan, not a statement that these checks have already been completed.

## 1. Evidence acquisition priorities

| Priority | Source | Collection target | Why it matters |
|---|---|---|---|
| Critical | NS-DC01 Security log | Events 4768, 4769, 4776, 4720to4738 where relevant | Validate authentication context, service-ticket activity and account changes |
| Critical | NS-FS01 Security log | Events 4624, 4672, 4688, 4663 if auditing is enabled | Establish destination logons, privilege context, process creation and audited file access |
| Critical | NS-FS01 Sysmon | Events 1, 3, 10, 11, 12to14 if configured | Reconstruct process ancestry, network activity, LSASS access and file creation |
| High | NS-FS01 WMI-Activity Operational | Available WMI operational records around 08:20to08:35 UTC | Identify WMI client, user, operation and client process context |
| High | NS-FS01 PowerShell Operational | Events 4103 and 4104, including all fragments | Reconstruct script content and execution context |
| High | NS-WEB01 Security log | Events 4624, 4672, 4688 and relevant service logs | Validate the inter-host logon and determine what service was accessed |
| High | File server / object access | File audit records, SMB server logs, USN journal and relevant file metadata | Establish what was accessed, by whom and whether copies match source files |
| High | Firewall / proxy / DNS | Connection disposition, five-tuple, bytes, DNS answers and time range | Determine whether outbound activity was blocked, completed or transferred data |
| Medium | EDR / endpoint response | Process tree, file reputation, alerts and available memory artefacts | Investigate LSASS access and possible credential or persistence activity |

Preserve original exports before parsing. Record collector, collection time, host time zone, file size, SHA-256 and storage location. Do not change the original source data during analysis.

## 2. Correlation tests

### Identity

- Match NS-DC01 Event ID 4769 to NS-FS01 Event ID 4624 using account, service/SPN, client address and a bounded time window.
- Use NS-FS01 Event ID 4624 `TargetLogonId` to correlate Event ID 4672 and later events on the same host.
- Do not assume a domain-controller ticket request proves successful access to the destination server.
- Confirm the service-account owner, approved source systems, scheduled task configuration and change records.

### WMI and process execution

- Reconstruct the NS-FS01 process tree using Sysmon `ProcessGuid` and `ParentProcessGuid`, not PID alone.
- Review WMI-Activity records for client machine, user, operation and client process ID where available.
- Correlate WMI client context with source-host network and authentication records.
- Treat `WmiPrvSE.exe` spawning a child process as WMI-associated execution, not conclusive proof of remote origin.

### PowerShell

- Reassemble all Event ID 4104 fragments using `ScriptBlockId`, `MessageNumber` and `MessageTotal` where present.
- Correlate the script block with process creation, user, host and parent process.
- Review Event ID 4103, transcription and module logging if configured.
- Distinguish discovery commands from approved administrative automation.

### LSASS

- Preserve the source executable and record SHA-256, signer, file path, creation time and parent process.
- Inspect Sysmon Event ID 10 source process, target process, granted access and call trace.
- Review EDR telemetry and file-system artefacts for evidence of a dump file or other credential-access activity.
- Do not claim credential dumping unless additional evidence supports it.

### File access and staging

- Validate file auditing policy and the meaning of each Event ID 4663 record.
- Identify the process responsible for creating files in `C:\ProgramData\Cache\`.
- Compare source and staged file names, sizes, timestamps and hashes.
- Determine whether an archive was created or whether another process accessed the staged data.
- Distinguish file access, file creation, local staging and external transfer as separate claims.

### Network activity

- Identify the process and user associated with the NS-FS01 outbound connection.
- Correlate Sysmon Event ID 3 with firewall and proxy records using the full source/destination tuple and timestamp.
- Establish whether the connection was allowed, denied, reset or completed.
- Review bytes sent and received, DNS resolution and packet data where lawfully available.
- Do not infer command-and-control or exfiltration from destination and port alone.

## 3. Alternative hypotheses to test

| Hypothesis | Evidence that would support it | Evidence that would weaken it |
|---|---|---|
| Approved backup or maintenance activity | Change ticket, job schedule, service owner confirmation, known management host and expected process hashes | Unapproved source workstation, unusual command line, unexplained LSASS access |
| Endpoint-management or software-deployment activity | Management platform records, matching deployment job, known agent and expected WMI operations | No corresponding job, unknown client, unusual executable or account use |
| Legitimate diagnostic or security software accessed LSASS | Valid signature, known product path, vendor documentation and matching EDR process | Unsigned or newly created executable, suspicious ancestry, dump artefacts |
| Finance file migration or application processing | Approved migration record, expected source/destination, known process and matching hashes | Unapproved staging path, unexplained file selection or unrelated outbound process |
| Benign application network traffic | Known application owner, expected destination, normal protocol and successful change validation | Unrecognised process, unusual destination, unexplained data volume or denied connection |

An alternative explanation should not be accepted merely because it is possible. Validate it against source records and system-owner context.

## 4. Provisional severity assessment

**Initial working severity: High, pending validation.**

| Dimension | Provisional assessment | Rationale |
|---|---|---|
| Confidentiality | Potentially high | Finance documents are described as accessed and staged; external disclosure is unconfirmed |
| Integrity | Undetermined | No verified unauthorised modification is described |
| Availability | No confirmed impact | No outage or service disruption is described |
| Privilege | High concern | A privileged service identity is implicated outside its stated baseline |
| Scope | Multiple hosts in narrative | Complete domain-wide coverage is unavailable |
| Confidence | Limited | No primary event exports or validated searches are retained |

Reassess severity after confirming account legitimacy, the affected host set, file access, network disposition and any evidence of persistence or impact. Severity is not an ATT&CK score and should reflect business impact and confidence, not just the number of suspicious techniques.

## 5. Exit criteria for a validated case study

The case should not be labelled dataset-validated until the following are complete:

- [ ] Permitted dataset and source provenance documented.
- [ ] Relevant event exports preserved and hashed.
- [ ] Host time zones and clock offsets recorded.
- [ ] Each evidence-register item linked to a source record or query result.
- [ ] Timeline rebuilt from source timestamps.
- [ ] Authentication and process relationships corroborated using stable identifiers.
- [ ] Alternative explanations assessed.
- [ ] SPL searches executed, raw events reviewed and field assumptions documented.
- [ ] Detection false positives and known coverage gaps recorded.
- [ ] Screenshots captured from the analyst's own investigation, with sensitive data redacted.
- [ ] Findings and ATT&CK mappings updated to match what the evidence actually supports.

## Current status

None of the above checks are claimed as completed in this portfolio case. This document records the validation work required to move from a reconstructed case narrative to a reproducible, evidence-backed investigation.
