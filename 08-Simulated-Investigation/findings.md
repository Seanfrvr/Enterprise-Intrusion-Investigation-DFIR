# Investigation Findings
### Northstar Logistics | Findings and Analysis

The following findings organise the case narrative into observations, assessments, confidence limits and follow-up actions. Evidence IDs refer to the [evidence register](evidence-register.md). Primary telemetry is not retained in this portfolio version; therefore, the confidence labels describe the internal consistency of the case narrative, not independently verified source evidence.

## F-01 — Privileged service-account authentication outside baseline

**Observation**

- 08:17 UTC: a domain-controller authentication record is associated with a Kerberos service-ticket request for `svc-backup`, with NS-WS044 identified as the client.
- 08:19 UTC: NS-FS01 records a network logon for `svc-backup` from NS-WS044, followed by a privileged logon record.
- The stated service-account baseline limits expected use to scheduled backup activity from designated infrastructure.

**Assessment**

The source workstation is inconsistent with the documented service-account pattern. The destination server's logon record is the primary evidence of access to NS-FS01; the domain-controller ticket record provides authentication context but is not, by itself, proof of successful target logon. The activity may indicate credential compromise, unauthorised use or an undocumented administrative change.

**Confidence:** High for the described baseline deviation; medium for credential compromise.

**Evidence references:** E-001, E-002.

**Alternative explanations:** approved maintenance, backup troubleshooting, a changed service architecture, or inaccurate service-account documentation.

**Further investigation:** validate the account owner and approved source hosts; correlate Event IDs 4769, 4624 and 4672 using account, source address, service name and Logon ID where available; review authentication package, logon type and historical account activity.

## F-02 — WMI-associated process execution on NS-FS01

**Observation**

- 08:26 UTC: Sysmon process-creation telemetry is described as showing `WmiPrvSE.exe` spawning `cmd.exe`, followed by PowerShell.
- The command context includes host and domain information gathering.
- The activity occurs shortly after the privileged session described in F-01.

**Assessment**

The process lineage is consistent with execution through the Windows Management Instrumentation provider. This supports a WMI-associated execution finding. It does not independently establish that the operation originated remotely from NS-WS044 or that the process was unauthorised. The remote client must be established using WMI-Activity, network and authentication context.

**Confidence:** High for the described process lineage; medium for remote or unauthorised execution.

**Evidence references:** E-003, E-004.

**Alternative explanations:** approved endpoint management, software deployment, inventory collection or administrator troubleshooting.

**Further investigation:** correlate Sysmon Event ID 1 with Security Event ID 4688 where available; review WMI-Activity Operational records for client machine, user, operation and client process ID; identify the source host and RPC/DCOM network context; inspect process hashes, signatures, command lines and approved management tooling.

## F-03 — PowerShell host and domain discovery

**Observation**

- 08:28 UTC: PowerShell script-block records are described as enumerating local users, domain information and running services.
- The case material does not include a complete script file, full script-block sequence or cryptographic hash of the script content.

**Assessment**

The commands are consistent with host and domain discovery. They can also occur during legitimate administration. Their timing after the unusual service-account activity and WMI-associated execution increases investigative priority but does not establish malicious intent.

**Confidence:** High for the described discovery content; medium for malicious intent.

**Evidence references:** E-005.

**Alternative explanations:** inventory scripts, health checks, system administration or backup tooling.

**Further investigation:** retrieve complete Event ID 4104 records; correlate script-block IDs with process creation and Event ID 4103 where available; inspect transcription and module logging; identify the initiating process, user and execution prevalence.

## F-04 — Unusual process access to LSASS

**Observation**

- 08:34 UTC: Sysmon Event ID 10 is described as recording a process from a temporary directory accessing `lsass.exe` on NS-FS01.
- The source executable's signer status has not been established from the available case material.
- No memory image, dump file, recovered credential material or subsequent authentication using recovered secrets is available.

**Assessment**

Unusual process access to LSASS is a significant credential-access indicator. Event ID 10 records process access; it does not prove that credentials were dumped or recovered. The source process, granted access rights, call trace and endpoint-security context are required to assess the behaviour.

**Confidence:** High for the described LSASS access event; low for successful credential extraction.

**Evidence references:** E-006.

**Alternative explanations:** endpoint-security software, diagnostic tooling, crash collection or other approved software accessing LSASS.

**Further investigation:** preserve the executable and metadata; calculate its SHA-256 hash; verify signer and file reputation; inspect source process GUID, PID, command line, user, granted access mask and call trace; review EDR alerts and memory evidence; hunt for possible credential reuse.

## F-05 — Inter-host authentication and finance-data staging

**Observation**

- 08:43 UTC: NS-WEB01 records a network logon for `svc-backup` with NS-FS01 identified as the source.
- 08:47 UTC: file-auditing records are described as showing access to finance documents on NS-FS01.
- 08:51 UTC: file-creation telemetry records copies of selected documents in `C:\ProgramData\Cache\`.

**Assessment**

The NS-WEB01 logon establishes an inter-host authentication event in the case narrative. It does not identify whether SMB, RDP, WinRM or another service was used, and does not alone prove interactive control. The finance-file records are consistent with local staging, but the source-to-destination relationship and process responsible for the copies require validation.

**Confidence:** High for the described inter-host logon and file-creation sequence; medium for the interpretation of collection and staging.

**Evidence references:** E-007, E-008, E-009.

**Alternative explanations:** approved file migration, backup activity, application processing or administrator access.

**Further investigation:** correlate Event ID 4624 on NS-WEB01 with source address, logon type and Logon ID; identify the remote service using SMB, RDP or WinRM telemetry; review file Event ID 4663 where auditing is configured; identify the process creating the staged files; compare source and destination hashes, sizes and timestamps.

## F-06 — Outbound network activity from NS-FS01

**Observation**

- 09:02 UTC: network telemetry is described as recording outbound TCP activity from NS-FS01 to 198.51.100.27 on port 8443.
- The case material does not include the firewall disposition, connection state, payload, bytes transferred or receiving-side confirmation.

**Assessment**

The originating host and timing make the activity relevant to the investigation. The destination is within the RFC 5737 TEST-NET-2 documentation range and is a reserved example address, not a live threat indicator. Without connection disposition and process context, the record does not establish successful command-and-control or data transfer.

**Confidence:** High for the described network record; low for successful external communication.

**Evidence references:** E-010.

**Alternative explanations:** approved application traffic, proxying, a blocked connection attempt or a benign service using a non-standard port.

**Further investigation:** review firewall allow/deny records, Sysmon Event ID 3, proxy and DNS logs; identify the process and user responsible; inspect connection state and byte counts; seek packet-level or receiving-side confirmation.

## F-07 — Scope and impact remain undetermined

**Observation**

The case narrative covers NS-WS044 and three servers but does not include complete domain-wide telemetry, cloud audit records, packet capture, endpoint memory or full disk images.

**Assessment**

The described sequence warrants investigation as a potential multi-host compromise. Initial access, persistence, the full set of affected assets, integrity impact and data-loss impact remain unresolved.

**Confidence:** High that the case material has significant coverage gaps; no conclusion is made about systems for which telemetry is absent.

**Evidence references:** E-001 through E-010.

**Further investigation:** expand the time window and host scope; inspect privileged group changes, scheduled tasks, services, remote-management configuration and domain-controller activity; review DNS, proxy, firewall and endpoint telemetry; determine whether staged files left the environment.

## Consolidated assessment

The case narrative is consistent with possible privileged-account misuse followed by WMI-associated execution, PowerShell discovery, suspicious LSASS access, inter-host authentication, finance-file staging and outbound network activity.

It does not establish credential theft, persistence, successful command-and-control, data exfiltration or actor attribution. Those conclusions require corroborating primary evidence.
