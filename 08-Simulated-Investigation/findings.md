# Investigation Findings
### Northstar Logistics | Findings and Analysis

This report records seven findings across identity, endpoint, file and network activity. Evidence references correspond to the [evidence register](evidence-register.md). Confidence describes the strength of the case narrative's analytical support; primary telemetry is not retained in this portfolio version.

## F-01 — Privileged service-account authentication outside baseline

**Observation**

- 08:17 UTC: a successful network logon for `svc-backup` is associated with source host NS-WS044 and destination NS-DC01.
- The documented service-account pattern in this case limits expected activity to scheduled backup operations from designated infrastructure.
- 08:19 UTC: a privileged logon session associated with the same identity is recorded on NS-FS01.

**Analysis**

The source workstation is inconsistent with the stated service-account baseline. The subsequent privileged session increases the significance of the anomaly. This may indicate compromised credentials or unauthorised use of the account; the authentication records alone do not establish how the credentials were obtained.

**Confidence:** High for the described baseline deviation; medium for credential compromise.

**Evidence references:** E-001, E-002.

**Further investigation:** correlate logon IDs, source addresses, logon types and authentication packages; review Event IDs 4624, 4648 and 4672; validate approved maintenance and backup activity with system owners.

## F-02 — WMI-associated remote process execution on NS-FS01

**Observation**

- 08:26 UTC: `WmiPrvSE.exe` is described as spawning `cmd.exe`, followed by PowerShell.
- The command context includes host and domain information gathering.
- The process activity is temporally associated with the privileged session described in F-01.

**Analysis**

The process lineage is consistent with execution through Windows Management Instrumentation. WMI is a legitimate management interface, but the process chain, account context and timing make the activity suspicious in this case.

**Confidence:** High for the described process relationship; medium-high for unauthorised remote execution.

**Evidence references:** E-003, E-004.

**Further investigation:** correlate Sysmon Event ID 1 with Security Event ID 4688; identify the WMI client and source host; review process hashes, signatures, command lines and related network connections; compare against approved management tooling.

## F-03 — PowerShell host and domain discovery

**Observation**

- 08:28 UTC: PowerShell script-block records are described as enumerating local users, domain information and running services.
- The case material does not include a complete script file or cryptographic hash for the script content.

**Analysis**

The command categories are consistent with host and domain discovery. They are also used by legitimate administrators. Their proximity to the unusual service-account activity and WMI-associated execution raises the priority for review.

**Confidence:** High for the described discovery content; medium for malicious intent.

**Evidence references:** E-005.

**Further investigation:** retrieve complete Event ID 4104 records; correlate with Event ID 4103 and process creation; inspect PowerShell transcription and module logging; compare the activity with historical administrative behaviour.

## F-04 — Unusual process access to LSASS

**Observation**

- 08:34 UTC: a Sysmon Event ID 10 record is described as showing an unsigned executable from a temporary directory accessing `lsass.exe` on NS-FS01.
- No memory image, extracted credential material or subsequent authentication using recovered secrets is available in the case material.

**Analysis**

Unusual access to LSASS is a significant credential-access indicator. However, a process-access event does not independently prove credential dumping or successful recovery of secrets.

**Confidence:** High for the described suspicious access; low-to-medium for successful credential extraction.

**Evidence references:** E-006.

**Further investigation:** preserve the executable and metadata; calculate and reputation-check its hash; inspect signer, path, command line and granted access mask; review EDR telemetry and memory evidence; hunt for possible credential reuse.

## F-05 — Internal authentication and finance-data staging

**Observation**

- 08:43 UTC: NS-WEB01 records a network logon associated with `svc-backup` from NS-FS01.
- 08:47 UTC: finance documents are described as being accessed on NS-FS01.
- 08:51 UTC: copies of selected documents are described as being created in `C:\ProgramData\Cache\`.

**Analysis**

The authentication sequence is consistent with movement between internal systems. The file activity indicates potential collection and local staging. The available case material does not establish that all file contents were read, that an archive was created, or that data was transmitted externally.

**Confidence:** High for the described authentication and file-copy sequence; medium-high for the collection/staging interpretation.

**Evidence references:** E-007, E-008, E-009.

**Further investigation:** correlate logon IDs and SMB sessions; compare source and staged file names, sizes and hashes; identify the process responsible for copying; review archive creation, removable media, proxy, firewall and network-transfer records.

## F-06 — Outbound connection attempt from NS-FS01

**Observation**

- 09:02 UTC: network telemetry is described as recording an outbound TCP connection attempt from NS-FS01 to 198.51.100.27:8443.
- No completed session, application-layer payload or receiving-server confirmation is included.

**Analysis**

The timing and originating host make the connection relevant to the investigation. The destination is within the RFC 5737 TEST-NET-2 documentation range and is used here as a reserved example address, not a live threat indicator. The described event does not establish command-and-control or successful data transfer.

**Confidence:** High for the described connection-attempt record; low for successful external communication.

**Evidence references:** E-010.

**Further investigation:** review firewall disposition, connection state, bytes sent and received, DNS and proxy records; identify the process opening the connection; seek packet-level or receiving-side confirmation.

## F-07 — Scope and impact cannot yet be determined

**Observation**

The case narrative covers a workstation and three servers but does not include complete domain-wide telemetry, cloud audit logs, packet capture, endpoint memory or full disk images.

**Analysis**

The described sequence warrants investigation as a potential multi-host compromise. The initial access vector, persistence mechanism, full set of affected assets and data-loss impact remain unresolved.

**Confidence:** High that the available case material has material investigative gaps.

**Evidence references:** E-001 through E-010.

**Further investigation:** expand the review period and host scope; inspect privileged group changes, scheduled tasks, services, remote-management settings and domain-controller activity; review DNS, proxy, firewall and endpoint telemetry; determine whether staged files left the environment.

## Overall finding

The case narrative is consistent with privileged-account misuse followed by remote execution, discovery, suspicious LSASS access, internal movement, finance-data staging and an outbound connection attempt.

The evidence described does not support definitive conclusions of credential theft, persistence, successful command-and-control, data exfiltration or actor attribution. Those conclusions require corroborating primary evidence.
