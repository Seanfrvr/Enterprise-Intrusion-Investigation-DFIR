# Investigation Findings

<sub>Northstar Logistics · Simulated scenario · Fictional evidence only</sub>

This document records the principal findings in the constructed case. The evidence IDs refer to the synthetic register in [evidence-register.md](evidence-register.md).

## Finding F-01 — Unusual privileged service-account authentication

**Observation**

- At 08:17 UTC, NS-DC01 records a successful network logon for `svc-backup` from NS-WS044.
- The scenario's fictional service-account baseline lists scheduled backup activity from NS-DC01 and NS-FS01, not interactive employee workstations.
- At 08:19 UTC, the same account receives elevated privileges in a logon session on NS-FS01.

**Assessment**

The source workstation and timing are inconsistent with the stated service-account baseline. This is suspicious use of a privileged identity and may indicate credential compromise or unauthorised use.

**Confidence:** High within the scenario that the account was used outside its documented pattern; medium that the credentials were compromised. The logs show account use, not how the credentials were obtained.

**Evidence:** E-001, E-002.

**Next steps**

- Review Event IDs 4624, 4648 and 4672 around the same logon session.
- Compare source workstation, logon type, authentication package and account activity with historical baseline.
- Check for legitimate maintenance, backup changes or approved administrator activity.
- Rotate credentials only after mapping service dependencies and preserving evidence.

## Finding F-02 — Remote process execution on the finance server

**Observation**

- At 08:26 UTC, NS-FS01 records a process-creation event for `wmiprvse.exe` spawning `cmd.exe`.
- The command line launches PowerShell with a non-interactive window and a command string that retrieves host and domain information.
- The event is associated in the scenario with the privileged session identified in F-01.

**Assessment**

The process chain is consistent with remote execution through Windows Management Instrumentation (WMI). WMI is a legitimate administration mechanism, so its presence alone is not malicious. The unusual parent-child chain, identity context and timing make this execution suspicious.

**Confidence:** High that the process chain occurred in the synthetic telemetry; medium-high that it represents unauthorised remote execution.

**Evidence:** E-003, E-004.

**Next steps**

- Correlate Sysmon Event ID 1 with Security Event ID 4688 if process auditing is enabled.
- Identify the WMI client, source host and associated network connections.
- Compare command line, signer, hash and parent process with known administrative tooling.
- Search for the same process chain on other servers.

## Finding F-03 — Suspicious PowerShell discovery activity

**Observation**

- At 08:28 UTC, PowerShell records commands that enumerate local users, domain information and running services.
- The scenario records script-block logging for the commands, but does not include a complete script file or a cryptographic hash for the script content.

**Assessment**

The commands are consistent with host and domain discovery. They can also appear during legitimate administration. Their execution shortly after the unusual privileged logon and remote process chain increases concern.

**Confidence:** High that the synthetic script-block records contain discovery commands; medium that the activity was malicious.

**Evidence:** E-005.

**Next steps**

- Correlate PowerShell Event IDs 4103 and 4104 with process-creation records.
- Recover the full script block and identify any downloaded or decoded content.
- Review PowerShell logging coverage and whether transcription is enabled.
- Check whether the same account executed similar commands historically.

## Finding F-04 — LSASS process access consistent with credential-access activity

**Observation**

- At 08:34 UTC, Sysmon Event ID 10 records a process-access event targeting `lsass.exe` on NS-FS01.
- The source process is an unsigned executable running from a temporary directory.
- The scenario does not contain a memory image, extracted credential material, or evidence of successful authentication using newly obtained secrets.

**Assessment**

Access to LSASS by an unusual unsigned process is a strong credential-access indicator and warrants immediate investigation. However, process access alone does not prove that credentials were dumped or recovered.

**Confidence:** High that suspicious LSASS access is represented in the synthetic telemetry; low-to-medium that credential material was successfully extracted.

**Evidence:** E-006.

**Next steps**

- Preserve the executable, metadata, hash and relevant endpoint telemetry.
- Determine granted access rights and process command line.
- Review EDR alerts and memory-forensic evidence if available.
- Hunt for subsequent logons that could indicate credential reuse.
- Do not claim credential theft without corroborating evidence.

## Finding F-05 — Internal movement and access to finance data

**Observation**

- At 08:43 UTC, NS-WEB01 records a network logon associated with `svc-backup` from NS-FS01.
- At 08:47 UTC, NS-FS01 records access to a set of finance documents on its local finance-data volume.
- At 08:51 UTC, a file-creation event records copies of selected documents in `C:\ProgramData\Cache\`.

**Assessment**

The authentication sequence is consistent with lateral movement from NS-FS01 to NS-WEB01. The file records indicate collection or staging of finance data on NS-FS01. The scenario does not establish that the files were opened in full, compressed, or transmitted outside the environment.

**Confidence:** High for the represented authentication and file-copy events; medium-high for the interpretation of collection and staging.

**Evidence:** E-007, E-008, E-009.

**Next steps**

- Correlate source and destination logons, logon IDs, SMB sessions and file-server auditing.
- Compare copied file names, sizes, hashes and timestamps with source files.
- Determine whether the staging directory was accessed by another process.
- Check for archive creation, removable-media activity and outbound transfer evidence.

## Finding F-06 — Outbound connection attempt to a documentation-only address

**Observation**

- At 09:02 UTC, network telemetry records an outbound TCP connection attempt from NS-FS01 to 198.51.100.27 on port 8443.
- The scenario records a connection attempt but does not include a completed packet-level session, application-layer payload or server-side confirmation.

**Assessment**

The timing and source host make the connection relevant to the investigation. The destination belongs to a documentation-only TEST-NET range and is used solely as a fictional indicator in this exercise. The record is not evidence of a real malicious infrastructure endpoint.

**Confidence:** High that the synthetic network record describes an outbound connection attempt; low that it establishes successful command-and-control or exfiltration.

**Evidence:** E-010.

**Next steps**

- Review firewall disposition, bytes sent/received, connection state and DNS context.
- Inspect proxy and packet-capture records if available.
- Correlate the connection with the process responsible for opening the socket.
- Do not classify the activity as successful exfiltration without transfer evidence.

## Finding F-07 — Incident scope and impact remain unresolved

**Observation**

The scenario includes suspicious activity across three servers and one workstation, but does not include complete domain-wide telemetry, cloud audit logs, packet capture or forensic images.

**Assessment**

The available synthetic evidence supports a multi-host intrusion hypothesis. The full scope, initial credential-compromise mechanism, persistence mechanism and data-loss impact cannot be established.

**Confidence:** High that the scenario is incomplete by design; no confidence claim is made about unobserved systems.

**Evidence:** E-001 through E-010.

**Required follow-up**

- Expand the time window and host scope.
- Review domain-controller replication, privileged group changes, scheduled tasks, services and remote-management configuration.
- Review DNS, proxy, firewall and endpoint telemetry for additional hosts.
- Validate whether any files left the environment.
- Reassess the incident severity when additional evidence is available.

## Consolidated conclusion

The synthetic evidence supports a high-priority investigation into suspected privileged-account misuse, remote execution, discovery, suspicious LSASS access, internal movement, finance-data staging and an outbound connection attempt.

The conclusion deliberately stops short of claiming confirmed credential theft, confirmed persistence, successful command-and-control, data exfiltration or attribution. Those claims require evidence not present in this scenario.
