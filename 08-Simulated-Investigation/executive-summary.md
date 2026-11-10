# Executive Summary
### Northstar Logistics | Enterprise Intrusion Investigation

## Incident overview

A sequence of identity, endpoint and network events raises concern that the privileged service identity `svc-backup` was used outside its documented operating pattern to access multiple systems.

The case narrative begins with authentication activity associated with NS-WS044 and `svc-backup`, followed by a privileged logon session on NS-FS01. Subsequent endpoint records describe WMI-associated process creation, PowerShell host and domain discovery, and access to LSASS by an executable running from a temporary directory. Later records describe network authentication involving NS-WEB01, finance-file access and local staging on NS-FS01, followed by outbound network activity.

## Overall assessment

The sequence is consistent with possible privileged-account misuse and suspicious activity across multiple hosts. The combination of an anomalous service-account source, remote-management execution indicators, unusual LSASS access and finance-data staging warrants high-priority triage.

The evidence described in this case does not establish the initial credential-compromise mechanism, successful credential extraction, the remote service used for inter-host access, successful external communication or data exfiltration.

## Principal findings

1. **Identity:** `svc-backup` is associated with authentication from NS-WS044, outside the stated service-account baseline.
2. **Execution:** NS-FS01 records a process chain involving `WmiPrvSE.exe`, `cmd.exe` and PowerShell. Remote origin requires corroboration from WMI and network telemetry.
3. **Discovery:** PowerShell script-block records describe host, domain and service enumeration.
4. **Credential-access indicator:** an unusual executable from a temporary path accesses LSASS. Its signer and whether credential material was extracted are not established.
5. **Inter-host authentication:** `svc-backup` is associated with a network logon on NS-WEB01 from NS-FS01. The remote protocol is not established.
6. **Data handling:** finance documents are accessed and copies are created in a local staging directory. External transfer is not established.
7. **Network:** outbound activity from NS-FS01 is recorded to 198.51.100.27:8443. Session disposition and payload are unavailable.

## Scope and coverage

The review period is 2026-10-21 08:10to10:05 UTC. The described scope includes NS-WS044, NS-DC01, NS-FS01 and NS-WEB01, with identity, process, PowerShell, file and network activity.

The case does not include packet capture, cloud audit records, email telemetry, endpoint memory acquisition, complete forensic disk images or comprehensive domain-wide event coverage. These gaps prevent a reliable determination of initial access, persistence, full compromise scope and data-loss impact.

## Provisional severity and business risk

**Provisional severity: High, pending validation.**

The proposed severity is based on the combination of a privileged service identity, activity across multiple systems, suspicious LSASS access and access to finance data. It is not a confirmed impact rating.

- **Confidentiality:** potentially high if finance data was accessed and transferred without authorisation; transfer is not established.
- **Integrity:** undetermined; no verified unauthorised modification is described.
- **Availability:** no confirmed disruption is described.
- **Scope:** multiple systems are implicated in the case narrative; enterprise-wide scope is unknown.

The severity should be reassessed after validating the source events, account legitimacy, affected assets and network-transfer outcome.

## Priority response actions

1. Preserve Security, Sysmon, PowerShell, WMI-Activity, file-server, firewall and proxy records before retention windows expire.
2. Validate the service-account activity with system owners; identify approved source hosts and service dependencies before disabling or rotating the account.
3. Investigate NS-FS01 and the process that accessed LSASS, preserving the executable, metadata, hash and relevant endpoint telemetry.
4. Correlate the destination server's logon record with domain-controller authentication records using account, source address, service information and logon identifiers where available.
5. Identify the remote protocol and process responsible for inter-host access.
6. Determine which finance files were accessed and staged; compare source and destination hashes and investigate archive or transfer activity.
7. Establish the outbound connection disposition, process attribution, DNS context and bytes transferred using endpoint, firewall, proxy and packet telemetry.
8. Expand the hunt to scheduled tasks, services, privileged group changes, remote-management configuration and other persistence mechanisms.
9. Reassess scope and severity before recovery and credential restoration.

## Confidence and reporting limitations

This is a reconstructed portfolio case study. Primary event exports, reproducible Splunk results and original investigation screenshots are not currently retained. The event descriptions and timestamps are illustrative case material, not independently verified observations. The searches are proposed analysis logic and have not been validated against a dataset in this project.

The report deliberately distinguishes suspicious behaviour from confirmed outcomes. Credential theft, persistence, successful command-and-control, exfiltration and actor attribution remain unconfirmed.