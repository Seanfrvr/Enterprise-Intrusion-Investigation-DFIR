# Executive Summary
### Northstar Logistics | Enterprise Intrusion Investigation

## Incident overview

A sequence of anomalous identity, endpoint and network events raises concern that a privileged service identity was misused to access multiple systems within the Northstar Logistics environment.

The activity sequence begins with a network logon by `svc-backup` from an employee workstation, followed by privileged access to the finance file server. Subsequent endpoint records describe WMI-associated process creation, PowerShell-based host and domain discovery, and access to the LSASS process by an unusual executable. The investigation narrative then records authentication to an additional server, access to finance documents, local file staging and an outbound TCP connection attempt.

## Assessment

The activity chain is consistent with a coordinated intrusion involving privileged-account misuse and movement between internal systems. The combination of identity anomalies, remote execution, suspicious LSASS access and finance-data staging warrants high-priority incident handling.

The principal assessment points are:

1. The `svc-backup` identity appears from a source outside its documented service-account pattern.
2. A WMI-associated process chain executes on NS-FS01 in the same investigative window.
3. PowerShell records contain host and domain discovery activity.
4. An unusual executable accesses LSASS on NS-FS01.
5. Finance documents are accessed and copies are created in a local staging directory.
6. NS-FS01 makes an outbound TCP connection attempt to 198.51.100.27 on port 8443.

The available case narrative does not establish how the service-account credentials were obtained, whether credentials were successfully extracted, whether the outbound connection completed, or whether data was transferred outside the environment.

## Scope

The review covers identity activity on NS-DC01, endpoint and process activity on NS-FS01, authentication involving NS-WEB01, and associated file and network events. The stated review period is 2026-10-21 08:10–10:05 UTC.

The case does not include packet capture, cloud audit records, email telemetry, endpoint memory acquisition or complete forensic disk images. These gaps limit conclusions about initial access, persistence, full compromise scope and data-loss impact.

## Business risk

If confirmed in an operational environment, the activity would create material risk to the confidentiality and integrity of finance information and to the trustworthiness of privileged service identities. Potential consequences include unauthorised access to sensitive records, further compromise through privileged credentials and disclosure of business information.

The extent of any data exposure remains undetermined. Local file staging is not equivalent to confirmed exfiltration.

## Priority response actions

1. Preserve identity, endpoint, file-server and network telemetry before retention windows expire.
2. Validate the service-account activity with system owners and review all dependent services before credential rotation.
3. Contain NS-FS01 from untrusted network paths while maintaining forensic access.
4. Investigate the source executable that accessed LSASS, including hash, signer, path and process ancestry.
5. Review authentication and remote-execution activity across the domain for related hosts and accounts.
6. Determine whether staged files were archived, accessed by another process or transferred.
7. Expand the hunt to scheduled tasks, services, remote-management settings, privileged group changes and additional persistence mechanisms.
8. Restore affected systems and credentials only after compromise scope and recovery requirements are understood.

## Confidence and reporting limitations

The report is a reconstructed portfolio case study. Primary event exports, reproducible Splunk results and original investigation screenshots are not currently retained. Event descriptions and timestamps therefore serve as illustrative case material, not independently verified observations. The SPL searches are proposed analysis logic and have not been validated against a dataset in this project.

The conclusions are intentionally bounded: suspicious activity is described where the scenario supports it, while credential theft, successful command-and-control, exfiltration and attribution remain unconfirmed.
