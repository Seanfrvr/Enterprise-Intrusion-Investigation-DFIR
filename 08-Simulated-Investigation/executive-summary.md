# Executive Summary

<sub>Northstar Logistics · Simulated incident · All details fictional</sub>

## Situation

Northstar Logistics is a fictional regional services company. During a routine review, its security team identifies a sequence of unusual events involving a privileged service identity, a domain controller, a finance file server and an internal application server.

The constructed scenario begins with abnormal authentication associated with the service account `svc-backup`. Subsequent records show remote process creation, suspicious PowerShell execution, access to the Local Security Authority Subsystem Service (LSASS) process, and access to finance data. A later network record shows an outbound connection attempt to a documentation-only TEST-NET address.

## Overall assessment

The scenario is consistent with a coordinated intrusion using a compromised or misused privileged identity. The activity chain includes account misuse, remote execution, credential-access behaviour, internal discovery, data staging and attempted external communication.

The strongest scenario-supported conclusions are:

1. The `svc-backup` identity authenticated to systems outside its documented fictional service pattern.
2. A remote process-creation event on NS-FS01 was associated with that identity.
3. PowerShell execution and access to LSASS were recorded on NS-FS01.
4. Files from a finance share were copied into a staging directory.
5. A subsequent outbound connection attempt from NS-FS01 targeted 198.51.100.27 over TCP/8443.

These observations support a high-priority incident assessment in the fictional environment. They do not prove that credentials were successfully extracted, that data left the organisation, or that an external operator controlled the destination.

## Scope

The simulated review covers:

- Identity and authentication events on NS-DC01.
- Process and network telemetry from NS-FS01 and NS-WEB01.
- PowerShell operational records.
- File access and file-creation observations.
- A defined period from 2026-10-21 08:10 UTC to 2026-10-21 10:05 UTC.

The exercise does not include packet capture, cloud audit logs, email telemetry, endpoint memory, or a complete forensic disk image.

## Business risk

If this activity occurred in a real organisation, the combination of privileged identity misuse, access to finance data and attempted outbound communication would create material risks:

- Unauthorised access to sensitive financial information.
- Potential compromise of additional systems through privileged credentials.
- Loss of confidence in the integrity of service-account activity.
- Possible disclosure of business-sensitive information.

The actual confidentiality impact remains undetermined because the scenario contains no verified evidence of successful external transfer.

## Recommended response

1. Disable or rotate the affected service identity after validating service dependencies and preserving relevant evidence.
2. Isolate NS-FS01 from untrusted network paths while maintaining forensic access.
3. Review privileged logons, remote process creation and service-account use across the domain.
4. Preserve Security, Sysmon, PowerShell, file-server and network records.
5. Inspect the staging directory and determine whether files were accessed or transferred.
6. Hunt for the same process hashes, command patterns, destination and account activity across other endpoints.
7. Restore systems and credentials only after the scope of compromise has been established.

## Assessment limitations

This is a synthetic case study written to demonstrate investigation structure and defensive reasoning. It is not a real incident, not a completed hands-on lab, and not evidence of tested Splunk detections. The scenario's observations are fictional inputs to the analysis.
