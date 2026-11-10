# Windows Forensic Artefacts

## Purpose

This reference summarises common Windows telemetry sources relevant to enterprise intrusion investigations. Artefact availability depends on operating-system version, audit policy, logging configuration and retention.

## Security event log

| Event ID | Typical investigative use |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Explicit credentials used |
| 4672 | Special privileges assigned to a logon |
| 4688 | Process creation, if enabled |
| 4720 | User account created |
| 4732 | Member added to a security-enabled local group |
| 1102 | Security audit log cleared |

Validate the event provider, channel, version and field names. Event IDs should not be interpreted without the surrounding record.

## Sysmon

Commonly useful event types include:

- **1:** Process creation.
- **3:** Network connection, if configured.
- **7:** Image loaded, if configured.
- **10:** Process access.
- **11:** File creation.
- **12to14:** Registry object events.
- **22:** DNS query.

Sysmon coverage depends on the deployed configuration. Absence of an event is not proof that the activity did not occur.

## PowerShell

PowerShell Operational logging can provide engine, module and script-block context. Event 4104 is commonly used for script-block logging when enabled. Correlate script content with process creation, account context and network activity.

## Registry

Registry artefacts can reveal configuration changes, startup mechanisms, application settings and traces of user activity. Preserve the hive and relevant transaction logs where forensic acquisition is required. A registry value's presence does not, by itself, establish who created it or why.

## File-system artefacts

Record full path, file name, size, timestamps, owner, ACLs, alternate data streams where relevant, signature and cryptographic hash. Interpret timestamps carefully: copying, extraction and system-clock differences can alter their meaning.

## Evidence handling

- Record the source host and collection method.
- Preserve original evidence and work from verified copies.
- Record collection time and time zone.
- Hash acquired files where appropriate.
- Document tool versions and commands used.
- Maintain chain-of-custody records for formal investigations.
- Avoid executing unknown files during triage.

## Interpretation

No single artefact should carry more weight than its reliability and context justify. Correlate independent sources and document gaps explicitly.