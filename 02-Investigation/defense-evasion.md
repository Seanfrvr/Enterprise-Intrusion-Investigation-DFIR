# Defence Evasion

## Objective

Assess whether activity may have been intended to reduce visibility, disguise files or interfere with forensic evidence.

## Areas to examine

- Windows event-log clearing and service interruption.
- PowerShell history, script-block and operational logging changes.
- Registry modifications.
- File renaming, extension changes and archive staging.
- Security-tool configuration changes or exclusions.
- Timestamp anomalies and deletion activity.
- Gaps in central log ingestion.

## Important Windows events

- **1102:** Security audit log cleared.
- **104:** An event log was cleared (Microsoft-Windows-Eventlog provider).
- **4688:** Process creation, when enabled.
- **4104:** PowerShell script-block logging, when enabled.
- Sysmon events may provide process, file, registry and network context.

Confirm the provider and channel. Event IDs can have different meanings across providers.

## Analysis method

1. Identify the affected host and log channel.
2. Establish whether the action was performed locally or remotely.
3. Correlate the event with the responsible account and process.
4. Compare local logs with centralised SIEM ingestion to identify collection gaps.
5. Review adjacent process, registry and file events.
6. Determine whether the action was part of approved maintenance.

## Interpretation limits

A log-clear event confirms a clearing action, not necessarily that all evidence was destroyed. A renamed file is not automatically malicious. Record exactly what changed and whether original content can be identified through hashes, file signatures or forensic examination.

## Defensive recommendations

Forward logs off-host, restrict log-management privileges, alert on clearing events, monitor changes to audit policy and retain immutable or access-controlled copies.