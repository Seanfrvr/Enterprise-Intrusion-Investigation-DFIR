# Splunk Threat Hunting

## How to use these searches

These SPL examples are **starting templates**, not validated detections. Confirm your index, sourcetype, field extractions, time range and data coverage before running them. The examples assume common Windows EventCode and Sysmon fields.

Replace `index=windows` and sourcetypes with values from your Splunk environment.

## Hunt 1 — Suspicious PowerShell process creation

**Question:** Which PowerShell processes have unusual command-line characteristics?

```spl
index=windows (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")
EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval cmd=lower(CommandLine)
| where like(cmd,"% -enc %") OR like(cmd,"%encodedcommand%") OR like(cmd,"%downloadstring%") OR like(cmd,"%frombase64string%")
| table _time host User ParentImage Image CommandLine ProcessGuid
| sort 0 _time
```

**Review:** Validate the full command, parent process, user, destination host and whether the behaviour is part of approved automation. Encoded PowerShell is not automatically malicious.

## Hunt 2 — Windows event-log clearing

**Question:** Are there records indicating that an event log was cleared?

```spl
index=windows (EventCode=1102 OR EventCode=104)
| eval event_channel=case(EventCode=1102, "Security", EventCode=104, "System")
| table _time host event_channel EventCode Provider_Name SubjectUserName SubjectDomainName Message
| sort 0 _time
```

**Review:** Event ID 1102 is recorded in the Security channel when the Security audit log is cleared. Event ID 104 is emitted by the Microsoft-Windows-Eventlog provider in the System channel when an event log is cleared. Do not constrain both events to the Security sourcetype; confirm the channel and provider in the raw record, then correlate with administrative activity and central log ingestion.

## Hunt 3 — Suspicious process access to LSASS

**Question:** Which processes accessed the LSASS process according to Sysmon?

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10 TargetImage="*\\lsass.exe"
| table _time host User SourceImage TargetImage GrantedAccess CallTrace SourceProcessGuid
| sort 0 _time
```

**Review:** Sysmon Event ID 10 records process access. Validate the source process, access mask, signer, parent process and known security products. Legitimate EDR and diagnostic tools may access LSASS.

## Hunt 4 — Authentication failures by account and source

**Question:** Are there concentrated authentication failures that warrant review?

```spl
index=windows (sourcetype="XmlWinEventLog:Security" OR sourcetype="WinEventLog:Security")
EventCode=4625
| stats count as failures earliest(_time) as first_seen latest(_time) as last_seen values(host) as target_hosts by TargetUserName IpAddress
| where failures >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - failures
```

**Review:** Thresholds are illustrative. Confirm field names for your event format and account for NAT, shared workstations, service accounts and expected authentication failures.

## Hunt documentation standard

For each run, record:
- Investigation question and hypothesis.
- Index, sourcetype, time range and data coverage.
- Exact SPL and any field assumptions.
- Result count and representative event references.
- Benign explanations and false positives.
- Follow-up pivots and limitations.
- Whether the search was tested, tuned or only proposed.

A search returning zero events does not prove the behaviour did not occur; it may indicate missing telemetry, incorrect field assumptions or an unsuitable time range.