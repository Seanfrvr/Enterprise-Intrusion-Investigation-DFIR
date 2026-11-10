# Splunk Hunt Notebook

These are **untested starting searches**. They are included as query notes, not advertised as finished detections. Before using one, identify the actual index and sourcetype, inspect an unfiltered event, and confirm the field names in your Splunk instance.

## First: inspect the data

Start broad enough to confirm that the source is present:

```spl
index=windows earliest=-24h
| stats count by sourcetype host
| sort - count
```

Then inspect one event from the relevant source:

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| head 5
| table _time host EventCode Message
```

If your environment uses another index or sourcetype, change it. Do not assume the examples' field names match your deployment.

## Hunt 1 — PowerShell process execution

**Question:** Which PowerShell processes have command-line patterns worth reviewing?

**Source:** Sysmon Event ID 1.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| where match(CommandLine, "(?i)(^|\\s)-(enc|encodedcommand)(\\s|$)|downloadstring|frombase64string")
| table _time host User ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort 0 _time
```

**What I would check next:** full command line, parent process, user, signer/hash and whether the same command appears on other hosts. Encoded arguments are a lead, not a verdict.

## Hunt 2 — LSASS process access

**Question:** Which processes accessed LSASS, and what was the source process?

**Source:** Sysmon Event ID 10.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
| table _time host User SourceImage SourceProcessGuid SourceProcessId GrantedAccess CallTrace
| sort 0 _time
```

**What I would check next:** source executable path, signature, hash, parent process, granted access mask and EDR context. Event ID 10 records process access; it does not establish that credentials were extracted.

## Hunt 3 — Windows log clearing

**Question:** Are there records that an event log was cleared?

```spl
index=windows (EventCode=1102 OR EventCode=104)
| table _time host EventCode Provider_Name Channel SubjectUserName SubjectDomainName Message
| sort 0 _time
```

Event ID 1102 is associated with the Security audit log being cleared. Event ID 104 is emitted by the Windows Eventlog provider when a log is cleared and is normally found in the System channel. Confirm the provider and channel in the raw event; do not assume the two records share a sourcetype.

## Hunt 4 — Failed logons by account and source

**Question:** Which account/source combinations generated repeated failed logons?

```spl
index=windows sourcetype="XmlWinEventLog:Security" EventCode=4625
| eval source=coalesce(IpAddress, Source_Network_Address)
| stats count as failures earliest(_time) as first_seen latest(_time) as last_seen values(host) as target_hosts by TargetUserName source
| where failures >= 5
| convert ctime(first_seen) ctime(last_seen)
| sort - failures
```

The threshold is only a starting point. Validate whether your extraction uses `TargetUserName`, `Target_Username`, `IpAddress` or another field. Account for NAT, shared systems, service accounts and normal authentication noise.

## Notes before trusting a result

- Use the raw event to verify every field used in a filter or aggregation.
- Check whether the relevant audit policy or Sysmon rule was enabled.
- Keep the search time range explicit when documenting an investigation.
- Review individual events behind a count; aggregates can hide important context.
- A zero-result search may mean no activity, missing telemetry, a wrong field or an unsuitable time range.

**Validation status:** none of these searches has been executed against the Northstar case narrative or independently tested in this repository. Do not describe them as validated detections.
