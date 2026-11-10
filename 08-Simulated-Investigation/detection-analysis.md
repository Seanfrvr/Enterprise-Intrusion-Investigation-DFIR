# Detection Engineering Analysis
### Northstar Logistics | Splunk SPL Hunt Logic

The following searches translate the investigation's key behaviours into practical hunt logic. They are starting-point SPL examples, not validated production detections. Confirm index names, sourcetypes, field extractions, CIM mapping and event coverage in the target Splunk environment.

## DET-01 — Service-account logon from an unexpected source

**Objective:** identify successful network logons for service identities from hosts outside an approved source list.

**Telemetry:** Windows Security Event ID 4624. Common fields include `TargetUserName`, `IpAddress`, `LogonType` and `ComputerName`.

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624
TargetUserName="svc-backup" Logon_Type=3
| stats count min(_time) as first_seen max(_time) as last_seen
  values(ComputerName) as destination_hosts
  values(IpAddress) as source_ips
  by TargetUserName
| convert ctime(first_seen) ctime(last_seen)
```

**Analyst review:** compare source host, logon type, authentication package and time of access against the service-account baseline. Validate approved backup operations before escalation.

**Tuning:** maintain an approved account-to-host mapping. Alert on new source hosts and unexpected logon types rather than suppressing all service-account activity.

## DET-02 — WMI spawning command interpreters

**Objective:** identify WMI provider processes spawning command shells or scripting engines.

**Telemetry:** Sysmon Event ID 1 or Security Event ID 4688 where process creation auditing is enabled.

```spl
index=sysmon EventCode=1
ParentImage="*\\WmiPrvSE.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time Computer User ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort 0 _time
```

**Analyst review:** inspect parent and child command lines, user context, process signer, hash, source host and related network activity.

**Tuning:** baseline approved management platforms, deployment systems and administrative scripts. WMI is a legitimate Windows management interface; parent process alone is not sufficient for a malicious verdict.

## DET-03 — Unusual access to LSASS

**Objective:** surface processes accessing LSASS outside expected security-product behaviour.

**Telemetry:** Sysmon Event ID 10. Field names and access-mask representation vary by configuration.

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| stats count values(GrantedAccess) as access_masks
  values(SourceImage) as source_processes
  values(Computer) as hosts
  by SourceImage
| sort - count
```

**Analyst review:** inspect source process path, signer, hash, user, command line and granted access rights. Correlate with EDR alerts and subsequent authentication activity.

**Tuning:** establish a baseline for approved endpoint-security components. Do not alert on every LSASS handle request without context.

## DET-04 — PowerShell discovery patterns

**Objective:** identify PowerShell process or script-block activity containing discovery-related commands or suspicious execution patterns.

**Telemetry:** Sysmon Event ID 1 and PowerShell Operational Event ID 4104. These sources may require separate searches and correlation because their schemas differ.

Illustrative script-block search:

```spl
index=windows EventCode=4104
| eval script_text=coalesce(ScriptBlockText, Message)
| where match(script_text,
  "(?i)(Get-ADUser|Get-ADComputer|Get-Service|Get-LocalGroupMember|FromBase64String|DownloadString)")
| table _time host User script_text
| sort 0 _time
```

**Analyst review:** retrieve the complete script block, correlate with process creation and identify the account, parent process, host role and execution frequency.

**Tuning:** keyword matches are leads for investigation, not a maliciousness verdict. Validate benign administration scripts and multiline event handling.

## DET-05 — File staging in an unusual directory

**Objective:** identify file creation in a monitored staging path.

**Telemetry:** Sysmon Event ID 11 or endpoint file telemetry.

```spl
index=sysmon EventCode=11
TargetFilename="*\\ProgramData\\Cache\\*"
| stats count values(TargetFilename) as files
  min(_time) as first_seen max(_time) as last_seen
  by Computer User
| convert ctime(first_seen) ctime(last_seen)
```

**Analyst review:** identify the creating process, file size, hash, source location and subsequent access. Correlate with archive utilities, removable-media events and outbound network records.

## DET-06 — Outbound connection review

**Objective:** identify outbound connections initiated by monitored endpoints and prioritise unusual destinations or processes.

**Telemetry:** Sysmon Event ID 3, firewall or proxy logs.

```spl
index=sysmon EventCode=3 Initiated=true
| stats count values(DestinationIp) as destinations
  values(DestinationPort) as ports
  by Computer Image
| sort - count
```

**Analyst review:** inspect connection state, destination reputation, DNS resolution, process attribution, bytes sent/received and proxy/firewall disposition. A connection attempt is not proof of a completed session or data transfer.

## Correlation approach

For a real investigation, correlate the identity, process, file and network searches using host, user, process GUID, logon ID and bounded time windows. Do not join solely on approximate timestamps where stronger identifiers are available.

The combination of file staging and outbound network activity on one host is a useful investigative lead. It does not prove that the staged files were transmitted.

## Validation plan

- [ ] Confirm index and sourcetype for each telemetry source.
- [ ] Verify field names against raw events.
- [ ] Confirm event collection and retention coverage.
- [ ] Run each search over a documented time range.
- [ ] Review raw events behind aggregated results.
- [ ] Test known-good administrative activity.
- [ ] Test controlled suspicious activity in an isolated lab.
- [ ] Record false positives, missed events and tuning decisions.
- [ ] Preserve query text, screenshots and sample event references.
- [ ] Mark detections as validated only after repeatable testing.

## Current validation status

The searches in this document are proposed hunt logic. They have not been executed against the case telemetry or validated in a Splunk environment as part of this repository. Field names and event availability must be checked before operational use.
