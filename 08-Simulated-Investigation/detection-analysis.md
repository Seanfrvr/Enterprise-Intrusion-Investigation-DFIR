# Detection Engineering Analysis
### Northstar Logistics | Splunk SPL Hunt Logic

These searches translate the case's investigative questions into practical hunt logic. They are starting points, not validated detections. The examples assume common Windows XML and Sysmon field extractions; confirm actual field names, index, sourcetype, event coverage and time range before use.

## DET-01: Service-account logon from an unexpected source

**Objective:** identify successful network logons for a privileged service identity and expose source hosts for baseline comparison.

**Telemetry:** Windows Security Event ID 4624 on the destination host. Event ID 4769 on a domain controller can provide Kerberos service-ticket context.

```spl
index=windows sourcetype="XmlWinEventLog:Security" EventCode=4624
TargetUserName="svc-backup" LogonType=3
| eval source_ip=coalesce(IpAddress, Source_Network_Address)
| stats count min(_time) as first_seen max(_time) as last_seen
  values(host) as destination_hosts
  values(source_ip) as source_ips
  values(TargetLogonId) as logon_ids
  values(AuthenticationPackageName) as auth_packages
  by TargetUserName
| convert ctime(first_seen) ctime(last_seen)
```

**Analyst review:** inspect raw events. Validate source IP-to-host mapping, destination host, logon type, authentication package and Logon ID. Compare against an approved service-account source-host baseline.

**Important:** field names vary by Windows event format. Some extractions use `Logon_Type`, `Target_Username` or other names. Confirm the raw event before relying on the search. A domain-controller Event ID 4769 is not a substitute for the destination server's Event ID 4624.

## DET-02: WMI provider spawning command interpreters

**Objective:** identify WMI provider processes spawning command shells or scripting engines.

**Telemetry:** Sysmon Event ID 1.

```spl
index=sysmon EventCode=1
ParentImage="*\\WmiPrvSE.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User ParentImage Image CommandLine
  ProcessGuid ParentProcessGuid ProcessId ParentProcessId Hashes
| sort 0 _time
```

**Analyst review:** inspect full process ancestry, user context, command line, signer, hash and related network activity. Correlate with WMI-Activity Operational records to identify the client machine and operation where those fields are logged.

**Tuning:** baseline approved management platforms and deployment tooling. WMI is legitimate administration; the parent process alone does not prove remote or malicious execution.

## DET-03: Unusual access to LSASS

**Objective:** surface processes accessing LSASS and retain context needed to distinguish security tooling from suspicious activity.

**Telemetry:** Sysmon Event ID 10.

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| table _time host User SourceImage SourceProcessGuid SourceProcessId
  TargetImage GrantedAccess CallTrace
| sort 0 _time
```

**Analyst review:** inspect source process path, signer, hash, parent process, user and granted access mask. Correlate with EDR alerts, file creation and subsequent authentication. Do not infer successful credential extraction from Event ID 10 alone.

## DET-04: PowerShell discovery patterns

**Objective:** identify script-block content containing discovery-related commands or suspicious execution patterns.

**Telemetry:** PowerShell Operational Event ID 4104.

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval script_text=coalesce(ScriptBlockText, Message)
| where match(script_text,
  "(?i)(Get-ADUser|Get-ADComputer|Get-Service|Get-LocalGroupMember|FromBase64String|DownloadString)")
| table _time host User ProcessID ScriptBlockId script_text
| sort 0 _time
```

**Analyst review:** retrieve all fragments for the same ScriptBlockId, where available, and correlate with process creation, account, parent process and host role.

**Tuning:** keyword matches are investigative leads, not a maliciousness verdict. Validate benign administrative scripts and multiline event handling.

## DET-05: File creation in a staging path

**Objective:** identify file creation in a monitored directory and retain the creating process.

**Telemetry:** Sysmon Event ID 11.

```spl
index=sysmon EventCode=11
TargetFilename="*\\ProgramData\\Cache\\*"
| table _time host User Image ProcessGuid TargetFilename
| sort 0 _time
```

**Analyst review:** identify the creating process and compare staged files with source files using names, sizes, hashes and timestamps. Event ID 11 records file creation; it does not independently establish the source file or copy mechanism.

## DET-06: Outbound network activity

**Objective:** identify outbound network connections and retain process and destination context.

**Telemetry:** Sysmon Event ID 3, firewall and proxy logs.

```spl
index=sysmon EventCode=3 Initiated=true
| table _time host User Image ProcessGuid SourceIp SourcePort
  DestinationIp DestinationPort Protocol
| sort 0 _time
```

**Analyst review:** inspect process attribution, destination, DNS context, firewall disposition, connection state and bytes sent/received. Confirm whether the connection was allowed, blocked or reset using network-control telemetry.

## DET-07: File staging and outbound activity on the same host

**Objective:** prioritise hosts with file creation in the monitored staging path and outbound connections in the same short time window.

```spl
(index=sysmon EventCode=11 TargetFilename="*\\ProgramData\\Cache\\*")
OR (index=sysmon EventCode=3 Initiated=true)
| eval activity=case(EventCode=11, "staging", EventCode=3, "outbound")
| bin _time span=15m
| stats count(eval(activity="staging")) as staging_events
  count(eval(activity="outbound")) as outbound_events
  values(TargetFilename) as staged_paths
  values(DestinationIp) as destinations
  values(DestinationPort) as destination_ports
  values(Image) as processes
  by host _time
| where staging_events>0 AND outbound_events>0
| sort 0 _time
```

**Interpretation:** this is a prioritisation hunt based on host and time-window co-occurrence. It does not prove that a staged file was transmitted. Review the raw events and correlate process identifiers, network records and transfer evidence.

## Correlation approach

Prefer stable identifiers over timestamp proximity:

- **Identity:** account SID, TargetLogonId, SubjectLogonId and source address.
- **Process:** ProcessGuid, ParentProcessGuid, PID and parent PID.
- **WMI:** client machine, user, operation and client process ID where available.
- **Files:** path, creating process, file size, timestamps and SHA-256.
- **Network:** process, source/destination tuple, disposition, session state and byte counts.

Do not join unrelated event sources solely because their timestamps are close. Use bounded time windows only when stronger identifiers are unavailable, and label the result as temporal correlation.

## Validation plan

- [ ] Confirm index, sourcetype and field extraction for each source.
- [ ] Inspect raw events and verify field names.
- [ ] Confirm event collection, audit policy and retention coverage.
- [ ] Run each search over a documented time range.
- [ ] Review raw events behind every aggregate.
- [ ] Test known-good administrative activity.
- [ ] Test controlled suspicious activity in an isolated lab.
- [ ] Record false positives, missed events and tuning decisions.
- [ ] Preserve query text, sample event references and screenshots.
- [ ] Mark detections as validated only after repeatable testing.

## Current validation status

These searches are proposed hunt logic. They have not been executed against primary case telemetry or validated in a Splunk environment as part of this repository. Field names and event availability must be confirmed before operational use.
