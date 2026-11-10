# Detection Analysis

<sub>Illustrative Splunk SPL · Synthetic scenario · Not executed or validated</sub>

This document translates the simulated findings into detection opportunities. The searches are starting points, not production-ready detections. Confirm the actual index, sourcetype, field names, CIM mapping, data coverage and time range before use.

## Detection 1 — Privileged service account used from an unusual source

**Objective:** identify successful network logons for service identities from hosts outside an approved source list.

**Relevant telemetry:** Windows Security Event ID 4624; fields commonly include `TargetUserName`, `IpAddress`, `LogonType`, `ComputerName`.

Illustrative SPL:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624
TargetUserName="svc-backup" Logon_Type=3
| stats count min(_time) as first_seen max(_time) as last_seen
  values(ComputerName) as destination_hosts
  values(IpAddress) as source_ips
  by TargetUserName
| convert ctime(first_seen) ctime(last_seen)
```

**Tuning:** use an approved service-account inventory and known source-host list. Exclude only documented, reviewed service patterns. Alert on new source hosts, unexpected logon types or unusual time windows.

**Validation:** test known-good backup activity and a controlled logon from a non-approved host. Confirm both alert behaviour and expected exclusions.

## Detection 2 — WMI-associated remote process execution

**Objective:** identify WMI provider processes spawning command interpreters or scripting engines.

**Relevant telemetry:** Sysmon Event ID 1 or Windows Security Event ID 4688 with process-creation auditing.

Illustrative SPL:

```spl
index=sysmon EventCode=1
ParentImage="*\\WmiPrvSE.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time Computer User ParentImage Image CommandLine ProcessGuid ParentProcessGuid
| sort 0 _time
```

**Tuning:** WMI is widely used by legitimate management products. Baseline approved management servers, administrators, software deployment tools and recurring commands. Do not suppress all WMI activity.

**Validation:** generate a benign WMI process-creation test in an isolated lab and verify that the expected parent/child relationship is collected.

## Detection 3 — Suspicious LSASS process access

**Objective:** surface processes accessing LSASS outside expected security-product behaviour.

**Relevant telemetry:** Sysmon Event ID 10. Field names vary by Sysmon version and extraction.

Illustrative SPL:

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| stats count values(GrantedAccess) as access_masks
  values(SourceImage) as source_processes
  values(Computer) as hosts
  by SourceImage
| sort - count
```

**Tuning:** establish a baseline of approved EDR, antivirus and Windows components. Review process signer, hash, path, user context and granted access rights. Avoid a simplistic rule that treats every LSASS handle request as malicious.

**Validation:** use a safe, controlled test procedure in a disposable lab. Confirm that telemetry is generated and that approved security software does not create unmanageable noise.

## Detection 4 — PowerShell discovery and suspicious execution

**Objective:** correlate PowerShell process creation with script-block content that performs discovery or uses suspicious execution patterns.

**Relevant telemetry:** Sysmon Event ID 1, PowerShell Operational Event ID 4104, and optionally 4103.

Illustrative SPL:

```spl
(index=sysmon EventCode=1 Image="*\\powershell.exe")
OR (index=windows EventCode=4104)
| eval process_context=coalesce(CommandLine, ScriptBlockText)
| where match(process_context,
  "(?i)(Get-ADUser|Get-ADComputer|Get-Service|Get-LocalGroupMember|FromBase64String|DownloadString)")
| table _time host User Image process_context
| sort 0 _time
```

**Tuning:** this is a keyword hunt, not a reliable maliciousness classifier. Validate field availability and multiline script-block handling. Use user, parent process, signer, host role and prevalence to prioritise results.

**Validation:** test benign administrative scripts and controlled suspicious command patterns. Measure false positives and ensure script-block logging is enabled where policy permits.

## Detection 5 — File staging followed by outbound connection

**Objective:** identify unusual file creation in staging locations followed by outbound connections from the same host.

**Relevant telemetry:** Sysmon Event ID 11, endpoint file telemetry, firewall, proxy or network connection logs.

Illustrative SPL for staging file creation:

```spl
index=sysmon EventCode=11
TargetFilename="*\\ProgramData\\Cache\\*"
| stats count values(TargetFilename) as files
  min(_time) as first_seen max(_time) as last_seen
  by Computer User
| convert ctime(first_seen) ctime(last_seen)
```

Illustrative SPL for outbound connections:

```spl
index=sysmon EventCode=3
Initiated=true
| stats count values(DestinationIp) as destinations
  values(DestinationPort) as ports
  by Computer Image
| sort - count
```

**Correlation requirement:** correlate on host and time window, then investigate the responsible process and transfer outcome. A file created in a staging directory and an outbound connection on the same host do not, by themselves, prove the file was transmitted.

## Validation checklist

- [ ] Confirm index, sourcetype and field extraction.
- [ ] Confirm source event IDs and logging coverage.
- [ ] Run against a defined, documented time range.
- [ ] Review raw events behind every aggregate.
- [ ] Test known-good administrative behaviour.
- [ ] Test a safe, controlled suspicious behaviour.
- [ ] Record false positives, missed events and tuning decisions.
- [ ] Capture the exact SPL version and result screenshots.
- [ ] Mark the detection as tested only after evidence is retained.

## Operational limitations

These examples do not include risk scoring, suppression windows, notable-event creation, CIM data-model acceleration or response automation. Add those only after confirming the telemetry and validating the core logic. Never deploy a search as a blocking or automated response rule solely because it appears plausible in a document.
