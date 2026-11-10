# BOTSv3 Hunt Workbook

**Dataset:** Splunk Boss of the SOC v3  
**Index:** `botsv3`  
**Execution state:** prepared; not executed in this repository  
**Purpose:** provide a disciplined starting point for source discovery and hypothesis-led investigation.

> These searches are analyst-authored starting points based on sourcetypes published by the dataset maintainers. They are not reported results, validated detections or claims that a particular event exists. Confirm field extraction and event coverage in the local instance before relying on any field.

## 1. Establish the data before hunting

### H-001: Sourcetype inventory

```spl
| metadata type=sourcetypes index=botsv3
| eval first_seen=strftime(firstTime,"%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| table sourcetype totalCount first_seen last_seen
| sort - totalCount
```

**Use:** identify which source families are actually populated and their time coverage.  
**Record:** output export, search job ID, execution time, total rows and any missing expected sources.

### H-002: Host and source distribution

```spl
| tstats count WHERE index=botsv3 BY host sourcetype
| sort - count
```

**Use:** establish which hosts generate which telemetry.  
**Caution:** host values may represent cloud resources, collectors or endpoints; validate entity meaning before correlating.

### H-003: Event-time range

```spl
index=botsv3 earliest=0
| stats count AS events min(_time) AS first_event max(_time) AS last_event
| eval first_event=strftime(first_event,"%Y-%m-%d %H:%M:%S %Z"),
       last_event=strftime(last_event,"%Y-%m-%d %H:%M:%S %Z")
```

**Use:** prevent incorrect time-picker assumptions. BOTSv3 is a historical dataset; use its actual event-time range, not the current date.

## 2. Cloud control-plane and identity

### H-010: AWS CloudTrail event distribution

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| spath
| stats count AS events dc(userIdentity.arn) AS principals
        values(eventSource) AS services
        by eventName
| sort - events
```

**Question:** which API operations dominate the CloudTrail data, and which deserve closer inspection?  
**Pivot:** inspect the raw events for a selected event name; then group by principal, source IP, user agent, region and error status.  
**Caution:** high event volume is not maliciousness. Automated service activity is common.

### H-011: AWS principal activity

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| spath
| stats count AS events
        dc(eventName) AS distinct_api_calls
        values(eventName) AS api_calls
        values(sourceIPAddress) AS source_ips
        values(userAgent) AS user_agents
        by userIdentity.arn
| sort - events
```

**Question:** are there principals with an unusual breadth of API activity or unexpected source context?  
**Pivot:** select one principal and inspect its chronological events. Compare activity with the principal type, role purpose and expected automation.  
**Caution:** do not treat a service role, assumed role or unfamiliar user agent as malicious without context.

### H-012: GuardDuty findings

```spl
index=botsv3 sourcetype=aws:cloudwatch:guardduty earliest=0
| spath
| table _time id type severity title accountId region
        resource.instanceDetails.instanceId
        service.action.actionType
| sort 0 - _time
```

**Question:** are there provider-generated findings that can guide a deeper investigation?  
**Pivot:** inspect the complete finding JSON, affected resource, actor context and related CloudTrail/VPC flow records.  
**Caution:** field paths depend on the event's JSON structure. Run `spath` and inspect raw data if columns are empty.

## 3. Microsoft identity and SaaS

### H-020: Azure AD sign-in activity

```spl
index=botsv3 sourcetype=ms:aad:signin earliest=0
| fieldsummary
```

This is deliberately a schema-discovery search. Review the returned field names and sample raw events before writing an aggregation. Then use the fields actually present to examine user, source IP, application, location, device context and result/status.

### H-021: Azure AD audit activity

```spl
index=botsv3 sourcetype=ms:aad:audit earliest=0
| fieldsummary
```

**Question:** which directory operations and actor/object fields are available?  
**Pivot:** inspect high-impact operations, actor identity, target object, result and adjacent events. Confirm whether the operation succeeded.

### H-022: Office 365 management activity

```spl
index=botsv3 (sourcetype=ms:o365:management OR sourcetype=o365:management:activity) earliest=0
| fieldsummary
```

**Question:** what operation, actor, workload and client context can be reconstructed?  
**Caution:** do not assume the two sourcetypes share an identical schema. Profile them separately if their fields differ.

## 4. Endpoint and network

### H-030: Windows event distribution

```spl
index=botsv3 sourcetype=wineventlog earliest=0
| stats count AS events by host EventCode
| sort host - events
```

**Question:** which Windows event IDs are present on each host?  
**Pivot:** choose an event ID relevant to a specific hypothesis, inspect raw records and confirm the channel and provider. Do not assume that a familiar EventCode has identical field extraction across all records.

### H-031: Sysmon process-event schema

```spl
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" earliest=0
| fieldsummary
```

After schema review, inspect process-creation events using the event identifier field confirmed in the raw records. Look for process image, command line, parent image, user, process GUID and parent process GUID where present. Use GUIDs for process lineage where available; PIDs can be reused.

### H-032: DNS activity

```spl
index=botsv3 sourcetype=stream:dns earliest=0
| fieldsummary
```

After confirming the field names, profile query names, source addresses, response codes and record types. Pivot from a domain to the requesting host and then to HTTP/TCP records where the available identifiers and time context support the relationship.

### H-033: HTTP activity

```spl
index=botsv3 sourcetype=stream:http earliest=0
| fieldsummary
```

After confirming fields, examine method, host, URI, user agent, source/destination addresses, response code and byte counts where present. A request path or unusual method is a lead, not proof of exploitation or successful transfer.


## 5. Fixture-informed hunts for full-index validation

The following searches are based on fields visible in the selected upstream
fixture records. Confirm that the full BOTSv3 index has the same field
extractions before treating results as complete.

### H-040: AWS console sign-ins without MFA

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| spath
| search eventName=ConsoleLogin responseElements.ConsoleLogin=Success additionalEventData.MFAUsed=No
| table _time userIdentity.userName userIdentity.arn sourceIPAddress userAgent additionalEventData.MFAUsed eventID
| sort 0 _time
```

**Question:** which successful console sign-ins in the full index record no MFA?
Compare source IP, user agent, principal and surrounding CloudTrail activity.
Do not equate missing MFA with compromise.

### H-041: S3 bucket ACL enumeration

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0 eventSource=s3.amazonaws.com eventName=GetBucketAcl
| spath
| stats count AS acl_checks dc(requestParameters.bucketName) AS distinct_buckets
        values(requestParameters.bucketName) AS buckets
        values(sourceIPAddress) AS source_ips
        dc(userIdentity.accessKeyId) AS distinct_temporary_credentials
        by userIdentity.userName userIdentity.arn
| sort - acl_checks
```

**Question:** are principals inspecting many buckets in a short period?
Expand the matching principal's raw event sequence and distinguish ACL
enumeration from subsequent object access.

### H-042: Coinhive DNS lookups

```spl
index=botsv3 sourcetype=stream:dns earliest=0
| search name="*coinhive.com" OR query="*coinhive.com"
| eval queried_domain=coalesce(name,query), client=coalesce(src_ip,src)
| stats count values(message_type) AS dns_message_types
        values(host_addr) AS resolved_addresses
        by client queried_domain
| sort - count
```

**Question:** which clients queried Coinhive-related domains, and are there
matching DNS responses? DNS activity alone does not establish code execution.

### H-043: Hidden PowerShell and registry-backed execution

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=0 EventCode=1
| search Image="*powershell.exe" CommandLine="*IEX*" CommandLine="*FromBase64String*"
| table _time host Computer User ParentImage ParentCommandLine Image CommandLine ProcessGuid ParentProcessGuid
| sort 0 _time
```

**Question:** where does this execution pattern occur, what launched it, and
which process GUIDs support lineage? Validate the actual sourcetype spelling
and field names from raw events first.

### H-044: Azure AD successful sign-ins from a shared IP

```spl
index=botsv3 sourcetype=ms:aad:signin earliest=0
| search loginStatus=Success
| stats dc(userPrincipalName) AS distinct_users
        values(userPrincipalName) AS users
        values(appDisplayName) AS applications
        values(location.country) AS countries
        by ipAddress
| where distinct_users > 1
| sort - distinct_users
```

**Question:** do multiple identities authenticate successfully from one
source IP? Enrich with device, session, authentication and conditional-access
context before assigning risk.

### H-045: Anonymous sharing and mailbox changes

```spl
index=botsv3 sourcetype=ms:o365:management earliest=0
| search Operation=AnonymousLinkCreated OR Operation=AnonymousLinkUsed OR Operation=Set-Mailbox
| table _time Operation UserId ClientIP Workload SourceFileName ObjectId Param_Name Param_Value ResultStatus
| sort 0 _time
```

**Question:** which users created or consumed anonymous links, and which
mailbox changes followed? Validate actor privileges, target objects and
change authorization. A shared link is not proof that a file was executed
or that data was stolen.


## 5. Correlation discipline

Use this order when connecting records:

1. **Same source record:** preserve the original event and its identifying fields.
2. **Stable entity key:** principal ID, ARN, user ID, host, process GUID, request ID or session ID.
3. **Supporting context:** source/destination tuple, application, user agent, resource ID and event time.
4. **Time window:** state why the window is appropriate; do not silently widen it until events appear related.
5. **Alternative explanation:** automation, shared NAT, legitimate admin activity, scheduled jobs, clock skew or parser behaviour.

Avoid broad `join` operations as the default. Prefer targeted pivots and small, inspectable result sets. Where correlation uses only time and IP, describe it as a lead rather than attribution.

## 6. Search record

For every executed hunt, preserve:

| Field | Required value |
|---|---|
| Hunt ID | H-xxx |
| Execution time | UTC timestamp |
| Time range | Exact absolute range or documented `earliest` / `latest` |
| SPL | Exact executed search |
| Search/job ID | Splunk identifier |
| Result count | Actual returned count |
| Field validation | Fields confirmed from raw events |
| Event references | Evidence IDs from the evidence log |
| Outcome | Supported / rejected / unresolved |
| Export | Filename, format and SHA-256 if retained |

Do not change a query after execution without recording the revised version. Keep the original search alongside the final one so another analyst can reproduce the pivot.

## 7. Exit criteria

A hunt is ready to become a finding only when the relevant raw events have been inspected, the key fields are understood, the event sequence is reproducible and plausible benign explanations have been considered. A hunt is ready to become a detection only after testing against both relevant and benign activity, documenting coverage gaps and defining useful alert context.
