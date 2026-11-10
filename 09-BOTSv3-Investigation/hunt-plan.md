# Hunt Plan and SPL

## Operating principle

The first searches establish what data exists. Subsequent hunts must be selected from the observed telemetry and investigative leads. Do not assume that every source family is complete or that an event with a suspicious name is malicious.

The searches below are starting points. They are not validated detections and must be adjusted after inspecting the actual event structure.

## Phase 1: Dataset orientation

Run the inventory searches in [Environment and Data Map](environment-and-data-map.md) and retain their output. Confirm the index, time range, hosts, sourcetypes and event counts before proceeding.

## Phase 2: Candidate investigative threads

Select one or two threads only after reviewing source coverage. The following are candidate directions based on the telemetry types documented by Splunk.

### Hunt A: Cloud identity and control-plane activity

**Question:** Are there unusual identity or administrative actions in the cloud audit records that warrant correlation with endpoint or network activity?

Initial event review:

```spl
index=botsv3 sourcetype=aws:cloudtrail earliest=0
| table _time userIdentity.type userIdentity.arn eventSource eventName sourceIPAddress userAgent errorCode
| sort 0 _time
```

**Caution:** AWS field extraction varies. Inspect raw events and verify the field paths before relying on the table. A cloud API call is not inherently malicious.

Potential pivots:
- Identity ARN or principal ID.
- Source IP and user agent.
- Event name and service.
- Credential session context, where available and appropriate to retain.
- Related activity in CloudWatch, GuardDuty, VPC flow or S3 access logs.

### Hunt B: Microsoft identity activity

**Question:** Does sign-in or directory audit activity show an account, source, application or sequence that merits deeper review?

```spl
index=botsv3 (sourcetype=ms:aad:signin OR sourcetype=ms:aad:audit) earliest=0
| table _time sourcetype user userPrincipalName appDisplayName ipAddress operationName resultType status
| sort 0 _time
```

**Caution:** The field names above are candidate fields. Validate them against raw events. Do not interpret failed sign-ins, unfamiliar IPs or administrative operations in isolation.

Potential pivots:
- User principal name and immutable identity identifiers.
- Source IP, application and device context.
- Result or status fields.
- Directory object and operation.
- Related Office 365 management activity.

### Hunt C: Windows process and authentication activity

**Question:** Is there a process or logon sequence that can be reconstructed across Windows event records?

```spl
index=botsv3 (sourcetype=wineventlog OR sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) earliest=0
| table _time host sourcetype EventCode EventID Channel Image CommandLine ParentImage User TargetUserName Source_Network_Address
| sort 0 _time
```

**Caution:** Windows field extractions and event identifiers differ by source and add-on. Confirm the event ID field and inspect raw records before writing event-specific logic.

Potential pivots:
- Host and account.
- Logon ID / Logon GUID where present.
- Process GUID, parent process GUID and process ID.
- Image, command line and parent image.
- Event time and channel.

### Hunt D: DNS, HTTP and network relationships

**Question:** Can endpoint, identity or cloud activity be correlated with network resolution and connection records?

```spl
index=botsv3 (sourcetype=stream:dns OR sourcetype=stream:http OR sourcetype=stream:tcp) earliest=0
| table _time sourcetype src_ip dest_ip query{} url http_method http_user_agent dest_port
| sort 0 _time
```

**Caution:** Field names vary by Stream version and event type. Inspect raw records first. A DNS query or HTTP request alone does not prove compromise or data exfiltration.

Potential pivots:
- Source and destination IP.
- Query name, URL, method and user agent.
- Destination port and protocol.
- Related endpoint process or cloud identity event.
- Response, byte-count and connection disposition fields, where available.

## Phase 3: Correlation

Use stable identifiers wherever possible. Preferred correlation keys include:
- User / principal identifiers.
- Hostname and endpoint identifiers.
- Process GUIDs and process IDs, with PID reuse considered.
- Cloud request IDs, session identifiers and access-key identifiers.
- Source/destination tuples with a defensible time window.

A shared timestamp or IP address alone is weak correlation. Record the reason each event is believed to be related.

## Phase 4: Finding standard

Each finding must contain:

1. **Question:** what the analyst was trying to establish.
2. **Evidence:** event IDs or stable references, source type, host, timestamp and relevant fields.
3. **Observation:** what the raw records directly show.
4. **Assessment:** why the behaviour is notable in context.
5. **Alternative explanations:** legitimate administration, automation, expected software behaviour, NAT, shared infrastructure or logging artefacts.
6. **Confidence:** low, moderate or high, with a reason.
7. **Impact:** what is established and what remains unknown.
8. **Next pivot:** the record or source needed to confirm or refute the assessment.

## Phase 5: Detection engineering

Only promote a hunt into a detection after:
- The search has been executed against the dataset.
- The required fields and event coverage are confirmed.
- The event sequence is understood.
- Benign examples and likely false positives have been reviewed.
- Thresholds, exclusions and time windows have a documented rationale.
- The alert output includes useful analyst context.

A query that returns interesting events is not automatically a production-ready detection.

## Execution record

For every executed search, record:
- Hunt ID and date/time executed.
- Exact SPL and time range.
- Splunk job/search ID.
- Number of results.
- Important event references.
- Whether the hypothesis was supported, rejected or unresolved.
- Export filename and SHA-256, if an export was retained.
