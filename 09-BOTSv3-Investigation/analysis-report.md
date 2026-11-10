# BOTSv3 investigation report

## Executive summary

A review of six selected BOTSv3-derived event extracts identified several
security-relevant activity clusters across cloud identity, endpoint and network
telemetry. The extracts contain 83 records across six source families. The
strongest observations are:

1. AWS CloudTrail records attribute successful console sign-ins without MFA
 and a burst of S3 `GetBucketAcl` calls to IAM user `bstoll`.
2. DNS records show an internal client querying multiple Coinhive-related
 domains.
3. Sysmon records show hidden PowerShell execution on `FYODOR-L`, including
 a command that retrieves a registry value and decodes it before invoking
 `IEX`.
4. Azure AD records show successful sign-ins for `fyodor` and `bgist` from
 the same IP address, with Hong Kong location metadata.
5. Office 365 management records show creation and use of an anonymous link
 to a `.lnk` file, followed by Exchange mailbox modifications.

These observations are supported by the committed fixture extracts. They
justify investigation and detection development, but the extracts are partial.
They do not establish the full attack chain, initial access, credential theft,
data exfiltration, or complete business impact. Full-index validation remains
outstanding.

## Scope and method

The analysis covered the six attributed files under [data/fixtures](data/fixtures/).
The fixture inventory contains 83 records:

| Fixture | Records |
|---|---:|
| AWS CloudTrail / `bstoll` | 20 |
| BSTOLL-L Windows logon excerpt | 11 |
| Coinhive DNS excerpt | 12 |
| FYODOR-L Sysmon excerpt | 4 |
| Azure AD sign-ins | 20 |
| Office 365 management | 16 |
| **Total** | **83** |

The Python pipeline parses the committed JSONL, preserves the source file and
line reference, normalizes common fields, calculates local SHA-256 hashes, and
generates a UTC timeline for timestamped events. The AWS fixture has been
sanitized to replace temporary access key identifiers. The local integrity
hashes describe the sanitized file bytes. The counts above describe
only the selected extracts, not the complete BOTSv3 index.

## Findings

### F-01: AWS console access without MFA and S3 bucket reconnaissance

**Source:** `01-aws-recon-bstoll.jsonl`, records 1 to 20 
**Observed identity:** IAM user `bstoll` 
**Observed source IPs:** `107.77.212.175`, `157.97.121.132`

Four CloudTrail console sign-in records show `ConsoleLogin` with a successful
response. Their `additionalEventData.MFAUsed` value is `No`. The same fixture
contains repeated S3 `GetBucketAcl` calls attributed to `bstoll`, including
requests for multiple bucket names. Several calls occur within the same
second, which is consistent with scripted or automated enumeration, although
the records alone do not identify the operator or tool.

**Assessment:** suspicious cloud account activity and probable bucket
reconnaissance. Lack of MFA increases account exposure but does not itself
prove compromise. The source IP and user-agent context should be compared
with known user activity and other CloudTrail actions.

**Next pivots:** inspect all events for the principal ID, session context and related API activity;
review `ListBuckets`, `GetObject`, `ListObjects`, IAM policy and access-key
operations; identify bucket contents and access outcomes; correlate with
GuardDuty and network telemetry.

**Confidence:** high for the recorded actions; moderate for malicious
reconnaissance; no conclusion on data access or exfiltration.

### F-02: BSTOLL-L logon excerpt is insufficient to rule out remote access

**Source:** `02-bstoll-l-endpoint.jsonl`, records 1 to 11 
**Host:** `BSTOLL-L`

The selected excerpt contains successful logon events for SYSTEM (type 5),
DWM-1 (type 2), and `bstoll` (type 11, source address 127.0.0.1). It does not
show a remote-interactive type 10 event in these 11 records.

**Assessment:** this narrow extract does not demonstrate remote interactive
logon, but it is not sufficient to conclude that the host had no remote
access. It is a curated excerpt, not a complete Security event log.

**Next pivots:** query the complete host history for 4624/4625, logon types
3, 10 and 9, source workstation/address, account SID, authentication package,
and adjacent 4648/4672/4768/4769 events. Correlate with RDP, VPN and endpoint
process telemetry.

**Confidence:** high for the listed records; low for any broader negative
claim.

### F-03: Coinhive-related DNS activity from an internal client

**Source:** `03-bstoll-coinhive-cryptojacking.jsonl`, records 1 to 12 
**Client:** `192.168.247.131` 
**Queried names:** `coinhive.com` and multiple `wsNNN.coinhive.com` names

The extract contains six DNS query records from the same internal client for
Coinhive-related domains and six corresponding DNS response records. The
responses include successful `NoError` replies and resolved addresses.

**Assessment:** the DNS activity is consistent with a client contacting
Coinhive infrastructure. DNS alone cannot prove that mining code executed,
identify the responsible process, or attribute the activity to a user. The
upstream scenario labels this activity as Coinhive cryptojacking; this
repository treats the selected DNS events as corroborating network evidence,
not standalone proof of resource abuse.

**Next pivots:** map the internal IP to DHCP/asset inventory at the event
time; inspect HTTP/TLS records, browser history/cache, endpoint process
creation and CPU/resource telemetry; search for related Coinhive domains
across the full dataset.

**Confidence:** high for the DNS queries and responses; moderate for Coinhive
infrastructure contact; insufficient alone to prove cryptojacking.

### F-04: Hidden PowerShell execution on FYODOR-L

**Source:** `04-fyodor-powershell-empire.jsonl`, records 1 to 4 
**Host:** `FYODOR-L`

Two Sysmon Event ID 1 records show PowerShell executing with hidden-window
and non-interactive options. The command retrieves a value named `debug`
from `HKLM:\Software\Microsoft\Network`, Base64-decodes it as Unicode,
and passes the result to `IEX`. One record shows a PowerShell parent; another
shows `svchost.exe` hosting the Task Scheduler service as parent, with the
process running as SYSTEM. Two additional records on `BGIST-L` concern
Dropbox OEM package removal and are not treated as part of this finding.

**Assessment:** the FYODOR-L command pattern is strongly suspicious and
consistent with registry-stored script execution and scheduled execution.
The fixture does not include the full registry, task scheduler or network
evidence needed to establish the complete persistence and command-and-control
mechanism.

**Next pivots:** retrieve the registry value and decode it as an artefact;
review Task Scheduler Operational events and task XML; inspect Sysmon Event
IDs 12to14, 3, 7 and 11; review PowerShell 4103/4104, Prefetch, Amcache and
correlated outbound connections. Preserve the decoded content as evidence
before analysis.

**Confidence:** high for the observed command line; moderate-to-high for
malicious intent; persistence and payload behaviour require corroboration.

### F-05: Azure AD sign-ins for two identities from a shared Hong Kong IP

**Source:** `05-azure-ad-signin-anomaly.jsonl`, records 1 to 20 
**Identities:** `fyodor@froth.ly`, `bgist@froth.ly` 
**IP:** `104.207.83.63`

The selected records include successful sign-ins for both identities from
`104.207.83.63`. The event payloads identify Hong Kong as the location.
The records span multiple Microsoft 365 applications.

**Assessment:** shared successful sign-ins from the same IP across two
accounts warrant investigation, particularly when considered alongside
the FYODOR-L PowerShell activity and Office 365 operations. The fixture
does not establish that the endpoint and cloud sessions were controlled by
the same actor. IP geolocation is contextual metadata and may be affected by
VPNs, proxies or service routing.

**Next pivots:** validate sign-in risk, device ID, client application,
conditional-access result, authentication details, MFA claims and session
correlation IDs; compare historical geolocation and user travel; inspect
token issuance and subsequent cloud audit events.

**Confidence:** high for the recorded successful sign-ins and IP/location
fields; moderate for suspicious account use; attribution remains unproven.

### F-06: Anonymous OneDrive link activity and Exchange mailbox changes

**Source:** `06-o365-cloud-account-abuse.jsonl`, records 1to16

The extract shows `bgist@froth.ly` creating an anonymous sharing link for
`BRUCE BIRTHDAY HAPPY HOUR PICS.lnk`, followed by a `SharingSet` event and
multiple `AnonymousLinkUsed` events from different client IPs. Later
Exchange management events show `Set-Mailbox` operations against
`klagerfield` and `bgist`. One event records `StsRefreshTokensValidFrom`
for `klagerfield`; another sets `AccountDisabled=True` for `bgist`.

**Assessment:** the anonymous sharing activity is consistent with exposure
of a Windows shortcut file through an externally accessible link. A
shortcut file can be used as a lure, but the audit record does not prove
that recipients executed it or that it delivered malware. The mailbox
changes are high-impact administrative actions and should be validated
against authorized change records and the actor's role.

**Next pivots:** inspect the full audit payloads and sharing permissions;
identify all link consumers and access outcomes; retrieve the file hash and
content from a preserved copy; correlate recipients with endpoint telemetry;
validate the Exchange actor, admin role, source session and change ticket;
review token revocation and account-disable workflow.

**Confidence:** high for the logged link and mailbox operations; moderate
for suspicious intent; no claim of successful malware execution or data theft.

## Cross-source correlation

The fixture extracts provide several useful pivots:

- `bstoll` appears in AWS CloudTrail, the BSTOLL-L logon excerpt and the
 Azure/Office 365 identity context. The names are related in the source
 scenario, but identity linkage should still be verified against directory
 identifiers and timestamps in the complete data.
- `fyodor@froth.ly` appears in Azure AD and Office 365 records; the
 `FYODOR-L` Sysmon records use the display identity
 `AzureAD\\FyodorMalteskesko`.
- `104.207.83.63` appears in successful Azure AD sign-ins for Fyodor and
 Bruce and in Office 365 activity attributed to Bruce.
- `107.77.212.175` appears in AWS CloudTrail and Office 365 sharing activity,
 including a record attributed to `bstoll` and anonymous link use.

These relationships are pivots, not proof that all events share a single
operator. The time windows, identity identifiers, device/session IDs and
raw event context must be validated before constructing a definitive
intrusion timeline.

## ATT&CK hypotheses

| Behaviour | Candidate technique | Evidence basis | Confidence |
|---|---|---|---|
| Cloud account use | T1078.004, Valid Accounts: Cloud Accounts | AWS and Azure AD identity activity | Moderate |
| S3 discovery | T1526, Cloud Service Discovery | Repeated S3 bucket ACL checks | Moderate |
| PowerShell execution | T1059.001, PowerShell | Sysmon process command line | High |
| Scheduled execution | T1053.005, Scheduled Task | Task Scheduler service parent; requires task artefact | Moderate |
| External sharing | T1567, Exfiltration Over Web Service (hypothesis only) | Anonymous sharing link; no proof of data theft | Low |
| Account manipulation | T1098, Account Manipulation (candidate) | Exchange Set-Mailbox changes | Moderate |

ATT&CK mappings are hypotheses tied to observed behaviour. Do not promote
a candidate mapping to confirmed technique without the corresponding
behavioural evidence.

## Detection opportunities

1. Successful AWS console login for IAM users with MFAUsed=No, enriched with
 source IP and user-agent history.
2. High-rate S3 bucket enumeration by a single principal or access key.
3. PowerShell with hidden/non-interactive execution that reads registry
 values and dynamically invokes decoded content.
4. Successful cloud sign-ins for multiple users from one unusual IP, with
 risk/device/conditional-access enrichment.
5. Anonymous sharing-link creation for shortcut/script/executable file types,
 followed by access from multiple external IPs.
6. Exchange Set-Mailbox operations that disable accounts or modify token
 validity, especially when initiated by an unusual actor.

These are detection specifications to test and tune. They are not yet
production-ready detections and have not been measured against the complete
BOTSv3 index or a benign baseline.

## Response recommendations

- Validate affected AWS, Azure AD and Microsoft 365 identities with the
 relevant identity owners and administrators.
- If compromise is confirmed, revoke sessions/tokens, rotate credentials,
 remove unauthorized keys and enforce MFA/conditional access.
- Preserve CloudTrail, Azure sign-in/audit, Office 365 audit and endpoint
 records before retention windows expire.
- Isolate and acquire FYODOR-L if endpoint compromise is confirmed; preserve
 the registry value, scheduled task, process and network artefacts.
- Revoke anonymous sharing links after preserving their metadata and
 determining exposure scope.
- Validate mailbox changes and restore only after establishing the intended
 configuration and business owner approval.

## Limitations and next validation

This report is fixture-backed, not a completed full-dataset case. The full
BOTSv3 archive has not been downloaded or loaded into Splunk in this
workspace. The next validation pass must run the searches in
[hunt-workbook.md](hunt-workbook.md) against the complete `index=botsv3`,
inspect raw records, reconcile field extractions, expand each time window,
capture original Splunk screenshots and update this report only where the
full dataset supports the finding.
