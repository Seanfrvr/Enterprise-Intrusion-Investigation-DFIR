# BOTSv3 cross-platform security investigation

## Executive summary

This report examines six selected BOTSv3 derived event extracts containing
83 records across AWS, Windows, DNS, Sysmon, Azure AD and Office 365 telemetry.
The extracts come from separate scenario folders. They are not a single
continuous incident dataset and do not establish one attacker or one intrusion.

**Central investigative question:** Do the suspicious activities across
Frothly's cloud services, endpoints and Microsoft 365 environment indicate
related security incidents, or are they independent events?

The records support six distinct observations:

1. AWS CloudTrail records show successful console sign ins without MFA and
   repeated S3 `GetBucketAcl` calls attributed to IAM user `bstoll`.
2. The Windows extract contains selected local and system logon events. It
   cannot rule out remote access elsewhere in the host history.
3. DNS records show an internal client querying Coinhive related domains.
4. Sysmon records show hidden PowerShell execution on `FYODOR-L`, including
   registry retrieval, Base64 decoding and dynamic invocation through `IEX`.
5. Azure AD records show successful sign ins for two identities from the
   same IP address, with Hong Kong location metadata.
6. Office 365 records show anonymous sharing link activity involving a
   Windows shortcut file and subsequent Exchange mailbox modifications.

These findings establish observable security-relevant activity across six telemetry sources and provide a structured basis for incident triage, threat hunting and follow-up collection. The report distinguishes directly recorded behaviour from analytical hypotheses and identifies the additional context needed to assess impact and attribution.

## Scope and method

The analysis covers six files in [data/fixtures](data/fixtures/), containing
83 records in total.

| Evidence | Source extract | Records |
|---|---|---:|
| E-001 | AWS CloudTrail activity attributed to bstoll | 20 |
| E-002 | BSTOLL-L Windows logon excerpt | 11 |
| E-003 | Coinhive DNS excerpt | 12 |
| E-004 | FYODOR-L Sysmon PowerShell excerpt | 4 |
| E-005 | Azure AD sign in excerpt | 20 |
| E-006 | Office 365 management excerpt | 16 |
| | **Total** | **83** |

The Python pipeline parses all 83 committed JSONL records, preserves source
filename and line number, normalizes common fields, calculates SHA-256 hashes
for the current local files and generates a UTC timeline for records with
usable timestamps. The current run produced 36 timestamped timeline records;
47 records remain in the normalized output without a usable timestamp. The
AWS fixture replaces temporary access key identifiers with stable redaction
labels. Its local hash therefore describes the sanitized file, not the
unmodified upstream source.

The generated inventory reports six source families and per-fixture counts.
These are counts from the committed extracts only. The generated timeline
retains the original fixture name and one-based line number for traceability.

## Findings

### F-01: AWS console sign ins without MFA and repeated S3 ACL inspection

**Evidence:** E-001  
**Source:** `01-aws-recon-bstoll.jsonl`, records 1 to 20  
**Identity:** IAM user `bstoll`  
**Source IPs:** `107.77.212.175`, `157.97.121.132`

Four CloudTrail console sign in records show a successful `ConsoleLogin`.
Their `additionalEventData.MFAUsed` value is `No`. The same extract contains
repeated S3 `GetBucketAcl` calls attributed to `bstoll`, including requests
for multiple bucket names. Several calls occur within the same second,
consistent with automated or scripted activity.

**Assessment:** the records establish successful console sign ins without
MFA and repeated bucket ACL inspection. They do not establish that the
account was compromised, identify the operator or show that bucket objects
were accessed. Lack of MFA increases exposure but is not proof of compromise.

**Next investigation:** review all CloudTrail activity for the principal and
session context. Look for `ListBuckets`, `ListObjects`, `GetObject`, IAM
policy changes and credential operations. Establish whether the source IPs
and user agents are expected for this identity. Review related GuardDuty
findings and relevant network telemetry.

**Confidence:** high for the recorded API actions and MFA metadata; moderate
for suspicious reconnaissance; no conclusion on object access or exfiltration.

### F-02: BSTOLL-L logon excerpt does not establish remote access history

**Evidence:** E-002  
**Source:** `02-bstoll-l-endpoint.jsonl`, records 1 to 11  
**Host:** `BSTOLL-L`

The 11 records are all Security Event ID 4624. They include five SYSTEM
service logons (type 5), four DWM-1 interactive logons (type 2) and two
`bstoll` cached interactive logons (type 11) with source address
`127.0.0.1`. No remote interactive type 10 logon appears in this selected
excerpt.

**Assessment:** the records show service, interactive and cached interactive
logons in this narrow slice. They do not show a type 10 remote interactive
logon in these 11 records. This is not evidence that remote access did not
occur elsewhere in the host's Security log.

**Next investigation:** search the complete host history for Security events
4624 and 4625, including logon types 3, 9 and 10. Review source workstation,
source address, account SID, authentication package and adjacent events
4648, 4672, 4768 and 4769. Correlate with RDP, VPN and endpoint process data.

**Confidence:** high for the listed records; no broader negative conclusion.

### F-03: Coinhive related DNS activity from an internal client

**Evidence:** E-003  
**Source:** `03-bstoll-coinhive-cryptojacking.jsonl`, records 1 to 12  
**Client:** `192.168.247.131`

The extract contains six DNS query records from the same internal client for
`coinhive.com` and multiple `wsNNN.coinhive.com` names, alongside six
corresponding response records. The responses include successful `NoError`
replies and resolved addresses.

**Assessment:** the records establish DNS activity involving Coinhive related
domains. They do not identify the responsible process or user and do not
prove that mining code executed or consumed system resources. The upstream
scenario describes cryptojacking; this report treats the DNS events as
network evidence that requires endpoint corroboration.

**Next investigation:** map the client IP to a device and user at the event
time. Inspect HTTP and TLS telemetry, browser history, endpoint process
creation and CPU usage. Search the complete dataset for related domains and
connections.

**Confidence:** high for the recorded DNS queries and responses; moderate
for contact with Coinhive infrastructure; insufficient alone to prove
cryptojacking.

### F-04: Hidden PowerShell execution on FYODOR-L

**Evidence:** E-004  
**Source:** `04-fyodor-powershell-empire.jsonl`, records 1 to 4  
**Host:** `FYODOR-L`

Two Sysmon Event ID 1 records show PowerShell executing with hidden window
and non interactive options. The command retrieves a value named `debug`
from `HKLM:\\Software\\Microsoft\\Network`, Base64 decodes it as Unicode
and passes the decoded content to `IEX`. One record shows a PowerShell
parent. Another shows `svchost.exe` hosting the Task Scheduler service as
parent, with the process running as SYSTEM. Two additional records on
`BGIST-L` concern Dropbox OEM package removal and are not included in this
finding.

**Assessment:** the command pattern is strongly suspicious and consistent
with registry stored script execution. The parent process context raises a
scheduled execution hypothesis, but the extract does not contain task
registration events, task XML or the registry value itself. Persistence
and command and control are therefore not confirmed.

**Next investigation:** acquire the registry value and decode it as a
separate artefact. Review Task Scheduler Operational events and task XML.
Inspect Sysmon Event IDs 12 to 14, 3, 7 and 11, PowerShell 4103 and 4104,
Prefetch, Amcache and correlated outbound connections. Preserve the decoded
content before analysis.

**Confidence:** high for the observed command line; moderate to high for
malicious intent; persistence and payload behaviour require corroboration.

### F-05: Azure AD sign ins for two identities from a shared IP

**Evidence:** E-005  
**Source:** `05-azure-ad-signin-anomaly.jsonl`, records 1 to 20  
**Identities:** `fyodor@froth.ly`, `bgist@froth.ly`  
**IP:** `104.207.83.63`

The selected records include successful sign ins for both identities from
`104.207.83.63`. The event payloads identify Hong Kong as the location.
The records span multiple Microsoft 365 applications.

**Assessment:** successful sign ins for two identities from one IP warrant
review, particularly when considered with the separate endpoint and Office
365 extracts. A shared IP may represent a VPN, proxy, corporate gateway or
service routing. The records do not establish that the cloud sessions and
FYODOR-L activity were controlled by the same actor.

**Next investigation:** validate sign in risk, device ID, client application,
conditional access result, authentication details, MFA claims and session
correlation IDs. Compare historical IP use and user travel. Inspect token
issuance and subsequent cloud audit events.

**Confidence:** high for the recorded sign ins and location fields; moderate
for suspicious account use; attribution remains unproven.

### F-06: Anonymous OneDrive link activity and Exchange mailbox changes

**Evidence:** E-006  
**Source:** `06-o365-cloud-account-abuse.jsonl`, records 1 to 16

The extract shows `bgist@froth.ly` creating an anonymous sharing link for
`BRUCE BIRTHDAY HAPPY HOUR PICS.lnk` at 09:58:02 UTC, followed by a
`SharingSet` event one second later. The fixture then records nine
`AnonymousLinkUsed` events for that file, including events attributed to
`anonymous` and one attributed to `bstoll@froth.ly`. The recorded client
IP addresses vary. Later Exchange management events show three
`Set-Mailbox` operations: an application account targets `klagerfield`,
`fyodor@froth.ly` sets `StsRefreshTokensValidFrom` for `klagerfield`,
and `fyodor@froth.ly` sets `AccountDisabled=True` for `bgist`.

**Assessment:** the audit records establish anonymous sharing activity
involving a Windows shortcut file and subsequent mailbox administration.
A shortcut can be used as a lure, but the events do not prove that recipients
executed it or that it delivered malware. The mailbox changes may be
administrative or response actions; their legitimacy depends on actor role,
change authorization and full event context.

**Next investigation:** inspect full audit payloads and sharing permissions.
Identify link consumers and access outcomes. Retrieve the file from a
preserved source and calculate its hash. Correlate recipients with endpoint
telemetry. Validate the Exchange actor, role, session and change ticket.
Establish whether token invalidation and account disablement were authorized
response actions.

**Confidence:** high for the logged link and mailbox operations; intent and
business impact remain unresolved.

## Cross source pivots

Some values recur across the selected extracts. These repetitions can guide
follow up searches, but the source files represent separate scenarios and
the available records do not establish one continuous intrusion.

- The name `bstoll` appears in AWS and Windows context. A matching display
  name is not a stable identity key.
- `fyodor@froth.ly` appears in Azure AD and Office 365 records. The Sysmon
  fixture uses the Windows identity `AzureAD\\FyodorMalteskesko` on
  `FYODOR-L`. Confirm the account and device relationship with directory
  identifiers and endpoint records.
- `104.207.83.63` appears in Azure AD sign ins for two identities and in
  Office 365 activity. A shared public IP may represent a shared gateway,
  VPN or proxy and does not identify the same operator.
- `107.77.212.175` appears in AWS and Office 365 records. Validate event
  times, principal identifiers and session context before treating this as
  a meaningful cross service relationship.

No combined incident timeline is asserted from these overlaps.

## MITRE ATT&CK assessment

| Observed behaviour | Technique | Assessment |
|---|---|---|
| Cloud account use | T1078.004, Valid Accounts: Cloud Accounts | Candidate mapping. Validate principal and session context. |
| PowerShell execution | T1059.001, PowerShell | Supported by the Sysmon process command line. |
| Scheduled execution | Not assigned | Task Scheduler parent is suggestive, but task registration evidence is absent. |
| S3 ACL inspection | Not assigned | `GetBucketAcl` does not by itself establish cloud service or object discovery. |
| Anonymous sharing | Not assigned | Sharing is recorded; exfiltration is not established. |
| Mailbox administration | Not assigned | Review operation parameters and actor permissions before mapping. |

Mappings are limited to behaviours supported by the available records.
Repeated `GetBucketAcl` calls are described as ACL inspection, not cloud
service discovery or object enumeration. The observed calls do not by
themselves establish T1526 or T1619. See
[T1526](https://attack.mitre.org/techniques/T1526/) and
[T1619](https://attack.mitre.org/techniques/T1619/).

## Detection opportunities

1. Successful AWS console sign ins with `MFAUsed=No`, enriched with source
   IP, user agent and principal history.
2. High rate S3 ACL checks by one principal, with bucket count and time window.
3. Hidden PowerShell that reads registry values and dynamically invokes
   decoded content.
4. Successful cloud sign ins for multiple users from one unusual IP, enriched
   with device, session and conditional access context.
5. Anonymous sharing link creation for shortcut, script or executable file
   types, followed by external link use.
6. High impact Exchange mailbox changes from unusual actors or sessions.

These are detection hypotheses, not validated detections. They have not been
tested against the complete BOTSv3 index or a benign activity baseline.

## Response considerations

- Validate affected AWS, Azure AD and Microsoft 365 identities with their
  owners and administrators.
- If compromise is confirmed, revoke sessions and tokens, rotate affected
  credentials, remove unauthorized keys and enforce MFA and conditional
  access.
- Preserve CloudTrail, Azure sign in and audit, Office 365 audit and endpoint
  records before retention windows expire.
- If endpoint compromise is confirmed, isolate and acquire FYODOR-L. Preserve
  the registry value, scheduled task, process and network artefacts.
- Preserve anonymous sharing metadata, determine exposure scope and revoke
  links where appropriate.
- Validate mailbox changes and restore configuration only after confirming
  the intended state with the business owner.

## Investigation scope

The report analyses 83 selected records from six BOTSv3-derived scenario extracts. The findings are tied to their source fixtures and record ranges. The extracts represent separate investigative threads, so recurring names, IP addresses and timestamps are treated as pivots for further analysis rather than proof of a single coordinated intrusion. The AWS fixture uses stable replacement labels for temporary access key identifiers; local integrity hashes therefore describe the sanitized files in this repository.
