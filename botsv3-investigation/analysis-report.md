# BOTSv3 cross platform security investigation

## Executive summary

This investigation reviews six selected BOTSv3 derived event extracts covering AWS, Windows, DNS, Sysmon, Azure AD and Office 365. The extracts contain 83 records and expose several security relevant behaviours across cloud services and endpoints.

The strongest endpoint lead is the hidden PowerShell execution recorded on `FYODOR-L`. Its command line retrieves a registry value, decodes it from Base64 and passes the result to `IEX`. That combination warrants priority investigation because it can execute content stored outside the visible command line. The extract does not include the registry value or task registration evidence, so the payload and persistence mechanism remain unresolved.

The cloud records provide separate leads. AWS CloudTrail records successful console sign ins without MFA and repeated S3 bucket ACL checks by `bstoll`. Azure AD records successful sign ins for two identities from the same public IP. Office 365 records anonymous sharing activity involving a Windows shortcut, followed by Exchange mailbox changes. Each deserves validation against identity, session and administrative context.

The DNS extract records queries for Coinhive related domains from an internal client. This is consistent with the upstream cryptojacking scenario, but DNS alone does not establish that mining code ran. The Windows logon extract is more limited: it contains local and service logons, but no remote interactive logon in the 11 selected records.

The key investigative judgement is to treat these as six leads, not one proven attack chain. Repeated names and IP addresses are useful pivots for deeper searches, but the available extracts do not establish a common operator or coordinated intrusion.

## Scope and approach

The analysis uses six files in [data/fixtures](data/fixtures/).

| Evidence | Source extract | Records |
|---|---|---:|
| E-001 | AWS CloudTrail activity attributed to bstoll | 20 |
| E-002 | BSTOLL-L Windows logon excerpt | 11 |
| E-003 | Coinhive DNS excerpt | 12 |
| E-004 | FYODOR-L Sysmon PowerShell excerpt | 4 |
| E-005 | Azure AD sign in excerpt | 20 |
| E-006 | Office 365 management excerpt | 16 |
| | **Total** | **83** |

I reviewed the event content by source, identified behaviours that warranted follow up, then compared recurring identities, hosts and IP addresses across the selected extracts. Those overlaps were treated as investigative pivots rather than proof of attribution. The findings below separate what the records show from what still needs corroboration.

The Python pipeline parses the 83 committed JSONL records, preserves each source filename and line number, normalizes common fields, calculates SHA-256 hashes for the current local files and generates a UTC timeline for records with usable timestamps. The fixture data contains 36 timestamped records and 47 without usable timestamps. All 83 remain represented in the normalized output. The AWS fixture replaces temporary access key identifiers with stable redaction labels, so its local hash describes the sanitized file rather than the unmodified upstream source.

## Findings

### F-01: AWS console sign ins without MFA and repeated S3 ACL checks

**Evidence:** E-001  
**Source:** `01-aws-recon-bstoll.jsonl`, records 1 to 20  
**Identity:** IAM user `bstoll`  
**Source IPs:** `107.77.212.175`, `157.97.121.132`

Four CloudTrail records show successful `ConsoleLogin` events where `additionalEventData.MFAUsed` is `No`. The same extract records repeated S3 `GetBucketAcl` calls attributed to `bstoll`, including requests against multiple bucket names. Several calls occur within the same second, which is consistent with scripted or automated enumeration.

The combination makes this a worthwhile cloud identity lead: the account successfully authenticated without MFA and then performed repeated bucket permission checks. The events do not show whether the sign ins were unauthorized, whether the bucket contents were accessed or who operated the sessions. I would not treat the absence of MFA as proof that the account was compromised.

**Next pivot:** Review the principal's complete CloudTrail history and session context. Check for `ListBuckets`, `ListObjects`, `GetObject`, IAM policy changes and credential operations. Compare the source IPs and user agents with the user's normal activity, and review related GuardDuty and network telemetry.

### F-02: BSTOLL-L logon records provide only a narrow view of access

**Evidence:** E-002  
**Source:** `02-bstoll-l-endpoint.jsonl`, records 1 to 11  
**Host:** `BSTOLL-L`

All 11 records are Security Event ID 4624. They include five SYSTEM service logons (type 5), four DWM-1 interactive logons (type 2) and two `bstoll` cached interactive logons (type 11) with source address `127.0.0.1`.

There is no type 10 remote interactive logon in this extract. That is useful context, but the sample is too small to establish the host's broader access history. It would be a mistake to use these 11 events to rule out remote access.

**Next pivot:** Search the complete Security log for events 4624 and 4625, paying particular attention to logon types 3, 9 and 10. Review source workstation, source address, account SID, authentication package and adjacent events 4648, 4672, 4768 and 4769. Correlate the results with RDP, VPN and endpoint process telemetry.

### F-03: Coinhive related DNS queries from an internal client

**Evidence:** E-003  
**Source:** `03-bstoll-coinhive-cryptojacking.jsonl`, records 1 to 12  
**Client:** `192.168.247.131`

The extract contains six DNS queries from the same internal client for `coinhive.com` and several `wsNNN.coinhive.com` names, together with six corresponding responses. The responses include successful `NoError` replies and resolved addresses.

The domain pattern is consistent with the upstream cryptojacking scenario and is enough to justify checking the endpoint. DNS records alone do not identify the process or user responsible, and they do not prove that mining code executed or consumed CPU resources.

**Next pivot:** Map the client IP to a device and user at the event time. Check HTTP and TLS telemetry, browser history, process creation and CPU activity. Search the wider dataset for related domains and outbound connections to establish whether the DNS activity led to an actual session.

### F-04: Hidden PowerShell execution on FYODOR-L

**Evidence:** E-004  
**Source:** `04-fyodor-powershell-empire.jsonl`, records 1 to 4  
**Host:** `FYODOR-L`

Two Sysmon Event ID 1 records show PowerShell launched with hidden window and non interactive options. The command retrieves a value named `debug` from `HKLM:\\Software\\Microsoft\\Network`, decodes it from Base64 as Unicode and passes the result to `IEX`. One record shows a PowerShell parent. Another shows `svchost.exe`, hosting the Task Scheduler service, as the parent, with PowerShell running as SYSTEM. Two additional records in the extract concern Dropbox OEM package removal on `BGIST-L` and are not part of this finding.

This is the strongest endpoint lead in the selected data. Retrieving encoded content from the registry and dynamically invoking it can conceal the executed script from a simple command line review. The Task Scheduler service context raises a scheduled execution hypothesis, but the extract contains no task registration events, task XML or registry value content. The exact payload and persistence mechanism therefore remain unknown.

**Next pivot:** Acquire and preserve the registry value before decoding it. Review Task Scheduler Operational events and task XML, Sysmon Event IDs 12 to 14, 3, 7 and 11, PowerShell events 4103 and 4104, Prefetch, Amcache and related outbound connections. Preserve the decoded content as a separate artefact for analysis.

### F-05: Azure AD sign ins for two identities from one public IP

**Evidence:** E-005  
**Source:** `05-azure-ad-signin-anomaly.jsonl`, records 1 to 20  
**Identities:** `fyodor@froth.ly`, `bgist@froth.ly`  
**IP:** `104.207.83.63`

The selected records include successful sign ins for both identities from `104.207.83.63`. The event payloads report Hong Kong location metadata, and the records span multiple Microsoft 365 applications.

Two identities using the same public IP is a useful pivot, particularly when reviewing the separate Office 365 activity. It is not enough to attribute both sessions to one operator. A VPN, proxy, corporate gateway or service routing can produce the same pattern. The location field also needs to be assessed alongside the underlying sign in and device context.

**Next pivot:** Review sign in risk, device ID, client application, Conditional Access result, authentication details, MFA claims and session correlation IDs. Compare the IP with historical use by each identity, then inspect token issuance and subsequent cloud audit activity.

### F-06: Anonymous OneDrive sharing followed by Exchange mailbox changes

**Evidence:** E-006  
**Source:** `06-o365-cloud-account-abuse.jsonl`, records 1 to 16

The audit extract records `bgist@froth.ly` creating an anonymous sharing link for `BRUCE BIRTHDAY HAPPY HOUR PICS.lnk` at 09:58:02 UTC. A `SharingSet` event follows one second later. The fixture then records nine `AnonymousLinkUsed` events for the file, including events attributed to `anonymous` and one attributed to `bstoll@froth.ly`. The recorded client IP addresses vary.

Later Exchange management events show three `Set-Mailbox` operations. An application account targets `klagerfield`; `fyodor@froth.ly` sets `StsRefreshTokensValidFrom` for `klagerfield`; and `fyodor@froth.ly` sets `AccountDisabled=True` for `bgist`.

The sharing events establish that the anonymous link was used, but they do not show that the shortcut was executed or that it delivered malware. The mailbox changes could be legitimate administration or incident response. Their significance depends on who initiated them, what permissions that actor held and whether the changes were authorized.

**Next pivot:** Retrieve the full audit payloads and sharing permissions. Identify link consumers and access outcomes. Preserve the file from an appropriate source and calculate its hash. Correlate recipients with endpoint telemetry. Validate the Exchange actor, role, session and change ticket before treating the mailbox operations as malicious.

## Cross source pivots

The selected extracts contain several recurring values worth checking against the full telemetry:

- The name `bstoll` appears in AWS and Windows context. A matching display name is not a stable identity key.
- `fyodor@froth.ly` appears in Azure AD and Office 365 records. The Sysmon fixture uses the Windows identity `AzureAD\\FyodorMalteskesko` on `FYODOR-L`. Confirm the directory account and device relationship using stable identifiers.
- `104.207.83.63` appears in Azure AD sign ins for two identities and in Office 365 activity. Check whether it belongs to a shared gateway, VPN or proxy before drawing conclusions about the operator.
- `107.77.212.175` appears in AWS and Office 365 records. Compare event times, principal identifiers and session context to determine whether the overlap is meaningful.

These are leads for further collection and correlation. The current extracts do not provide enough continuity to construct a single incident timeline.

## MITRE ATT&CK assessment

| Observed behaviour | Technique | Assessment |
|---|---|---|
| Cloud account use | T1078.004, Valid Accounts: Cloud Accounts | Candidate mapping. Validate principal and session context. |
| PowerShell execution | T1059.001, PowerShell | Supported by the Sysmon process command line. |
| Scheduled execution | Not assigned | Task Scheduler parent is suggestive, but task registration evidence is absent. |
| S3 ACL inspection | Not assigned | `GetBucketAcl` does not by itself establish cloud service or object discovery. |
| Anonymous sharing | Not assigned | Sharing is recorded; exfiltration is not established. |
| Mailbox administration | Not assigned | Review operation parameters and actor permissions before mapping. |

Mappings are limited to behaviours supported by the available records. Repeated `GetBucketAcl` calls are described as ACL inspection, not cloud service discovery or object enumeration. The observed calls do not by themselves establish T1526 or T1619. See [T1526](https://attack.mitre.org/techniques/T1526/) and [T1619](https://attack.mitre.org/techniques/T1619/).

## Detection opportunities

The findings suggest several detection opportunities for a full telemetry environment:

1. Successful AWS console sign ins with `MFAUsed=No`, enriched with source IP, user agent and principal history.
2. High rate S3 ACL checks by one principal, measured by bucket count and time window.
3. Hidden PowerShell that reads registry values and dynamically invokes decoded content.
4. Successful cloud sign ins for multiple users from one unusual IP, enriched with device, session and Conditional Access context.
5. Anonymous sharing link creation for shortcut, script or executable file types, followed by external link use.
6. High impact Exchange mailbox changes from unusual actors or sessions.

These are detection hypotheses for further testing, not validated production detections. They have not been tested against the complete BOTSv3 index or a benign activity baseline.

## Response priorities

If these leads were being investigated in a live environment, I would prioritize the following collection and validation:

1. **Preserve the FYODOR-L endpoint evidence.** Acquire the registry value, scheduled task artefacts, relevant PowerShell logs and surrounding process and network telemetry before making changes.
2. **Validate cloud identity activity.** Confirm whether the AWS and Azure AD sign ins were expected, inspect session context and review subsequent actions by the affected principals.
3. **Establish the OneDrive exposure.** Identify who used the anonymous link, what access succeeded and whether the shortcut was retrieved or executed.
4. **Validate Exchange changes.** Confirm the initiating actors, permissions and authorization for token invalidation and account disablement.
5. **Resolve the DNS lead.** Identify the device and process responsible for Coinhive related queries and determine whether a corresponding connection or mining process existed.

Containment actions such as revoking sessions, rotating credentials, disabling accounts or removing sharing links should follow confirmation of the affected identity, scope and business impact. Preserve relevant CloudTrail, Azure sign in, Office 365 audit and endpoint records before retention windows expire.

## Investigation scope

This report analyses 83 selected records from six BOTSv3 derived scenario extracts. Findings are tied to their source fixtures and record ranges. The extracts represent separate investigative threads, so recurring names, IP addresses and timestamps are treated as pivots for further analysis rather than proof of a single coordinated intrusion. The AWS fixture uses stable replacement labels for temporary access key identifiers; local integrity hashes therefore describe the sanitized files in this repository.
