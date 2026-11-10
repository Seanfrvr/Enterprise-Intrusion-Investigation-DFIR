# Incident Timeline
### Northstar Logistics | 21 October 2026 | UTC

| Time (UTC) | Host | Activity | Evidence | Assessment |
|---|---|---|---|---|
| 08:17 | NS-DC01 | Successful network logon for `svc-backup` from NS-WS044 | E-001 | Source inconsistent with documented service pattern |
| 08:19 | NS-FS01 | Privileged logon session associated with `svc-backup` | E-002 | Elevated account context |
| 08:26 | NS-FS01 | WMI provider process spawns command shell and PowerShell | E-003 | WMI-associated execution |
| 08:27 | NS-FS01 | Host and domain discovery commands execute | E-004 | Discovery activity |
| 08:28 | NS-FS01 | PowerShell script-block records enumerate users, domain and services | E-005 | PowerShell discovery |
| 08:34 | NS-FS01 | Unsigned temporary executable accesses LSASS | E-006 | Credential-access indicator |
| 08:43 | NS-WEB01 | Network logon for `svc-backup` from NS-FS01 | E-007 | Possible lateral movement |
| 08:47 | NS-FS01 | Finance documents accessed | E-008 | Potential collection |
| 08:51 | NS-FS01 | Selected documents copied to `C:\ProgramData\Cache\` | E-009 | Local staging |
| 09:02 | NS-FS01 | Outbound TCP connection attempt to 198.51.100.27:8443 | E-010 | Connection outcome undetermined |

## Sequence analysis

**1. Identity anomaly (08:17–08:19)**

The service identity is first associated with a workstation outside its documented operating pattern, followed by a privileged session on the finance server.

**2. Remote execution and discovery (08:26–08:28)**

WMI-associated process creation and PowerShell discovery activity follow the privileged logon. This sequence is consistent with remote administration or execution, but requires source-host and session correlation to distinguish legitimate management from abuse.

**3. Credential-access indicator (08:34)**

An unusual process is described as accessing LSASS. The event raises concern for credential-access activity, but there is no evidence of recovered credentials in the case material.

**4. Internal movement and collection (08:43–08:51)**

The service identity appears on another server. Finance documents are then accessed and copied to a local staging path. The records do not establish external transfer.

**5. Outbound network activity (09:02)**

An outbound connection attempt is recorded after the staging activity. Without session outcome, payload and process attribution, command-and-control and exfiltration remain unconfirmed.

## Timeline integrity notes

The timestamps in this case study are presented in UTC and arranged as a coherent investigative sequence. A production investigation must verify timestamps against original event records, host clock configuration, time-zone settings, ingestion delay and logon/session identifiers. Temporal proximity alone does not prove causation.
