# Incident Timeline
### Northstar Logistics | 21 October 2026 | UTC

| Time (UTC) | Host | Activity described | Evidence | Assessment |
|---|---|---|---|---|
| 08:17 | NS-DC01 | Kerberos service-ticket request associated with `svc-backup`; NS-WS044 identified as client | E-001 | Authentication context; not proof of target-server logon by itself |
| 08:19 | NS-FS01 | Network logon for `svc-backup` from NS-WS044; privileged logon record follows | E-002 | Account use outside stated baseline |
| 08:26 | NS-FS01 | `WmiPrvSE.exe` process lineage to `cmd.exe` and PowerShell | E-003 | WMI-associated process execution |
| 08:27 | NS-FS01 | Host and domain discovery command context | E-004 | Discovery activity |
| 08:28 | NS-FS01 | PowerShell script-block records describe user, domain and service enumeration | E-005 | PowerShell discovery |
| 08:34 | NS-FS01 | Process from temporary directory accesses `lsass.exe` | E-006 | Credential-access indicator; extraction not established |
| 08:43 | NS-WEB01 | Network logon for `svc-backup` from NS-FS01 | E-007 | Inter-host authentication; protocol not established |
| 08:47 | NS-FS01 | Finance documents accessed | E-008 | Potential collection |
| 08:51 | NS-FS01 | File copies created in `C:\ProgramData\Cache\` | E-009 | Local staging; source and copy process require validation |
| 09:02 | NS-FS01 | Outbound TCP activity to 198.51.100.27:8443 | E-010 | Network activity; disposition and transfer outcome unknown |

## Sequence analysis

**1. Identity anomaly (08:17to08:19)**

A domain-controller authentication record is followed by a network logon on NS-FS01 from the workstation. The destination server's Security event is required to establish the logon; the domain-controller record provides supporting Kerberos context.

**2. WMI-associated execution and discovery (08:26to08:28)**

A process chain involving the WMI provider, command shell and PowerShell is followed by discovery commands. The process tree supports WMI-associated execution, but WMI client and source-host records are needed to confirm remote origin.

**3. Credential-access indicator (08:34)**

A process accesses LSASS. This is suspicious in context, but the available record does not establish that a memory dump was created or credentials were recovered.

**4. Inter-host authentication and file staging (08:43to08:51)**

The service identity is associated with a network logon on NS-WEB01 from NS-FS01. Finance-file access and local file creation are then described on NS-FS01. The remote service, file-copy process and relationship between the logon and file activity require corroboration.

**5. Outbound network activity (09:02)**

Outbound TCP activity follows the staging events. Without firewall disposition, process attribution, payload and byte counts, successful command-and-control or exfiltration cannot be concluded.

## Timeline integrity

The timestamps are presented in UTC as part of the reconstructed case narrative. A production investigation must preserve original timestamps and time zones, document host clock offsets and ingestion delays, and correlate events using Logon IDs, process GUIDs, PIDs and other stable identifiers. Temporal proximity alone does not prove causation.
