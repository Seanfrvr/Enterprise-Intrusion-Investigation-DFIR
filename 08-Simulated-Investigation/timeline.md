# Simulated Intrusion Timeline

<sub>All timestamps and events are fictional; UTC throughout</sub>

| Time (UTC) | Host | Event | Evidence | Assessment |
|---|---|---|---|---|
| 08:17 | NS-DC01 | Successful network logon by `svc-backup` from NS-WS044 | E-001 | Unusual service-account source |
| 08:19 | NS-FS01 | Privileged logon session associated with `svc-backup` | E-002 | Elevated access context |
| 08:26 | NS-FS01 | WMI provider spawns command shell and PowerShell | E-003 | Suspicious remote execution chain |
| 08:27 | NS-FS01 | Host and domain discovery commands execute | E-004 | Discovery activity |
| 08:28 | NS-FS01 | PowerShell script-block records enumerate users, domain and services | E-005 | Discovery activity |
| 08:34 | NS-FS01 | Unsigned temporary executable accesses LSASS | E-006 | Credential-access indicator |
| 08:43 | NS-WEB01 | Network logon associated with `svc-backup` from NS-FS01 | E-007 | Possible lateral movement |
| 08:47 | NS-FS01 | Finance documents accessed | E-008 | Potential collection |
| 08:51 | NS-FS01 | Selected documents copied to `C:\ProgramData\Cache\` | E-009 | Staging activity |
| 09:02 | NS-FS01 | Outbound TCP connection attempt to 198.51.100.27:8443 | E-010 | Suspicious outbound attempt; outcome unknown |

## Sequence interpretation

1. **Identity anomaly:** the service identity appears from a workstation outside its documented baseline.
2. **Execution:** remote WMI-associated process creation follows the privileged logon.
3. **Discovery and credential-access indicator:** PowerShell discovery and LSASS access occur on the finance server.
4. **Movement and collection:** the identity appears on another server while finance files are accessed and copied to a staging directory.
5. **Outbound activity:** a connection attempt follows the staging events.

## Timeline caveats

- This sequence is internally authored for the exercise; it is not reconstructed from a real event export.
- A timestamp sequence supports temporal association, not automatic causation.
- Host clock drift, time-zone conversion and log ingestion delay would need to be assessed in a real investigation.
- The order of events should be revalidated against raw event timestamps and logon/session identifiers when a real dataset is used.
