# MITRE ATT&CK Mapping

<sub>Candidate mappings for a fictional scenario · Not attribution</sub>

Mappings below describe behaviours represented in the synthetic evidence. They are not proof that a real actor used these techniques. Technique selection should be revisited if the evidence changes.

| Simulated behaviour | Candidate technique | ID | Evidence | Assessment |
|---|---|---|---|---|
| Use of a privileged account outside its documented pattern | Valid Accounts | T1078 | E-001, E-002 | Supported as suspicious account use; credential compromise mechanism unknown |
| WMI-associated process creation | Windows Management Instrumentation | T1047 | E-003 | Supported by the synthetic process chain; legitimate administration remains an alternative |
| PowerShell discovery commands | PowerShell | T1059.001 | E-004, E-005 | Supported as PowerShell execution; malicious intent inferred from context |
| Access to LSASS by an unusual process | OS Credential Dumping: LSASS Memory | T1003.001 | E-006 | Candidate mapping; LSASS access is not proof of successful dumping |
| Network logon to another server | Remote Services / SMB or Windows Admin Shares | T1021.002 (only if SMB evidence confirms) | E-007 | Provisional; logon alone is insufficient to select a specific remote-service sub-technique |
| Copying finance files to a local staging directory | Data from Local System | T1005 (only if local collection is confirmed) | E-008, E-009 | Candidate mapping; file access and copy records support collection/staging |
| Outbound connection attempt | Application Layer Protocol or non-standard port (depending on protocol evidence) | Not assigned | E-010 | Insufficient protocol and payload evidence for a defensible technique mapping |

## Mapping discipline

- Map the behaviour actually evidenced, not the presumed objective.
- Prefer a parent technique when the available evidence cannot support a sub-technique.
- Do not map a network connection to command-and-control without sufficient protocol or operational context.
- Do not map file staging to exfiltration without evidence of transfer outside the environment.
- Record alternative explanations and the telemetry needed to strengthen or reject each mapping.

## ATT&CK coverage gaps

The scenario does not establish the initial access vector, malware family, persistence mechanism, successful credential dumping, data exfiltration or operator attribution. These remain explicit investigation gaps rather than assumed techniques.
