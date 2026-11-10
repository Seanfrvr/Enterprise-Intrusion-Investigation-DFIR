# MITRE ATT&CK Mapping

## Purpose

ATT&CK mapping provides a common vocabulary for describing observed adversary behaviour. It does not establish attribution and must not replace evidence-based analysis.

Reference: [MITRE ATT&CK Enterprise](https://attack.mitre.org/)

## Mapping rules

1. Map behaviour, not merely a tool name.
2. Use the narrowest technique supported by the evidence.
3. Record the exact observation that supports the mapping.
4. Distinguish observed behaviour from inferred intent.
5. Include confidence and evidence limitations.
6. Re-check technique names and IDs against the current ATT&CK knowledge base before publication.

## Candidate technique reference

The following are examples of technique areas an analyst may consider when the required evidence exists. They are **not findings about a particular incident**.

| Candidate ID | Technique | Evidence needed before mapping |
|---|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Script or command execution evidence and context |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | WMI execution or remote WMI activity evidence |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Evidence of process access or memory acquisition consistent with credential dumping |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Evidence of RDP use for remote access |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Clear Windows Event Logs | Evidence that Windows event logs were cleared |
| [T1562.002](https://attack.mitre.org/techniques/T1562/002/) | Disable Windows Event Logging | Evidence of logging service or policy interference |

## Mapping register

| Observation ID | ATT&CK ID | Technique | Tactic | Evidence reference | Confidence | Notes |
|---|---|---|---|---|---|---|
| Not populated | Pending validation | Pending | Pending | Pending | Pending | Add only after reviewing source evidence |

## Confidence guidance

- **High:** the observed behaviour closely matches the technique and is directly supported by reliable telemetry.
- **Medium:** behaviour is consistent with the technique but evidence is incomplete or partly indirect.
- **Low:** mapping is a hypothesis requiring additional evidence.

Do not map a technique solely because a particular executable, command or event ID appears in a log.