# MITRE ATT&CK Mapping
### Northstar Logistics | Behaviour-to-Technique Assessment

The mappings below are candidates based on the behaviours described in the case narrative. They are not proof of a real actor or confirmed technique execution. Map only what the available evidence can support; leave gaps explicit.

| Behaviour described | Candidate technique | ID | Evidence reference | Confidence / qualification |
|---|---|---|---|---|
| Use of a privileged account outside its documented pattern | Valid Accounts | T1078 | E-001, E-002 | Candidate; confirms account use only if primary authentication records validate. Credential compromise mechanism is unknown |
| WMI provider process lineage to command interpreters | Windows Management Instrumentation | T1047 | E-003, E-004 | Candidate; process lineage supports WMI-associated execution. Remote origin and malicious intent require corroboration |
| PowerShell discovery commands | Command and Scripting Interpreter: PowerShell | T1059.001 | E-005 | Supported as PowerShell execution if script-block records validate; intent remains contextual |
| Unusual process access to LSASS | OS Credential Dumping: LSASS Memory | T1003.001 | E-006 | Investigative candidate only; process access does not establish a memory dump or recovered credentials |
| Inter-host network logon | No sub-technique assigned | — | E-007 | Remote service is unknown. Establish SMB, RDP, WinRM or another protocol before mapping |
| Finance-file access and local staging | No technique assigned yet | — | E-008, E-009 | Collection mechanism and source location require validation before selecting T1005 or T1039 |
| Outbound TCP activity | No technique assigned | — | E-010 | Protocol, process, payload and session outcome are insufficient for a C2 or exfiltration mapping |

## Mapping rationale

**Valid Accounts (T1078):** the described account use is inconsistent with the stated service-account baseline. Authentication evidence does not establish whether credentials were stolen, shared, misconfigured or used under an undocumented change.

**Windows Management Instrumentation (T1047):** the described process lineage supports investigation of WMI execution. WMI-Activity records and network context are needed to establish the client and remote operation.

**PowerShell (T1059.001):** script-block content supports PowerShell use. The analyst must distinguish discovery commands from legitimate administrative automation.

**OS Credential Dumping: LSASS Memory (T1003.001):** LSASS access is a credential-access indicator. Evidence of a dump operation, memory artefact or recovered credentials is needed before claiming credential dumping occurred.

## Techniques deliberately not assigned

- **Remote Services (T1021):** a network logon does not identify the remote service. Confirm SMB, RDP, WinRM or another mechanism first.
- **Collection (T1005 / T1039):** identify whether files were collected from a local system or network share and establish the collection process.
- **Command and Control:** identify the protocol, process, destination context and session behaviour.
- **Exfiltration:** establish that data was transferred outside the environment, with supporting transfer evidence.

The initial access vector, persistence mechanism and operator identity are also unresolved. These are investigation gaps, not reasons to guess additional techniques.
