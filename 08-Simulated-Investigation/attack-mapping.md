# MITRE ATT&CK Mapping
### Northstar Logistics | Behaviour-to-Technique Assessment

The table maps behaviours described in the case narrative to candidate ATT&CK techniques. Mappings are provisional and should be confirmed against primary telemetry before being treated as incident findings.

| Behaviour described | ATT&CK technique | ID | Evidence reference | Assessment |
|---|---|---|---|---|
| Privileged account used outside its documented pattern | Valid Accounts | T1078 | E-001, E-002 | Suspicious account use is described; credential compromise mechanism is unknown |
| WMI-associated process creation | Windows Management Instrumentation | T1047 | E-003 | Process lineage is consistent with WMI execution; legitimate administration remains an alternative |
| PowerShell discovery commands | PowerShell | T1059.001 | E-004, E-005 | PowerShell execution is described; malicious intent is contextual |
| Unusual process access to LSASS | OS Credential Dumping: LSASS Memory | T1003.001 | E-006 | Candidate mapping only; access does not establish successful credential dumping |
| Remote access to another server | Remote Services | T1021 | E-007 | Parent technique is a candidate; specific sub-technique requires protocol/service evidence |
| Finance data accessed and staged locally | Data from Local System | T1005 | E-008, E-009 | Candidate mapping; file access and staging are described, but exact collection method needs validation |
| Outbound TCP connection attempt | No technique assigned | — | E-010 | Protocol, payload and session outcome are insufficient to support a C2 mapping |

## Mapping rationale and gaps

**Valid Accounts (T1078):** the account activity is described as inconsistent with the service-account baseline. The available case narrative does not establish whether the credentials were stolen, shared, misconfigured or legitimately used under an undocumented change.

**Windows Management Instrumentation (T1047):** the described WMI provider process lineage supports investigation of WMI execution. Source-host and remote-operation telemetry would strengthen the mapping.

**PowerShell (T1059.001):** the script-block description supports PowerShell use. The analyst must distinguish discovery activity from legitimate administrative automation.

**OS Credential Dumping: LSASS Memory (T1003.001):** LSASS access is a credential-access indicator. Evidence of a dump operation, memory artefact or recovered credentials would be needed to confirm the specific technique.

**Remote Services (T1021):** a network logon to another server does not identify the remote service used. SMB, RDP, WinRM or another protocol must be established before assigning a sub-technique.

**Data from Local System (T1005):** file access and local staging may be consistent with collection. The exact process and collection mechanism require corroboration.

## Techniques not assigned

The case does not provide sufficient support for a specific initial-access technique, persistence technique, command-and-control technique or exfiltration technique. These are investigation gaps, not implied findings. Do not assign ATT&CK techniques solely to make the matrix appear complete.
