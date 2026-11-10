# Enterprise Intrusion Investigation
### Northstar Logistics | Security Operations & Digital Forensics

## Incident overview

This case study examines a suspected enterprise intrusion involving anomalous privileged-account activity, WMI-associated process execution, PowerShell discovery, suspicious access to LSASS, inter-host authentication, finance-file staging and outbound network activity.

The report is structured around an evidence-led workflow. Each finding separates the source observation from analyst assessment, records competing explanations, identifies confidence limits and specifies the additional evidence needed to confirm or reject the hypothesis.

## Case documents

| Document | Contents |
|---|---|
| [Executive summary](executive-summary.md) | Incident assessment, scope, risk and response priorities |
| [Investigation findings](findings.md) | Seven findings with observations, assessments and investigative next steps |
| [Incident timeline](timeline.md) | Chronological sequence and correlation caveats |
| [Evidence register](evidence-register.md) | Source references, required fields and evidential limitations |
| [Detection analysis](detection-analysis.md) | SPL hunt logic, field assumptions, tuning and validation |
| [ATT&CK mapping](attack-mapping.md) | Conservative behaviour-to-technique mapping |
| [Investigation validation plan](investigation-validation.md) | Collection requirements, correlation tests, severity rationale and evidence gaps |

## Environment under review

| Asset | Role | Address |
|---|---|---|
| NS-DC01 | Domain controller | 10.20.10.10 |
| NS-FS01 | Finance file server | 10.20.20.15 |
| NS-WEB01 | Internal application server | 10.20.30.25 |
| NS-WS044 | Employee workstation | 10.20.40.44 |
| j.mercer | Finance employee account | Standard user |
| svc-backup | Backup service identity | Privileged service account |

The private addresses are reserved documentation values. The external address 198.51.100.27 is within the RFC 5737 TEST-NET-2 documentation range and is not a live threat-intelligence indicator.

## Investigation scope

- Authentication activity involving NS-WS044, NS-DC01 and NS-FS01.
- Process creation and WMI-associated execution on NS-FS01.
- PowerShell Operational records on NS-FS01.
- Process access to LSASS on NS-FS01.
- Network authentication involving NS-WEB01.
- Finance-file access and local staging on NS-FS01.
- Outbound network telemetry from NS-FS01.
- Review period: 2026-10-21 08:10–10:05 UTC.

## Key analytical constraints

- A domain-controller Kerberos service-ticket event is not itself proof of a successful logon to the target server. Correlate it with the destination server's Security log.
- A `WmiPrvSE.exe` parent process supports WMI-associated execution but does not, by itself, identify the remote client.
- Sysmon Event ID 10 records process access to LSASS; it does not prove that credentials were dumped.
- A network logon on NS-WEB01 does not identify SMB, RDP, WinRM or another remote service without additional evidence.
- Sysmon Event ID 11 records file creation; it does not independently prove the source file or copy mechanism.
- An outbound connection record does not establish payload content or successful data transfer.

## Case-study provenance

This is a reconstructed portfolio case study. The incident narrative and event descriptions are illustrative; primary event exports, reproducible Splunk result sets and original investigation screenshots are not currently retained. The report should not be represented as a verified real-world incident or as dataset-validated hands-on work. All SPL requires execution and validation in a suitable environment.

## Investigation conclusion

The case narrative warrants a high-priority investigative hypothesis involving possible privileged-account misuse, WMI-associated execution, PowerShell discovery, suspicious LSASS access, inter-host authentication, finance-data staging and outbound network activity. Credential extraction, persistence, successful command-and-control, exfiltration and actor attribution remain unconfirmed.
