# Enterprise Intrusion Investigation
### Northstar Logistics | Security Operations & Digital Forensics

## Incident overview

This case study follows a suspected enterprise intrusion involving privileged-account activity, remote execution, endpoint discovery, credential-access indicators, lateral movement, data staging and outbound network activity.

The investigation is organised around six deliverables:

| Document | Contents |
|---|---|
| [Executive summary](executive-summary.md) | Incident assessment, scope, risk and response priorities |
| [Investigation findings](findings.md) | Seven findings with analysis, confidence and follow-up actions |
| [Incident timeline](timeline.md) | Chronological sequence of relevant activity |
| [Evidence register](evidence-register.md) | Evidence references, source types and limitations |
| [Detection analysis](detection-analysis.md) | SPL hunt logic, tuning considerations and validation |
| [ATT&CK mapping](attack-mapping.md) | Technique mapping tied to investigative observations |

## Environment under review

| Asset | Role | Address |
|---|---|---|
| NS-DC01 | Domain controller | 10.20.10.10 |
| NS-FS01 | Finance file server | 10.20.20.15 |
| NS-WEB01 | Internal application server | 10.20.30.25 |
| NS-WS044 | Employee workstation | 10.20.40.44 |
| j.mercer | Finance employee account | Standard user |
| svc-backup | Backup service identity | Privileged service account |

The external address 198.51.100.27 is within the RFC 5737 TEST-NET-2 documentation range. It is used as a reserved example indicator, not as a live threat-intelligence indicator.

## Investigation scope

- Identity and authentication activity on NS-DC01.
- Process execution, PowerShell and Sysmon telemetry on NS-FS01.
- Authentication activity involving NS-WEB01.
- Finance-file access and staging activity.
- Outbound connection telemetry.
- Review period: 2026-10-21 08:10–10:05 UTC.

## Analytical approach

The report separates event observations from analyst assessment. Each finding records supporting evidence references, confidence, alternative explanations and additional collection required to strengthen the conclusion.

## Case-study provenance

This is a reconstructed portfolio case study. Its incident narrative and event descriptions are illustrative; primary event exports, reproducible Splunk result sets and original investigation screenshots are not currently retained in the repository. It should not be represented as a verified real-world incident or as dataset-validated hands-on work. The SPL examples require execution and validation in a suitable environment.

## Investigation conclusion

The case narrative supports a high-priority investigation hypothesis involving privileged identity misuse, suspicious remote execution, LSASS access, finance-data staging and an outbound connection attempt. It deliberately does not claim successful credential extraction, successful data exfiltration, confirmed command-and-control or actor attribution without the evidence needed to establish those outcomes.
