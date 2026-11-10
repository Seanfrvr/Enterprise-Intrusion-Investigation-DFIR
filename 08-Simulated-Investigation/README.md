# Simulated Enterprise Intrusion Investigation

<sub>Fictional scenario · Synthetic evidence · Defensive analysis exercise</sub>

> **Important:** This is a deliberately constructed simulation. The organisation, people, hostnames, timestamps, IP addresses, events and findings are fictional. They are not observations from a real environment, a TryHackMe room, BOTSv3, or another third-party dataset. No claim is made that the searches below have been executed against telemetry.

## Case brief

A fictional regional services company, **Northstar Logistics**, detects unusual activity involving a privileged domain account and two Windows servers. The exercise follows the investigation from identity anomaly through endpoint execution, lateral movement, data staging and attempted outbound communication.

The objective is not to tell a dramatic story. It is to demonstrate disciplined SOC reasoning: distinguish direct observations from interpretation, identify what each data source can and cannot prove, and avoid overstating impact.

## Case documents

| Document | Contents |
|---|---|
| [Executive summary](executive-summary.md) | Situation, scope, assessment and business impact |
| [Investigation findings](findings.md) | Evidence-led findings with confidence and limitations |
| [Timeline](timeline.md) | Normalised sequence of simulated events |
| [Evidence register](evidence-register.md) | Evidence IDs, source types and evidential limitations |
| [Detection analysis](detection-analysis.md) | SPL examples, detection logic, tuning and validation plan |
| [ATT&CK mapping](attack-mapping.md) | Behaviour mapping with evidence strength |

## Environment

| Asset | Role | Address |
|---|---|---|
| NS-DC01 | Domain controller | 10.20.10.10 |
| NS-FS01 | Finance file server | 10.20.20.15 |
| NS-WEB01 | Internal application server | 10.20.30.25 |
| NS-WS044 | Employee workstation | 10.20.40.44 |
| User: j.mercer | Finance employee | Standard user |
| User: svc-backup | Backup service identity | Privileged service account |

All addresses are documentation-only private ranges. The external test address 198.51.100.27 belongs to the RFC 5737 TEST-NET-2 documentation range and is not a real command-and-control endpoint.

## Scenario assumptions

- The exercise uses synthetic event records designed for analysis and documentation.
- Event IDs, process relationships and command examples are representative of Windows telemetry, but are not claimed to be exported from a live host.
- Timestamps are UTC and are internally consistent within this scenario.
- The scenario assumes Security Event Logs, Sysmon and PowerShell operational logging were available. Real environments may not collect all of them.
- Any SPL shown is an illustrative starting point. Field extractions, index names, sourcetypes and results must be validated against a real dataset before operational use.

## Analytical standard

Each finding uses four separate labels:

- **Observation:** what the simulated evidence explicitly records.
- **Assessment:** the most defensible interpretation.
- **Confidence:** how strongly the available scenario evidence supports that interpretation.
- **Limitations:** what cannot be concluded from the evidence.

Confidence describes the assessment, not the authenticity of this synthetic exercise. A simulated event is still simulated.

## Scenario boundaries

The scenario supports an assessment of suspected account compromise, suspicious remote execution, credential-access behaviour, file staging and attempted outbound communication. It does **not** establish successful credential theft, successful exfiltration, malware attribution, or the identity of an operator.

## Reproduction and extension

To turn this into a hands-on lab later, generate or obtain a permitted dataset, ingest it into Splunk, record the actual index and sourcetypes, run each search, preserve result screenshots, and replace illustrative observations only with findings supported by that dataset. Keep synthetic and observed evidence in separate folders and label them distinctly.
