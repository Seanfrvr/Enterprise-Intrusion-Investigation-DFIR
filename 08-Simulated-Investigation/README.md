# Northstar Logistics — Reconstructed Case Exercise

This folder contains a fictional enterprise intrusion scenario used to practise investigation structure and evidence-based reasoning. It is **not** a report of a verified incident.

## Scenario

The exercise describes possible misuse of a privileged service account, WMI-associated process execution, PowerShell discovery, unusual LSASS access, inter-host authentication, finance-file staging and outbound network activity.

The scenario uses documentation-only IP ranges. In particular, `198.51.100.27` is an RFC 5737 TEST-NET-2 example address, not a live threat indicator.

## Documents

| File | Purpose |
|---|---|
| [Executive summary](executive-summary.md) | Short assessment and response priorities |
| [Findings](findings.md) | Seven scenario findings, alternatives and follow-up pivots |
| [Timeline](timeline.md) | Reconstructed event sequence |
| [Evidence register](evidence-register.md) | Describes the telemetry needed to support each finding |
| [Detection analysis](detection-analysis.md) | Proposed Splunk searches and validation requirements |
| [ATT&CK mapping](attack-mapping.md) | Conservative candidate mappings |
| [Validation plan](investigation-validation.md) | Work required to test the scenario against real telemetry |

## Environment in the scenario

| Asset | Role | Address |
|---|---|---|
| NS-DC01 | Domain controller | 10.20.10.10 |
| NS-FS01 | Finance file server | 10.20.20.15 |
| NS-WEB01 | Internal application server | 10.20.30.25 |
| NS-WS044 | Employee workstation | 10.20.40.44 |

Accounts referenced: `svc-backup` and `j.mercer`.

Scenario window: **2026-10-21 08:10–10:05 UTC**.

## Provenance and limitations

The narrative, event descriptions and timestamps are authored scenario material. Original event exports, Splunk result sets, hashes and investigation screenshots are not retained. The SPL has not been run against a dataset for this case.

Consequently:
- The findings describe what the scenario says, not independently verified observations.
- Confidence labels reflect the scenario's internal consistency, not source validation.
- ATT&CK entries are candidates, not proof of technique execution.
- No credential theft, persistence, successful C2, exfiltration or attribution is established.

Keep this folder labelled as a reconstructed exercise. Do not present it as live incident response or as hands-on findings from a dataset.

## What would make this a real investigation

Use a dataset that is permitted for analysis and publication. Preserve the original records, document the source and time range, run and tune the searches, capture your own screenshots, record false leads, and rewrite the findings from the results. Until then, this folder is a case-writing exercise, not the centrepiece evidence of the portfolio.
