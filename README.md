# Enterprise Intrusion Investigation
### SOC Analysis · Threat Hunting · Digital Forensics & Incident Response

<p align="center">
 <strong>SPLUNK · WINDOWS TELEMETRY · DETECTION ENGINEERING · MITRE ATT&CK</strong>
</p>

---

## Project overview

This repository documents an evidence-led approach to enterprise intrusion
investigation, threat hunting and defensive detection engineering.

The BOTSv3 workstream now includes selected upstream event extracts, source
provenance, a reproducible local analysis pipeline, a fixture-backed findings
report and Splunk hunt logic for subsequent full-index validation.

**Evidence boundary:** the BOTSv3 records committed here are selected extracts
from a public BOTSv3-derived fixture repository. They are not the complete
BOTSv3 archive and were not queried in a live Splunk instance in this
workspace. The report distinguishes direct observations from assessment and
does not claim unperformed full-index validation.

## Project sections

| Section | Purpose |
|---|---|
| [Case overview](01-Case-Overview/case-overview.md) | Scope, assumptions and evidence standard |
| [Investigation playbooks](02-Investigation/) | Investigative questions and analysis methods by activity area |
| [ATT&CK mapping](03-MITRE-ATTACK/attack-mapping.md) | Candidate technique mapping and confidence rules |
| [Splunk hunting](04-Detection-Engineering/splunk-hunting.md) | Reusable SPL hunt templates |
| [Detection specifications](04-Detection-Engineering/detection-rules.md) | Detection logic, tuning and validation |
| [Windows artefacts](05-Digital-Forensics/windows-artifacts.md) | Forensic value and limitations of common artefacts |
| [Incident response](06-Incident-Response/response-recommendations.md) | Containment through recovery |
| [Evidence catalogue](07-Evidence/evidence-catalogue.md) | Evidence register and handling standard |
| [Timeline](07-Evidence/intrusion-timeline.md) | Timestamp normalisation and event sequencing |
| [Enterprise intrusion case study](08-Simulated-Investigation/) | Reconstructed Northstar scenario |
| [BOTSv3 investigation](09-BOTSv3-Investigation/) | Attributed event extracts, analysis pipeline, findings and validation hunts |

## What this project demonstrates

- Investigative question development and hypothesis testing.
- Windows Security, Sysmon, PowerShell and network telemetry analysis.
- Splunk SPL search construction and event correlation.
- Identity, process, file and network investigation.
- Evidence provenance, integrity checking, timeline construction and confidence assessment.
- MITRE ATT&CK mapping based on supported behaviour.
- Detection design, false-positive analysis, tuning and validation.
- Incident containment, eradication, recovery and lessons learned.

## Investigation workflow

1. Define the scope and investigative questions.
2. Identify available sources and coverage.
3. Acquire and preserve relevant records.
4. Inspect raw events and validate extracted fields.
5. Correlate identity, process, host and network activity.
6. Test the hypothesis against the evidence.
7. Document findings, confidence and impact.
8. Map supported behaviour to ATT&CK.
9. Develop, test and tune detections.
10. Recommend proportionate response actions.

## Tools and technologies

| Technology | Investigative use |
|---|---|
| Splunk Enterprise | Search, correlation and threat hunting |
| Windows Security logs | Authentication, privileges and object access |
| Sysmon | Process, network, file and process-access telemetry |
| PowerShell logging | Script-block and module activity |
| WMI-Activity logs | WMI client and operation context |
| Firewall / proxy logs | Connection disposition and network transfer context |
| CyberChef | Safe examination of encoded or transformed data |
| MITRE ATT&CK | Behaviour classification and defensive coverage |
| Python | Evidence normalization, integrity manifests and repeatable reporting |

## Evidence and analytical standards

The repository separates:

- **Observation:** what a source record directly shows.
- **Correlation:** a relationship supported by identifiers or multiple records.
- **Assessment:** the analyst's interpretation of the observations.
- **Inference:** a plausible explanation that is not directly proven.
- **Unknown:** a question the available evidence cannot resolve.

A timestamp match alone does not establish causation. A process name alone
does not establish malicious intent. LSASS access does not prove credential
extraction. File creation does not prove data exfiltration. A network event
does not prove command-and-control without sufficient protocol, process and
session context.

No search is described as tested unless it has been executed against a known
dataset and the raw results reviewed. Confirm indexes, sourcetypes, field
extractions, event coverage, time range and data-model assumptions before
relying on SPL.

## Current project status

The BOTSv3 workstream contains 83 records from six selected, attributed event
extracts; a Python pipeline for fixture-scoped integrity, normalization,
inventory and timeline generation; and a findings report with confidence
limits and follow-up pivots. A GitHub Actions workflow runs the pipeline
tests.

The full BOTSv3 archive has not been downloaded and installed in Splunk in
this workspace. Full-index searches, raw-event expansion, detection testing
against the complete dataset and original Splunk screenshots remain the next
validation stage. See [BOTSv3 validation status](09-BOTSv3-Investigation/validation-status.md).
