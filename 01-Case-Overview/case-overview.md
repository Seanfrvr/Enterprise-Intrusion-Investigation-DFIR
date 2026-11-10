# Case Overview

## Purpose

This playbook provides a repeatable approach for investigating suspected enterprise intrusion activity using Windows telemetry and a SIEM. It is intended to support practical SOC analysis, threat hunting and DFIR documentation.

It is a methodology reference, not a report of a particular real-world incident. Any future case-specific findings must be supported by an identified dataset, evidence references and documented validation.

## Scope

The investigation model covers:

- Identity and account activity.
- Process execution and native administration utilities.
- Persistence indicators.
- Defence-evasion and anti-forensic behaviour.
- Credential-access indicators.
- Host discovery and lateral movement.
- Access to and staging of sensitive data.
- Network configuration and possible command-and-control activity.
- Log tampering and evidence preservation.

## Core investigative questions

1. What activity triggered the investigation?
2. Which hosts, accounts and data sources are in scope?
3. What happened before and after the triggering event?
4. Which observations are directly supported by telemetry?
5. Can related events be correlated across hosts and data sources?
6. What alternative benign explanations exist?
7. What can and cannot be concluded?
8. What detection, containment and recovery actions are justified?

## Evidence standard

Every material conclusion should reference an evidence identifier and include:

| Attribute | Requirement |
|---|---|
| Source | Original log, file, registry artefact or telemetry platform |
| Time | Original timestamp, time zone and normalised UTC where possible |
| Context | Host, user, process, parent process and relevant network details |
| Observation | What the artefact directly shows |
| Interpretation | What the observation may mean |
| Confidence | High, medium or low, with rationale |
| Limitation | Missing fields, collection gaps or alternative explanations |

## Confidence model

- **High:** directly supported by reliable evidence and corroborated where appropriate.
- **Medium:** supported by relevant evidence but with a material gap or plausible alternative.
- **Low:** hypothesis based on incomplete or indirect indicators.
- **Unknown:** evidence is insufficient to make a defensible assessment.

## Assumptions and boundaries

Do not infer attribution from a tool name, command pattern or ATT&CK match. Do not claim credential recovery, successful command-and-control, or data exfiltration without evidence of the outcome. Preserve uncertainty rather than filling gaps with assumptions.