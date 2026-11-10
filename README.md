# VOLT TYPHOON
### Enterprise Intrusion Investigation | Security Operations | Digital Forensics & Incident Response

<p align="center">
  <strong>SIEM INVESTIGATION · THREAT HUNTING · WINDOWS FORENSICS · MITRE ATT&CK</strong>
</p>

---

## Project Overview

This repository documents a hands-on investigation of a simulated enterprise intrusion attributed to Volt Typhoon.

The investigation reconstructs adversary activity across a Windows-based environment through the examination of security telemetry, process execution records, registry activity, authentication artefacts and file-system operations.

Using Splunk as the primary investigation platform, supported by CyberChef for encoded-data analysis, the investigation follows the progression of an intrusion from initial access through persistence, credential access, lateral movement, data collection, command and control, and cleanup.

The objective is to demonstrate the analytical process behind a SOC investigation: identifying suspicious activity, validating evidence, correlating events, interpreting adversary behaviour and translating findings into defensive recommendations.

**This is an investigation-focused project, not simply a collection of completed lab answers.**

> Project status: Private development repository. Publication of room-specific evidence is pending confirmation of applicable permissions.

---

## Investigation Profile

| Attribute | Details |
|---|---|
| Investigation | Volt Typhoon |
| Environment | Simulated enterprise network |
| Primary platform | Splunk Enterprise |
| Supporting tool | CyberChef |
| Operating environment | Windows |
| Investigation discipline | SOC investigation / DFIR |
| Behaviour framework | MITRE ATT&CK Enterprise |
| Primary focus | Adversary activity reconstruction |

## Executive Summary

The investigation identified a sequence of activities consistent with a structured enterprise intrusion.

Observed behaviour included account compromise, administrative account creation, reconnaissance using native Windows utilities, Active Directory database access, web shell deployment, credential-access attempts, movement between servers, collection of financial information and attempts to conceal activity.

A recurring characteristic was the abuse of legitimate administrative functionality.

Rather than relying exclusively on conspicuous malware execution, the activity included PowerShell, WMIC, registry queries, Windows event-log utilities and other native system capabilities.

This highlights a central challenge for SOC analysts: legitimate tools can become suspicious when used in unusual combinations, by unexpected accounts, on unexpected systems or outside normal administrative workflows.

The investigation therefore prioritised behavioural context and event correlation over treating individual executable names as definitive indicators of compromise.

## Investigation Objectives

The investigation aimed to answer the following questions:

1. How was access established within the environment?
2. Which accounts and systems were involved?
3. What commands and utilities were executed?
4. How was continued access maintained?
5. What evidence of defence evasion was present?
6. How did the attacker attempt to obtain authentication material?
7. How did the attacker discover and access additional systems?
8. What information was targeted for collection?
9. What command-and-control configuration was identified?
10. What evidence was removed during cleanup?

## Attack Progression

The investigation is organised around the following adversary activity stages.

| Stage | Activity | Investigation focus |
|---|---|---|
| 01 | Initial Access | Account compromise and entry into the environment |
| 02 | Execution | Command execution and system reconnaissance |
| 03 | Persistence | Web shell deployment |
| 04 | Defense Evasion | Removal and disguise of activity artefacts |
| 05 | Credential Access | Registry reconnaissance and credential extraction attempts |
| 06 | Discovery & Lateral Movement | Event-log enumeration and movement between servers |
| 07 | Collection | Identification and copying of financial information |
| 08 | C2 & Cleanup | Proxy configuration and event-log destruction |

## Technical Investigation

The technical reports document the evidence, investigative reasoning and defensive significance of each stage.

| Report | Description |
|---|---|
| [Initial Access](03-Technical-Investigation/initial-access.md) | Account compromise and administrative access |
| [Execution](03-Technical-Investigation/execution.md) | WMIC, NTDS database access and command execution |
| [Persistence](03-Technical-Investigation/persistence.md) | Web shell deployment and continued access |
| [Defense Evasion](03-Technical-Investigation/defense-evasion.md) | Registry modifications, file disguise and environment checks |
| [Credential Access](03-Technical-Investigation/credential-access.md) | Software reconnaissance, Mimikatz and LSASS analysis |
| [Discovery & Lateral Movement](03-Technical-Investigation/discovery-lateral-movement.md) | Windows event enumeration and movement between servers |
| [Collection](03-Technical-Investigation/collection.md) | Financial data identification and file copying |
| [C2 & Cleanup](03-Technical-Investigation/c2-cleanup.md) | Proxy configuration and event-log clearing |

## MITRE ATT&CK Analysis

The investigation uses the MITRE ATT&CK Enterprise framework to classify observed adversary behaviour.

The mapping distinguishes between:

- Observed techniques supported directly by evidence.
- Behaviour correlated across multiple events.
- Analytical interpretations that require further validation.

The objective is to connect technical observations to recognised adversary tactics and techniques without overstating what the evidence establishes.

**[View MITRE ATT&CK Mapping](04-MITRE-ATTACK/mitre-mapping.md)**

## Investigation and Detection Engineering

The investigation also considers how the observed behaviour could be identified by a defensive security team.

Areas of interest include:

- Unusual administrative account activity.
- Suspicious WMIC and PowerShell execution.
- NTDS database access and copying.
- Unexpected web shell creation.
- Registry modifications associated with activity removal.
- Access to LSASS memory and suspicious memory dumps.
- Authentication-event enumeration.
- Unexpected file transfers between servers.
- Bulk access to sensitive financial information.
- Changes to proxy configuration.
- Windows event-log clearing.

**[View Detection Opportunities](05-Detection-Engineering/detection-opportunities.md)**

## Evidence and Investigation Artefacts

Evidence documentation will include relevant Splunk observations, CyberChef analysis and supporting investigative notes where publication is authorised.

Each artefact will be associated with:

- An evidence identifier.
- Investigation stage.
- Source or log type.
- Observation.
- Analytical significance.
- Related MITRE ATT&CK technique, where applicable.

Original screenshots and unmodified evidence will be retained separately from any redacted presentation copies.

## Investigation Timeline

A consolidated timeline will correlate the observed activity across the investigation stages.

**[View Intrusion Timeline](08-Timeline/intrusion-timeline.md)**

## Defensive Assessment

The final assessment will consider:

- Visibility gaps exposed by the investigation.
- Opportunities for improved Windows telemetry collection.
- Detection opportunities for living-off-the-land activity.
- Credential protection and privileged-access controls.
- Web server hardening.
- Monitoring of internal proxy configuration.
- Event-log protection and centralised log retention.
- Incident containment and evidence preservation.

**[View Incident Response Recommendations](06-Incident-Response/recommendations.md)**

---

## Tools and Technologies

| Technology | Application |
|---|---|
| Splunk Enterprise | SIEM investigation and event analysis |
| CyberChef | Encoded-data analysis |
| Windows Event Logs | Authentication and system activity investigation |
| PowerShell | Script and command-line investigation |
| Windows Registry | Configuration and activity artefact analysis |
| MITRE ATT&CK | Adversary behaviour classification |

## Skills Demonstrated

- SIEM-based investigation
- Splunk search and event analysis
- Windows event-log investigation
- PowerShell command-line analysis
- Digital forensics and incident reconstruction
- Credential-access investigation
- Active Directory security
- Threat hunting
- Lateral movement analysis
- MITRE ATT&CK mapping
- Detection and incident response reasoning
- Technical documentation

## Scope and Limitations

This is a simulated investigation performed within an authorised training environment.

The conclusions are limited to the available telemetry and evidence examined during the exercise.

The presence of a command or tool does not automatically establish successful execution of every intended objective. For example, analysing an LSASS dump demonstrates credential-access activity, but does not independently prove that credentials were successfully recovered or reused.

Likewise, file copying establishes collection activity but does not, without additional evidence, prove successful external exfiltration.

The project does not independently establish real-world attribution.

## Disclaimer

This project is intended for defensive cybersecurity education and professional portfolio development.

TryHackMe and its training materials remain the property of their respective owners. This project is not affiliated with or endorsed by TryHackMe.

Publication of room-specific findings, screenshots and other training material is subject to the applicable platform policies and intellectual property permissions.
