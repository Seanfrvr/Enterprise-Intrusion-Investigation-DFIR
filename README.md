# Enterprise Intrusion Investigation

**SOC analysis · Splunk · Windows telemetry · DFIR**

A working collection of Windows investigation notes, Splunk hunt examples and evidence-handling references, alongside a reconstructed enterprise case exercise.

> **Honest project status:** this repository currently contains investigation notes and proposed SPL, not a fully evidenced end-to-end incident investigation. The Northstar case is reconstructed for analytical practice. Its source events, screenshots and Splunk results are not retained, and its searches have not been validated against a dataset. I do not present it as a real incident or completed live investigation.

## Start here

| Section | What is here |
|---|---|
| [Investigation notes](02-Investigation/) | Practical pivots for execution, persistence, credential access, lateral movement, collection and C2 |
| [Splunk hunt notebook](04-Detection-Engineering/splunk-hunting.md) | A small set of Windows/Sysmon SPL examples with field assumptions |
| [Detection engineering](04-Detection-Engineering/detection-rules.md) | What makes a hunt operationally useful and how to validate it |
| [Windows artefacts](05-Digital-Forensics/windows-artifacts.md) | Event IDs and artefact interpretation |
| [Evidence handling](07-Evidence/evidence-catalogue.md) | Evidence recording and integrity notes |
| [Timeline method](07-Evidence/intrusion-timeline.md) | Building a traceable cross-host timeline |
| [Northstar case exercise](08-Simulated-Investigation/) | Reconstructed incident narrative, findings and validation plan |

## How I approach an investigation

1. Start with the raw event and confirm its provider, channel, timestamp and fields.
2. Identify the account, host, process or network tuple involved.
3. Pivot using stable identifiers such as Logon ID and Process GUID.
4. Check whether the activity fits the host's role and the account's normal use.
5. Test at least one benign explanation.
6. Record what the evidence shows separately from what it might mean.
7. Write a detection only after understanding the data and its limitations.

## Current limitations

- The SPL examples are starting points. They have not been run and tuned against the Northstar case data.
- The Northstar event sequence is illustrative, not source-backed.
- No screenshots or raw event exports are included as evidence.
- Generic investigation notes are reference material, not proof of practical experience.

The next meaningful improvement is not another document. It is a small investigation using permitted telemetry, with the actual query, raw events, pivots, false leads and screenshots captured as the work is done.
