# BOTSv3 Investigation

### Splunk threat hunting · Multi-source correlation · Evidence-led analysis

## Objective

Use Splunk's Boss of the SOC version 3 (BOTSv3) dataset as the source for a separate, reproducible investigation. The workstream is designed to move from dataset orientation to source validation, hypothesis-led hunting, event correlation, findings, detection development and incident reporting.

BOTSv3 is a public training and research dataset published by Splunk. The upstream project describes it as a pre-indexed Splunk dataset of approximately 320.1 MB, distributed under CC0. Its documented search index is `botsv3`.

**Upstream source:** [splunk/botsv3](https://github.com/splunk/botsv3)

## Current status

| Work item | Status |
|---|---|
| Dataset source and published metadata reviewed | Complete |
| Investigation structure and evidence standard | Complete |
| Initial Splunk inventory searches prepared | Prepared; not executed |
| Sourcetype and host coverage confirmed locally | Pending |
| Hunt hypotheses tested against raw events | Pending |
| Event excerpts and search exports preserved | Pending |
| Findings and timeline supported by event references | Pending |
| Detection logic tested against dataset | Pending |
| Original Splunk screenshots | Pending |

This repository currently contains the investigation plan and reproducible starting searches. It does **not** claim that the dataset has been installed, queried or independently analysed. No event output, indicator, hash, timestamp or finding is represented as a result of a local BOTSv3 investigation until it has been collected and recorded.

## Investigation sequence

1. **Establish the dataset.** Record the upstream source, acquisition date, archive checksum and local Splunk version.
2. **Validate the environment.** Confirm the `botsv3` index, event volume, time coverage, hosts and sourcetypes.
3. **Map telemetry.** Identify which source families can answer the investigative questions and document missing coverage.
4. **Develop hypotheses.** Select a coherent activity thread based on the available records, rather than assuming a predetermined attack chain.
5. **Hunt and pivot.** Execute searches, inspect raw events, follow stable identifiers and preserve the exact search and time range.
6. **Build the evidence record.** Assign evidence IDs, record source metadata and hash exported artefacts.
7. **Assess findings.** Separate direct observations from correlations, interpretations and unresolved questions.
8. **Develop detections.** Test candidate logic against the dataset, inspect false positives and document limitations.
9. **Report.** Produce a concise incident narrative and timeline that can be reproduced from the preserved evidence.

## Repository contents

- [Dataset provenance and acquisition record](dataset-provenance.md)
- [Environment and data map](environment-and-data-map.md)
- [Hunt plan and SPL](hunt-plan.md)
- [BOTSv3 hunt workbook](hunt-workbook.md)
- [Analyst investigation notebook](analyst-notebook.md)
- [Evidence log](evidence-log.md)
- [Validation and detection engineering](validation-and-detection-engineering.md)
- [Investigation report template](report-template.md)

## Published dataset details

The upstream project publishes BOTSv3 as a 320.1 MB pre-indexed Splunk dataset, provides the historical MD5 reference and lists the included sourcetypes and software versions. Installation instructions specify extracting the dataset under `$SPLUNK_HOME/etc/apps`, restarting Splunk and querying `index=botsv3 earliest=0`. Review the [upstream instructions](https://github.com/splunk/botsv3) before installation; the listed Splunk and add-on versions are historical, so compatibility must be checked in the local environment.

## Evidence standard

A search is not a finding. A search becomes an investigative result only after its execution context and returned events have been reviewed.

For each material result, preserve:

- Search ID or job ID, exact SPL, index, time range and execution date.
- Event timestamp, host, sourcetype, source and relevant event identifiers.
- Raw event excerpt or export with sensitive or irrelevant fields handled appropriately.
- A SHA-256 hash for each retained export.
- Analyst interpretation, confidence, alternative explanations and next pivot.

Screenshots will be added after the local investigation is performed. Until then, the text records are preparation material, not substitutes for captured evidence.
