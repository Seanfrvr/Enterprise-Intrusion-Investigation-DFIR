# Enterprise Intrusion Investigation

**SOC analysis | Threat hunting | Digital forensics and incident response**

This repository contains a BOTSv3 based investigation using selected event
records from the public training dataset. It demonstrates evidence handling,
event analysis, cross source correlation, Splunk search development and
repeatable analysis with Python.

## Investigation

The main case study is in
[botsv3-investigation](botsv3-investigation/README.md).

Start with the [investigation report](botsv3-investigation/analysis-report.md)
for the findings, evidence limits and conclusions. The
[evidence log](botsv3-investigation/evidence-log.md) identifies the
committed records. The [hunt workbook](botsv3-investigation/hunt-workbook.md)
contains Splunk searches for extending the analysis into the full dataset.

## Analysis pipeline

The Python pipeline reads the six committed JSONL extracts and generates
fixture scoped integrity hashes, an event inventory, normalized CSV and a
UTC timeline.

From the repository root:

```bash
python botsv3-investigation/pipeline/analyze.py
python -m unittest discover -s botsv3-investigation/pipeline -p "test_*.py" -v
```

The pipeline uses the Python standard library. GitHub Actions runs the same
tests when relevant files change.

## Data and evidence boundary

The repository contains 83 records from six selected BOTSv3 derived scenario
extracts. These extracts represent separate investigative threads. They must
not be presented as one continuous intrusion or as proof that all named
identities, hosts and IP addresses were controlled by one actor.

The current records are attributed to their upstream source files. The AWS
fixture has stable replacement labels for temporary access key identifiers.
The full BOTSv3 archive has not been acquired or queried in a live Splunk
instance for this project. Findings are limited to the selected records.
Full index validation and original Splunk screenshots remain outstanding.

## Scope

The project focuses on:

- AWS CloudTrail identity and S3 API activity.
- Windows authentication context.
- DNS activity associated with Coinhive domains.
- Sysmon PowerShell process execution.
- Azure AD sign in activity.
- Office 365 sharing and mailbox administration events.

## Reproducibility

- [Dataset provenance](botsv3-investigation/dataset-provenance.md)
- [Full archive acquisition](botsv3-investigation/full-dataset-acquisition.md)
- [Evidence log](botsv3-investigation/evidence-log.md)
- [Validation status](botsv3-investigation/validation-status.md)
- [Pipeline source](botsv3-investigation/pipeline/analyze.py)

The purpose of this repository is to show how conclusions are derived from
records, where the evidence stops and what an analyst would validate next.
