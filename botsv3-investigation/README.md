# BOTSv3 investigation

This project analyses six selected event extracts derived from Splunk's Boss
of the SOC version 3 dataset. The extracts contain 83 records across AWS,
Windows, DNS, Sysmon, Azure AD and Office 365 telemetry.

## Read the investigation

1. [Investigation report](analysis-report.md). Findings, evidence, assessment,
   confidence, correlation limits and response priorities.
2. [Evidence log](evidence-log.md). Fixture register, source references and
   evidence handling.
3. [Hunt workbook](hunt-workbook.md). Hypothesis-led Splunk searches across
   cloud, identity, endpoint and network telemetry.
4. [Dataset provenance](dataset-provenance.md). Upstream source files,
   published dataset metadata and local sanitization.
5. [Validation status](validation-status.md). Completed analysis, pipeline,
   regression testing and workflow validation.
6. [Full archive acquisition](full-dataset-acquisition.md). Reproducible
   download, checksum verification and dedicated lab installation.

## What the records show

The six extracts represent distinct investigative threads:

| Area | Source extract | Main question |
|---|---|---|
| AWS | CloudTrail activity attributed to `bstoll` | Were console and S3 API actions consistent with expected account use? |
| Windows | Selected `BSTOLL-L` logon events | What can this narrow authentication excerpt establish? |
| DNS | Coinhive related queries from an internal client | Does DNS activity indicate contact with Coinhive infrastructure? |
| Sysmon | PowerShell process creation on `FYODOR-L` | What does the process command line and parent context indicate? |
| Azure AD | Sign ins for `fyodor` and `bgist` | Are the successful sign ins from a shared IP anomalous? |
| Office 365 | Sharing and Exchange management events | What sharing and mailbox operations were recorded? |

These are separate scenario extracts. Shared names, IP addresses or timing
are investigative pivots, not proof of one actor or one continuous attack
chain.

## Run the local pipeline

From this directory:

```bash
python pipeline/analyze.py
python -m unittest discover -s pipeline -p "test_*.py" -v
```

The pipeline generates local SHA256 hashes for the current fixture files,
an inventory, a normalized CSV and a UTC timeline. These outputs are derived
from the committed extracts and are not full dataset results.

## Investigation deliverables

- Six findings with evidence IDs, source record ranges and confidence assessments.
- Cross-source pivots covering recurring identities, IP addresses and investigative context.
- MITRE ATT&CK assessment and detection opportunities.
- Evidence provenance and AWS identifier sanitization record.
- Python processing pipeline with regression tests and CI execution.
- Splunk hunt workbook for deeper investigation of the BOTSv3 telemetry.

The analysis is based on the six committed scenario extracts and their 83 records. The source register and report identify the scope of each observation.
