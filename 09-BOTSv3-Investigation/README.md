# BOTSv3 investigation

This workstream uses public BOTSv3-derived event extracts to build a traceable
SOC investigation and a repeatable analysis pipeline.

## Start here

1. [Dataset provenance](dataset-provenance.md)
2. [Fixture analysis report](analysis-report.md)
3. [Run the local pipeline](pipeline/README.md)
4. [Pipeline source](pipeline/analyze.py)
5. [Hunt workbook for full-index validation](hunt-workbook.md)
6. [Analyst notebook](analyst-notebook.md)
7. [Evidence log](evidence-log.md)
8. [Validation status](validation-status.md)

## Data included

Six selected JSONL extracts are committed under [data/fixtures](data/fixtures/).
They contain 83 records across:

- AWS CloudTrail
- Windows logon metadata
- DNS
- Sysmon process creation
- Azure AD sign-ins
- Office 365 management activity

The records were copied without modification from the public fixture files
listed in [dataset provenance](dataset-provenance.md). The upstream Git blob
SHA is recorded for each source. These are selected event slices, not the
complete BOTSv3 archive or a complete export of `index=botsv3`.

## Investigation thread

The extracts support a set of related investigative pivots:

- AWS: activity attributed in CloudTrail to IAM user `bstoll`, including
  successful console sign-in records without MFA and repeated S3 bucket ACL checks.
- Endpoint: a narrow BSTOLL-L logon excerpt, useful for scoping local logon
  context but insufficient to rule out other access.
- DNS: queries from an internal client to Coinhive-related domains.
- Sysmon: hidden PowerShell execution on `FYODOR-L`, including registry value
  retrieval and dynamic invocation.
- Azure AD: successful sign-ins for `fyodor` and `bgist` from a shared source
  IP with Hong Kong location fields in the selected extract.
- Office 365: anonymous-link creation/use for a `.lnk` file and Exchange
  `Set-Mailbox` operations.

The report documents observations, assessments, confidence and next pivots.
The cross-source relationships are not treated as proof of a single actor or
complete intrusion chain.

## Reproduce the local analysis

From this directory:

```bash
python pipeline/analyze.py
python -m unittest discover -s pipeline -p "test_*.py" -v
```

The pipeline writes fixture integrity hashes, inventory, normalized CSV and
UTC timeline outputs. GitHub Actions runs the same tests on changes.

## Validation boundary

<badge>Fixture-backed</badge> means the raw records are present in this repo
and traceable to their upstream source files.

<badge>Full-index validation pending</badge> means the complete BOTSv3 archive
has not been acquired and searched in the user's Splunk environment. The
hunt workbook contains queries to execute and validate later. No full-index
search results or screenshots are claimed here.
