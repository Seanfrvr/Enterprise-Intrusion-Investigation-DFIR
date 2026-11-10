# BOTSv3 investigation

This workstream uses public BOTSv3-derived event extracts to build a traceable
SOC investigation and a repeatable analysis pipeline.

## Start here

1. [Full dataset acquisition](full-dataset-acquisition.md)
2. [Dataset provenance](dataset-provenance.md)
3. [Fixture analysis report](analysis-report.md)
4. [Run the local pipeline](pipeline/README.md)
5. [Pipeline source](pipeline/analyze.py)
6. [Hunt workbook for full-index validation](hunt-workbook.md)
7. [Analyst notebook](analyst-notebook.md)
8. [Evidence log](evidence-log.md)
9. [Validation status](validation-status.md)

## Data included

Six selected JSONL extracts are committed under [data/fixtures](data/fixtures/).
They contain 83 records across:

- AWS CloudTrail
- Windows logon metadata
- DNS
- Sysmon process creation
- Azure AD sign-ins
- Office 365 management activity

The records are derived from the public fixture files. The AWS fixture has been sanitized to replace temporary credential identifiers. Original source paths and blob SHAs are recorded in [dataset provenance](dataset-provenance.md). The local analysis pipeline and its regression tests passed in GitHub Actions run 41. These are selected event slices, not the
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
UTC timeline outputs. GitHub Actions is configured to run the same tests when relevant files change.

## Validation boundary

**Fixture-backed:** means the raw records are present in this repo
and traceable to their upstream source files.

**Full-index validation pending:** means the complete BOTSv3 archive
has not been acquired and searched in the user's Splunk environment. The
hunt workbook contains queries to execute and validate later. No full-index
search results or screenshots are claimed here.
