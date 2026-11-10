# Validation status

## Completed

- Reviewed public BOTSv3 scenario documentation and selected six event fixture extracts.
- Copied the selected JSONL records without changing their event content.
- Recorded upstream source paths and Git blob SHAs in [dataset provenance](dataset-provenance.md).
- Added a local Python pipeline for fixture parsing, normalization, local SHA-256 calculation, inventory and UTC timeline generation.
- Generated a fixture-scoped inventory containing 83 records across six source families.
- Documented six findings in [analysis report](analysis-report.md), each tied to the selected fixture records and explicit confidence limits.

## Not completed

- Full BOTSv3 archive acquisition and MD5 verification.
- Installation of the full dataset in Splunk.
- Full-index event counts, sourcetype inventory or field-extraction validation.
- Execution of the hunt workbook against the complete \`index=botsv3\`.
- Review of all surrounding raw events and complete time windows.
- Original screenshots captured from a live Splunk search session.
- Detection performance, false-positive and false-negative testing against a benign baseline.

## Interpretation constraints

The committed extracts are real records copied from a public BOTSv3-derived
fixture repository, but they are partial. Absence of an event from a fixture
is not evidence that the event is absent from BOTSv3. All counts in the local
inventory apply only to the six committed files. Identity and IP matches are
investigative pivots, not proof of common control or attribution.
