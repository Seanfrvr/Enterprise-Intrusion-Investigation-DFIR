# Validation status

## Completed

1. Reviewed public BOTSv3 project metadata and the public scenario repository.
2. Obtained six selected BOTSv3-derived JSONL event extracts.
3. Recorded the original upstream source paths and Git blob SHAs.
4. Redacted AWS temporary access key identifiers in the current AWS fixture.
5. Added a Python pipeline for fixture parsing, normalization, SHA-256
   calculation, inventory and UTC timeline generation.
6. Added unit tests for expected record counts, source coverage, timeline
   ordering, integrity output and AWS identifier redaction.
7. Documented six findings with fixture references and confidence limits.
8. Added Splunk hunt searches for follow-up investigation.
9. Added a GitHub Actions workflow for repeatable fixture analysis.
10. GitHub Actions run 33 completed successfully on 10 November 2026.
    The Python test step and generated analysis artifact step both passed.

## Not completed

1. Full BOTSv3 archive download and MD5 verification.
2. Installation of the full archive in Splunk.
3. Full-index event counts and sourcetype inventory.
4. Field extraction validation against the full index.
5. Execution of the hunt workbook against the complete \`index=botsv3\`.
6. Review of all surrounding raw events and complete time windows.
7. Original screenshots from a live Splunk search session.
8. Detection performance testing against benign and malicious baselines.

## Interpretation limits

The extracts are selected records from a public BOTSv3-derived source. The
AWS fixture contains stable redaction labels in place of temporary access key
identifiers. The current local hashes describe these sanitized bytes.

Absence of an event from a selected extract does not establish that the event
is absent from BOTSv3. Fixture counts are not full dataset counts. Identity
and IP matches are investigative pivots, not proof of common control or
attribution.

## Next validation session

1. Download the official archive using [the acquisition script](scripts/acquire-botsv3.sh).
2. Verify the published MD5 before extraction.
3. Install only in a dedicated Splunk lab.
4. Record the Splunk version, add-ons, index status and time range.
5. Run the inventory searches in [the hunt workbook](hunt-workbook.md).
6. Compare full-index records with the six selected extracts.
7. Expand each finding using raw events and stable identifiers.
8. Export the search results, calculate SHA-256 and update the evidence log.
9. Capture original screenshots and update the report only where supported.
