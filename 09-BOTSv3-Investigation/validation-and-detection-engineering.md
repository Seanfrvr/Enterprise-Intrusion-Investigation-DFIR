# Validation and Detection Engineering

## Purpose

This document defines how BOTSv3 hunt logic will be evaluated before any search is described as a validated detection. The dataset is a historical, pre-indexed training dataset; it is useful for exercising investigation and detection workflows, but it is not a substitute for testing against a current production environment.

## Validation stages

| Stage | Test | Required record | Pass condition |
|---|---|---|---|
| 1. Data availability | Confirm index, time range, hosts and sourcetypes | Inventory exports | Required source is present |
| 2. Schema | Inspect raw events and extracted fields | Field notes and representative event references | Required fields are consistently available or limitations documented |
| 3. Logic | Execute hunt against relevant time range | Exact SPL, search ID and output | Search returns interpretable records |
| 4. Context | Inspect benign and suspicious examples | Event references and analyst notes | Behaviour is understood in context |
| 5. Correlation | Pivot using stable identifiers | Linked evidence IDs | Relationship is supported beyond timestamp coincidence |
| 6. False positives | Review legitimate activity and edge cases | Tuning notes | Known benign patterns documented |
| 7. Regression | Re-run final search after changes | Versioned SPL and result summary | Expected behaviour remains reproducible |
| 8. Documentation | Record coverage and limitations | Detection specification | Another analyst can reproduce the test |

## Detection specification template

| Field | Description |
|---|---|
| Detection ID | Stable identifier, e.g. BOTSV3-DET-01 |
| Name | Behaviour-oriented title |
| Objective | Threat or behaviour the logic is intended to surface |
| Data sources | Exact index and sourcetypes |
| Required fields | Fields verified in raw events |
| Logic | Exact SPL and version |
| Trigger | Threshold, sequence or condition |
| Context | Entity and event fields included in output |
| False positives | Known legitimate patterns |
| Tuning | Exclusions and rationale |
| Test evidence | Search IDs and evidence references |
| Limitations | Coverage, parser and dataset constraints |
| Status | Draft / tested in BOTSv3 / production candidate |

## Initial detection candidates

These are candidates to evaluate after source inventory, not finished detections:

1. Cloud control-plane operations with unusual principal, source or service context.
2. Identity sign-in sequences with unusual user/application/device combinations.
3. Endpoint process execution with suspicious parent-child or command-line context.
4. DNS or HTTP activity that becomes suspicious when correlated with endpoint or identity evidence.
5. Security-provider findings that can be enriched with underlying cloud audit and network records.

Do not assign a severity or ATT&CK technique solely because a search matches a keyword or event name.

## Test cases

For each detection candidate, document at least:

- **Positive example:** a real event or event sequence that should match, with evidence IDs.
- **Benign example:** a legitimate event or sequence that should not alert, or should be excluded.
- **Boundary case:** incomplete fields, missing source, duplicate events, time skew or unusual but valid administration.
- **Expected result:** what the detection should do.
- **Actual result:** what the executed search did.
- **Disposition:** pass / fail / inconclusive, with rationale.

If the dataset does not contain an appropriate positive or benign example, record the test as not available. Do not manufacture a fixture and call it a BOTSv3 observation.

## Production-readiness boundary

Passing a test against BOTSv3 means the logic was exercised against this dataset under the recorded conditions. It does not establish production efficacy, complete coverage, acceptable alert volume or compatibility with a different Splunk version, add-on set or field-normalisation scheme. Production deployment requires environment-specific validation.
