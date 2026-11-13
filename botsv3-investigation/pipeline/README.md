# Fixture analysis pipeline

## Purpose

The pipeline analyses the six committed BOTSv3-derived JSONL extracts.
It produces a fixture inventory, normalized event table, integrity manifest
and UTC timeline. The current fixture set contains 83 records: 36 have usable
timestamps and 47 do not.

## Requirements

Python 3.10 or later. The pipeline uses only the Python standard library.

## Run from the repository root

```bash
python botsv3-investigation/pipeline/analyze.py
python -m unittest discover -s botsv3-investigation/pipeline -p "test_*.py" -v
```

## Generated outputs

| File | Purpose |
|---|---|
| `output/fixture-integrity.json` | SHA256, byte count and record count for each local fixture |
| `output/inventory.json` | Fixture-scoped event and sourcetype counts, timestamp coverage and user/source pivots |
| `output/normalized-events.csv` | Normalized events with source filename and line references |
| `output/timeline.json` | Timestamped records sorted in UTC |

The output directory is generated during execution. It is not original
evidence. Delete it and rerun the pipeline to reproduce the files.

## Data handling

The AWS CloudTrail fixture replaces temporary AWS access key identifiers
with stable labels. This preserves grouping between records while avoiding
unnecessary publication of credential metadata. The local SHA256 values
describe the sanitized files, not the original upstream bytes.

## Analytical safeguards

1. Missing timestamps remain missing. The pipeline does not infer event time.
2. Raw JSONL records remain the source records for fixture analysis.
3. The normalized CSV is a convenience view, not a replacement for raw events.
4. Shared usernames and IP addresses are pivots, not proof of common control.
5. A selected fixture cannot support a negative finding about the full dataset.
6. The inventory key `sourcetypes_by_user` maps each observed user string to the sourcetypes in which it appears.
7. Every report finding identifies its fixture and record range.

## Relationship to Splunk hunting

The pipeline provides repeatable processing and integrity checks for the committed fixture set. The companion [hunt workbook](../hunt-workbook.md) contains SPL searches for source discovery and hypothesis-led investigation in a Splunk environment. Keep Splunk search exports and their execution metadata as separate evidence artefacts from the generated fixture outputs.
