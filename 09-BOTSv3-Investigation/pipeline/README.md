# BOTSv3 fixture analysis pipeline

## Purpose

This pipeline parses six selected JSONL event extracts attributed to BOTSv3.
It produces a repeatable fixture inventory, normalized event table, integrity
manifest and UTC timeline.

It does not download BOTSv3, install Splunk, or query the full index.

## Requirements

Python 3.10 or later. The pipeline uses only the Python standard library.

## Run

From the repository root:

```bash
cd 09-BOTSv3-Investigation
python pipeline/analyze.py
python -m unittest discover -s pipeline -p "test_*.py" -v
```

## Outputs

| File | Purpose |
|---|---|
| `output/fixture-integrity.json` | SHA-256, byte count and record count for each local fixture |
| `output/inventory.json` | Fixture-scoped event and sourcetype counts |
| `output/normalized-events.csv` | Normalized events with original fixture and line references |
| `output/timeline.json` | Timestamped records sorted in UTC |

The output directory is generated during execution and is not a source of
original evidence. Delete it and rerun the pipeline to reproduce the files.

## Data handling

The AWS CloudTrail fixture has been sanitized after GitHub secret scanning
identified temporary AWS access key identifiers. The current records contain
stable redaction labels in place of those values. The source event structure
and relationships are retained.

The pipeline hashes the exact local fixture bytes. Its SHA-256 values therefore
describe the sanitized files, not the original upstream Git blobs.

## Analytical safeguards

1. Missing timestamps remain missing. The pipeline does not infer event time.
2. Raw JSONL records remain the primary source for this fixture analysis.
3. The normalized CSV is a convenience view, not a replacement for raw events.
4. Shared usernames and IP addresses are pivots, not proof of common control.
5. A selected fixture cannot support a negative finding about the full dataset.
6. Every report finding must identify the fixture and record range that supports it.

## Full dataset validation

When the complete BOTSv3 archive and Splunk are available, validate the same
hypotheses against `index=botsv3`. Inspect raw events before relying on field
extractions. Preserve the exact SPL, time range, search job ID and exported
results for each hunt. Keep full-index results separate from fixture outputs.
