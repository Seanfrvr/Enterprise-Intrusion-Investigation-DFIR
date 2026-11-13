# Validation status

## Analysis and engineering completed

1. Reviewed public BOTSv3 project metadata and the public scenario repository.
2. Obtained six selected BOTSv3-derived JSONL event extracts and recorded their upstream source paths and Git blob identifiers.
3. Sanitized temporary AWS access key identifiers while preserving stable grouping labels.
4. Analysed 83 records across six telemetry sources and documented six findings with evidence references, assessments and confidence levels.
5. Developed cross-source pivots and assessed alternative explanations before drawing attribution conclusions.
6. Mapped supported behaviours to MITRE ATT&CK and identified detection opportunities.
7. Built a Python pipeline for fixture parsing, normalization, SHA-256 integrity calculation, inventory and UTC timeline generation.
8. Added regression tests for record counts, source coverage, timeline ordering, integrity output and AWS identifier sanitization.
9. Added GitHub Actions to run the pipeline tests and generate fixture-scoped analysis artefacts.
10. Manually ran the GitHub Actions workflow successfully. The workflow processed 83 records and generated the inventory, integrity manifest, normalized CSV and UTC timeline, including 36 timestamped records.

## Analysis scope

The investigation is based on six selected scenario extracts containing 83 records. The report uses source record references, distinguishes observed activity from hypotheses and treats recurring identities or IP addresses as investigative pivots rather than proof of common control.

The Splunk workbook contains analyst-authored searches for deeper investigation of the BOTSv3 telemetry. Its searches are separate from the Python fixture pipeline and should be interpreted as hunt logic, not as returned search results.

## Reproducible validation

Run from the repository root:

```bash
python botsv3-investigation/pipeline/analyze.py
python -m unittest discover -s botsv3-investigation/pipeline -p "test_*.py" -v
```

The pipeline regenerates the fixture integrity manifest, inventory, normalized event export and UTC timeline. GitHub Actions runs the regression suite when relevant repository files change.
