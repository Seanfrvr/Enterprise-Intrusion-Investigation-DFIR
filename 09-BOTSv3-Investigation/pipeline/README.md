# BOTSv3 fixture analysis pipeline

## Scope

This pipeline operates on six small JSONL fixture extracts copied from the public
\`splunk-bots-hunts\` project. The upstream project identifies them as BOTSv3
event slices. Each local fixture has a source GitHub path and immutable source
blob SHA recorded in \`../dataset-provenance.md\`.

These are **not the complete BOTSv3 archive** and are **not a local acquisition
of the full index**. They are suitable for learning data handling, field
normalization, event correlation and report generation. Do not use fixture
record counts as full-dataset statistics.

## Run

Requires Python 3.10+ and no third-party packages.

\`\`\`bash
cd 09-BOTSv3-Investigation
python pipeline/analyze.py
\`\`\`

Generated files:

- \`output/fixture-integrity.json\` — SHA-256 and byte/record counts for the local fixture files.
- \`output/inventory.json\` — fixture-scoped sourcetype counts and identity/IP pivots.
- \`output/normalized-events.csv\` — normalized events with original fixture/line references.
- \`output/timeline.json\` — records with parseable timestamps, sorted in UTC.

Generated output is reproducible and can be deleted/rebuilt. The original JSONL
fixtures are never modified.

## Analytical safeguards

- Missing timestamps remain missing; no timestamp is inferred.
- Raw source fields are retained in the JSONL files.
- The normalized CSV is a convenience view, not a replacement for raw records.
- Shared usernames/IPs create pivots for investigation; they do not prove attribution.
- A narrow fixture cannot support a negative finding about the complete dataset.
- Every conclusion in the report must identify the source fixture and record line(s).

## Next stage: full dataset validation

When Splunk and the complete BOTSv3 dataset are available, validate the same
hypotheses against \`index=botsv3\`, inspect raw events before relying on extracted
fields, and export the actual search results. Keep the fixture pipeline output
separate from full-index results.
