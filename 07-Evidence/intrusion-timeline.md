# Investigation Timeline

## Purpose

A timeline helps correlate activity across identities, endpoints and network sources. It should be populated only from verified timestamps and traceable evidence.

## Timeline rules

- Preserve the original timestamp exactly as recorded.
- Record the source time zone and any known clock offset.
- Normalise to UTC for cross-source comparison, retaining the original value.
- Do not invent missing timestamps or order events more precisely than the evidence allows.
- Mark inferred ordering and uncertain times explicitly.
- Link each row to an evidence identifier.

## Timeline template

| Original time | Time zone | Normalised UTC | Host | Account / process | Event summary | Evidence ID | Confidence |
|---|---|---|---|---|---|---|---|
| Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending |

## Correlation notes

When timestamps conflict, consider clock drift, ingestion delay, event-generation time versus collection time, daylight-saving changes and differences between endpoint and SIEM time settings. Document the chosen ordering method.

## Summary

A timeline is an analytical model, not proof of causation. Temporal proximity can support a hypothesis but does not establish that one event caused another.