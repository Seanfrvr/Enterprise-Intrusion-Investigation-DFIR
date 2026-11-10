# Evidence Catalogue

Use this register while collecting evidence. Create one row per source artefact or exported record set; do not fill fields from memory after the investigation.

## Evidence register

| ID | Source / host | Collection time (with zone) | Original time range | Record / file reference | SHA-256 | Handling / redaction |
|---|---|---|---|---|---|---|
| E-001 | Pending | Pending | Pending | Pending | Pending | Pending |

## Analyst observation

For each evidence ID, add a short entry using this structure:

- **Observed:** the exact value or behaviour visible in the source.
- **Context:** account, host, process, event ID or network tuple.
- **Relevance:** which investigative question it helps answer.
- **Limit:** what this artefact cannot establish by itself.
- **Next pivot:** the next source or identifier to check.

Keep observations separate from conclusions. If a value was not collected, write "not available"; do not infer it.

## Handling

- Preserve original exports and analyse working copies.
- Record the collection tool, command/query and collector.
- Hash files where appropriate and retain the hash with the original.
- Keep original timestamps and time zones; document any UTC conversion.
- Redact credentials, tokens, personal data and confidential information before publication.
- Keep a note of what was redacted and why.

A screenshot helps explain an investigation but is not a substitute for the underlying event. Capture the query, time range, source and relevant fields, and retain the event export where authorised.

**Current repository status:** the Northstar case register is illustrative. This catalogue is a blank working format; it does not represent collected evidence.
