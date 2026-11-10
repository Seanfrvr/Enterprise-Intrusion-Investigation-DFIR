# Investigation Timeline

Build the timeline from source records, not from memory or an assumed attack sequence.

## Timeline worksheet

| Original timestamp | Time zone | UTC timestamp | Host | Account / process | Event summary | Evidence ID | Confidence |
|---|---|---|---|---|---|---|---|
| Pending | Pending | Pending | Pending | Pending | Pending | Pending | Pending |

## Working rules

- Preserve the timestamp exactly as the source recorded it.
- Record the source host's time zone and known clock offset.
- Keep original time and normalised UTC side by side.
- Distinguish event time from SIEM ingestion time.
- Link every row to an evidence ID.
- Mark inferred ordering as inferred.
- Do not create minute-level precision when the source only supports a broader time window.

## Correlation

Use identifiers where available:

- **Windows logons:** Logon ID, account SID, source address and destination host.
- **Processes:** Process GUID and ParentProcessGuid; use PID with host and time context.
- **Files:** full path, process, size, hash and timestamps.
- **Network:** source/destination IP and port, protocol, process and connection disposition.

Temporal proximity is useful for finding pivots, but it does not prove that one event caused another. When records conflict, investigate clock drift, ingestion delay, time-zone settings and event-generation versus collection time.

**Current repository status:** the Northstar timeline is a reconstructed exercise timeline, not a timeline derived from retained source events.
