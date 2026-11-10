# Collection

## Objective

Determine whether sensitive information was accessed, gathered or staged, and assess whether there is evidence of subsequent transfer.

## Sources to examine

- File-system create, read, rename and delete telemetry.
- PowerShell and process command lines.
- File-server and share-access auditing.
- EDR file activity.
- Archive creation and compression activity.
- DLP alerts and cloud-storage audit logs.
- Network flow, proxy and firewall records.

## Analysis method

1. Identify the sensitive data locations and relevant access controls.
2. Establish the user and process responsible for access.
3. Review file names, paths, extensions, sizes and timestamps.
4. Compare activity with the account's normal role and access pattern.
5. Determine whether files were copied, compressed or staged in a new location.
6. Search for evidence of transfer to an external or otherwise unusual destination.

## Collection versus exfiltration

Reading or copying a file supports a collection assessment. Creating an archive supports a staging assessment. Neither proves that data left the environment. To assess exfiltration, correlate staging with network, proxy, cloud or endpoint transfer evidence.

## Reporting

Record the data category, affected systems, access scope, evidence source, transfer evidence and unresolved questions. Avoid exposing real personal or confidential information in portfolio examples; use synthetic filenames and data.