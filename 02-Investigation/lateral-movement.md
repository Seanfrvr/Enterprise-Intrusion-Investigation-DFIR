# Discovery and Lateral Movement

## Objective

Determine how an actor may have discovered other systems and whether access moved from one host or identity to another.

## Useful Windows telemetry

| Event | General significance |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned to a new logon |
| 4768 | Kerberos authentication ticket requested |
| 4769 | Kerberos service ticket requested |
| 4776 | NTLM credential validation |
| 4688 | Process creation, if enabled |

Event availability depends on audit policy, domain role and log source.

## Analysis method

1. Identify the suspected source host, destination host and account.
2. Build a timeline of authentication events across both systems.
3. Review logon type, source address, workstation name and authentication package where available.
4. Correlate successful logons with remote service access, process creation and file transfers.
5. Compare the activity with normal administration and service-account behaviour.
6. Look for repeated access patterns across multiple hosts.

## Correlation cautions

A Kerberos service-ticket request is common in normal domain activity. A successful logon is not automatically lateral movement. Stronger conclusions require source/destination context, unusual account behaviour and related execution or access evidence.

## Detection opportunities

Hunt for privileged accounts authenticating to unusual hosts, remote logons outside expected administration windows, explicit-credential use followed by remote execution, and rare account-to-host relationships. Tune for helpdesk, deployment, backup and endpoint-management systems.