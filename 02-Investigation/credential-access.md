# Credential Access

## Objective

Investigate activity that may expose passwords, hashes, tickets, tokens or other authentication material.

## Telemetry and artefacts

- Process creation and command-line telemetry.
- EDR alerts for suspicious access to LSASS.
- Memory-dump file creation and access.
- Windows Security authentication events.
- PowerShell and command-shell activity.
- Registry access involving remote-access or credential-management software.
- Active Directory database access and backup activity.
- Identity-provider sign-in and token events.

## Analysis method

1. Identify the process associated with credential-access behaviour.
2. Review process ancestry, account, integrity level and host role.
3. Correlate process access to LSASS with dump-file creation or suspicious utility execution.
4. Determine whether directory database files were accessed, copied or staged.
5. Review subsequent authentication activity for possible use of exposed material.
6. Separate attempted access from confirmed acquisition and confirmed credential reuse.

## Important distinctions

- Access to LSASS is not proof that credentials were recovered.
- Creation of a memory dump is not proof that it contained usable secrets.
- Access to an Active Directory database is not proof that the database was successfully extracted.
- A suspicious tool name alone is not proof of malicious activity.

## Response priorities

If credential exposure is credible, preserve evidence, identify affected accounts and systems, revoke sessions where appropriate, rotate exposed secrets in a controlled sequence, review privileged accounts and investigate whether authentication material was subsequently used. Coordinate with identity and directory-service owners to avoid disrupting recovery.