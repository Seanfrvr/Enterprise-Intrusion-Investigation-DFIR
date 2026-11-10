# Credential Access

## Investigation question

Was authentication material accessed, acquired or subsequently used? Treat these as separate claims.

## LSASS investigation

For Sysmon Event ID 10 or an EDR process-access alert, capture:

- Source process path, PID and ProcessGuid.
- Target process (confirm it is LSASS).
- Granted access mask and call trace, where available.
- User, integrity level and parent process.
- File signature, SHA-256 and file creation metadata.
- Related dump-file creation or EDR findings.

Then check whether the source process is an approved security or diagnostic tool. Compare its signer, path, hash and prevalence with known-good endpoint software.

**Important:** process access to LSASS is not proof that credentials were dumped. A dump file is not proof that usable secrets were recovered.

## Other credential sources

Depending on the suspected technique, review:

- Authentication events for unusual account use after the suspected access.
- PowerShell and process telemetry for credential-related commands.
- Access to directory database or registry files.
- Browser, password-manager or application credential stores, where authorised.
- Identity-provider session, token and MFA events.

## Build the evidence chain

1. Identify the process or action that may have accessed credentials.
2. Establish whether credential material was actually acquired.
3. Identify which accounts or secrets could have been exposed.
4. Look for later authentication that could indicate reuse.
5. Record what remains unknown.

Do not recommend indiscriminate password resets before identifying affected identities and coordinating the order with system owners. Preserve evidence and revoke sessions or rotate secrets proportionately to the confirmed exposure.
