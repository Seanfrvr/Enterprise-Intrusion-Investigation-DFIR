# Persistence

## Objective

Identify mechanisms that could allow continued access after the initial execution or authentication event.

## Areas to examine

- Services and scheduled tasks.
- Run keys and startup locations.
- New or modified local and domain accounts.
- Web-server content and application configuration.
- Unusual scripts or executables in writable directories.
- Remote-management and remote-access configuration.
- EDR persistence findings and autorun telemetry.

## Web application considerations

For a suspected web shell or malicious server-side script, correlate:

1. File creation and modification metadata.
2. Web-server access logs and request methods.
3. Requests to unusual paths or newly created resources.
4. Web-server worker process activity and child processes.
5. Outbound network connections initiated by the web-server process.
6. Account and privilege context of any resulting process.

A suspicious file on a web server is not sufficient to prove remote command execution. Seek evidence that the file was requested and that the server process performed unexpected actions.

## Evidence preservation

Collect the file, metadata, relevant web logs, application configuration and process telemetry in a forensically sound manner. Record hashes and collection times where possible. Do not execute a suspected payload during triage.

## Defensive controls

Restrict write access to web roots, separate application identities from administrative accounts, monitor unexpected child processes of web-server workers, maintain file-integrity monitoring and centralise web access logs.