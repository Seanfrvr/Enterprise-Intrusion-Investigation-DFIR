# Execution

## Objective

Identify suspicious process execution and determine whether a command or utility was used in an unusual context.

## Telemetry to review

- Windows Security event 4688, when process creation auditing is enabled.
- Sysmon Event ID 1 for process creation.
- PowerShell operational logs, including script-block logging where configured.
- EDR process trees and command-line telemetry.
- Parent process, user, integrity level, executable path, hash and signature.

## Analysis method

1. Identify the process and preserve the complete command line.
2. Review parent-child relationships and the initiating account.
3. Check executable path, signature, hash and prevalence.
4. Compare the command with expected administration on that host.
5. Correlate execution with file creation, registry changes, authentication and network connections.
6. Assess whether the command completed successfully; do not infer success from process creation alone.

## Native tools and context

Legitimate utilities such as PowerShell, WMIC, command shell and Windows administration tools can be abused. Their presence is not a detection by itself. Stronger signals include unusual parent processes, encoded or obfuscated arguments, execution from user-writable paths, unexpected remote targets, rare account/host combinations and suspicious follow-on activity.

## Investigation record

Document the process GUID or event identifier, host, user, process and parent process, command line, timestamp, associated artefacts, benign explanations considered and confidence.

## Detection engineering

Prefer behaviour-based combinations over simple executable-name matches. Tune against known IT automation, software deployment, endpoint management and administrator workflows.