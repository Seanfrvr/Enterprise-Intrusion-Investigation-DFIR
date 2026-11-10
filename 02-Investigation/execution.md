# Process Execution

## Start with the process event

For Sysmon Event ID 1 or Security Event ID 4688, capture:

- Host and event timestamp.
- User and logon context.
- Image path and complete command line.
- Parent image and parent command line.
- Process ID and, for Sysmon, ProcessGuid / ParentProcessGuid.
- Hash and signature, where available.

## Investigation pivots

1. **Parent process:** is the parent expected for this application and host role?
2. **Execution path:** is the binary in a protected application directory or a user-writable location?
3. **Command line:** are there unusual arguments, encoded content, remote URLs or unexpected file paths?
4. **Identity:** is the account expected to run this process on this host?
5. **Follow-on activity:** did it create files, change registry keys, spawn children, access LSASS or make network connections?
6. **Prevalence:** does the same binary/hash/command appear on other systems?

Sysmon ProcessGuid is preferable to PID alone for process correlation because PIDs can be reused. Confirm which fields your event format actually extracts.

## Interpretation

PowerShell, cmd.exe, WMI and other administration tools are common in legitimate environments. Their presence alone is not a finding. A process-creation event establishes that process creation was recorded; it does not prove every command completed successfully.

## Record the result

Keep the raw event reference, query, time range, process tree, relevant file/network pivots, benign explanation considered and unresolved questions. Avoid labelling a process malicious based only on its name.
