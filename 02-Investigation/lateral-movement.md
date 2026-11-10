# Lateral Movement

## Investigation question

Did an account or operator use one system to access another system, and what remote service or execution method was involved?

## Start with the destination

On the destination host, inspect successful logons:

- **4624:** successful logon. Review logon type, account, source address, authentication package and TargetLogonId.
- **4672:** special privileges assigned to a logon. Correlate using the logon identifier; it is not proof of malicious privilege use.
- **4688 / Sysmon 1:** process creation after the logon, if collection is enabled.

On the domain controller, use:

- **4768:** Kerberos TGT request.
- **4769:** Kerberos service-ticket request.
- **4776:** NTLM credential validation.

A 4769 event provides Kerberos context; it does not prove the destination server accepted a logon. Confirm access in the destination host's records.

## Useful pivots

1. Start from the destination's 4624 record.
2. Record account, source address, logon type, authentication package and TargetLogonId.
3. Correlate 4672 and later events on that destination using the Logon ID.
4. Check source-host telemetry for the initiating process and network connection.
5. Identify the service: SMB, RDP, WinRM, WMI, remote service creation or another mechanism.
6. Compare the account-to-host relationship with normal administration and service-account use.

## What would strengthen the conclusion?

- A successful destination logon from an unexpected source.
- A related remote service or protocol record.
- Process execution or file access tied to the same logon/session.
- A source-host process responsible for the connection.
- Activity inconsistent with the account owner's documented workflow.

A network logon alone does not identify the remote protocol or prove hands-on-keyboard activity. Record the exact evidence and leave the mechanism unresolved until it is established.
