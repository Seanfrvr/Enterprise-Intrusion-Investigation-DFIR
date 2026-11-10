# Executive Summary
### Northstar Logistics | Reconstructed Case Exercise

## Assessment

The scenario describes a sequence of events involving the privileged service identity `svc-backup`: authentication from an unexpected workstation, WMI-associated process execution on a file server, PowerShell discovery, unusual access to LSASS, inter-host authentication, finance-file staging and outbound network activity.

Taken together, these behaviours warrant high-priority investigation **within the scenario**. They do not establish a confirmed compromise or prove that credentials were extracted or data left the environment.

## Main findings in the scenario

1. **Identity:** `svc-backup` is described as authenticating from NS-WS044, outside its stated service-account baseline.
2. **Execution:** NS-FS01 is described as recording `WmiPrvSE.exe` spawning command and PowerShell processes. The remote client is not established.
3. **Discovery:** PowerShell records are described as containing host, domain and service enumeration.
4. **Credential access:** an executable from a temporary path is described as accessing LSASS. Credential extraction is not established.
5. **Inter-host access:** NS-WEB01 is described as recording a network logon from NS-FS01. The remote service is unknown.
6. **File activity:** finance documents are described as accessed and copied to a local staging path. External transfer is not established.
7. **Network:** outbound TCP activity is described to `198.51.100.27:8443`. This is a documentation-only address; connection success and payload are unavailable.

## Provisional risk

**Working severity: High, pending validation.** The scenario combines a privileged identity, multiple hosts, LSASS access and finance-data staging. This is a prioritisation judgement, not a confirmed impact rating.

- Confidentiality: potentially high; external disclosure is unproven.
- Integrity: unknown; no verified unauthorised modification is described.
- Availability: no confirmed disruption.
- Scope: several hosts appear in the scenario; wider scope is unknown.

## Priority investigation steps

1. Validate the service-account owner, approved source hosts and scheduled backup activity.
2. Correlate the destination host's Event ID 4624 with domain-controller authentication context.
3. Reconstruct process ancestry and identify the WMI client using WMI-Activity and network telemetry.
4. Preserve and examine the executable associated with LSASS access; review EDR and file artefacts.
5. Identify the remote service used for inter-host access.
6. Determine which finance files were accessed, what process staged them and whether hashes match source files.
7. Establish the outbound connection disposition, process, DNS context and bytes transferred.
8. Expand the review to persistence, other privileged identities and additional hosts.

## Provenance and confidence

This is a reconstructed portfolio exercise. Its narrative and timestamps are illustrative. No primary event exports, original screenshots, reproducible Splunk result sets or hashes are retained, and the searches have not been validated against a dataset in this project.

The scenario does not establish initial access, credential theft, persistence, successful command-and-control, exfiltration or actor attribution. The findings must be rewritten if later source evidence differs from the scenario.
