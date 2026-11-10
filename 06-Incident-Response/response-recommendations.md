# Incident Response Recommendations

## Response principles

Response actions should be proportional to the confidence and potential impact of the finding. Preserve evidence before making changes where operationally safe, and coordinate disruptive actions with system owners.

## 1. Preparation

- Maintain an inventory of critical hosts, identities and business services.
- Centralise Windows, identity, endpoint, DNS, proxy and firewall telemetry.
- Protect log retention from local administrator tampering.
- Define escalation paths and emergency account procedures.
- Maintain tested backups and recovery procedures.

## 2. Identification and triage

- Validate the alert against original telemetry.
- Identify affected users, hosts, applications and data.
- Establish an initial timeline with time zones.
- Determine whether privileged identities or critical systems are involved.
- Record confidence, impact and immediate unknowns.

## 3. Containment

- Isolate affected endpoints when justified and operationally safe.
- Disable or restrict compromised accounts and revoke active sessions.
- Block confirmed malicious infrastructure through managed controls.
- Restrict exposed services and suspicious remote-access paths.
- Preserve volatile evidence where feasible before shutdown or isolation.

Containment should avoid destroying evidence or interrupting critical services without coordination.

## 4. Eradication

- Remove confirmed persistence mechanisms.
- Rebuild systems where integrity cannot be trusted.
- Patch exploited applications and exposed services.
- Rotate credentials and secrets that may have been exposed.
- Review privileged groups, service accounts, tokens and remote access.
- Validate that the initial access path has been closed.

## 5. Recovery

- Restore from known-good sources.
- Reintroduce systems in a controlled sequence.
- Increase monitoring on previously affected identities and hosts.
- Validate authentication, endpoint health and business functionality.
- Confirm logging and alerting are operating before closing the incident.

## 6. Lessons learned

- Identify telemetry gaps and improve collection.
- Convert validated behaviours into tested detections.
- Review access controls and administrative workflows.
- Update response playbooks and escalation criteria.
- Track remediation owners and due dates.

## Evidence preservation checklist

- Record incident identifier, analyst and timestamps.
- Preserve original logs and relevant endpoint artefacts.
- Record collection method, source and hash where appropriate.
- Maintain chain of custody where required.
- Keep investigative notes separate from assumptions and conclusions.