# Detection Engineering

## Detection lifecycle

A detection should begin with a specific behaviour and a defensible data requirement, not a list of suspicious executable names.

1. Define the threat behaviour and investigation question.
2. Identify the event sources and required fields.
3. Write the initial analytic.
4. Test against known benign and suspicious examples.
5. Measure false positives and data gaps.
6. Tune thresholds, exclusions and grouping.
7. Document ownership, severity and response guidance.
8. Review after changes to logging, infrastructure or attacker tradecraft.

## Detection specification template

| Field | Description |
|---|---|
| Detection name | Short, behaviour-focused title |
| Objective | Behaviour the analytic is intended to identify |
| Data sources | Required event providers, indexes and sourcetypes |
| Required fields | Fields used for filtering, grouping and context |
| Logic | SPL or platform-native analytic |
| ATT&CK mapping | Technique supported by the behaviour |
| Severity | Impact and likelihood rationale |
| False positives | Expected benign matches |
| Tuning | Approved exclusions and thresholds |
| Validation | Test data, simulation or historical event review |
| Response | Analyst triage and escalation steps |
| Limitations | Coverage gaps and known blind spots |

## Example detection concepts

### 1. Event-log clearing

**Signal:** Security log clear event or Windows Eventlog clear event.

**Triage:** Identify the actor, host, channel, process context and whether the action was part of authorised maintenance. Correlate with central log gaps and privileged activity.

### 2. Unusual PowerShell execution

**Signal:** PowerShell with suspicious argument patterns, unusual parent process, rare user/host combination or unexpected network activity.

**Triage:** Retrieve the full command line and script-block content where available. Validate signer, parent process, account role and follow-on activity.

### 3. Suspicious LSASS process access

**Signal:** A process accesses LSASS with an unusual access pattern.

**Triage:** Check process signer, hash, parent, user, access mask, EDR classification and whether a dump file was created. Exclude known security tooling only after validation.

## Validation status

No detection in this repository should be described as production-ready or tested until it has been executed against representative data and reviewed for both true and false positives.