# Detection Engineering Notes

A hunt query is not automatically a detection. A detection needs a defined data source, stable logic, known benign matches, tuning and an analyst action.

## From hunt to detection

Before promoting a search, answer:

1. **What behaviour matters?** Describe the activity, not just the executable name.
2. **Which telemetry proves it?** Name the provider, event ID and required fields.
3. **What context changes the risk?** Account privilege, host role, parent process, destination or sequence.
4. **What normally causes this event?** Check IT administration, endpoint security, backup and deployment activity.
5. **What should the analyst do?** Give a concrete first pivot and escalation condition.

## Example: unusual process access to LSASS

| Element | Specification |
|---|---|
| Signal | Sysmon Event ID 10 where TargetImage resolves to LSASS |
| Required context | SourceImage, source PID/GUID, user, GrantedAccess, CallTrace, host |
| Higher-risk context | Unsigned or unusual executable, writable path, unexpected parent or rare host/account combination |
| Common benign causes | EDR, antivirus, diagnostic and credential-management software |
| First triage step | Verify source process signature/hash and compare with approved endpoint tooling |
| Escalation | Suspicious process lineage, dump artefact, related credential-use activity or EDR confirmation |
| Limitation | Event ID 10 alone does not prove credential dumping |

This is a detection concept, not a tested analytic. A production rule needs a validated access-mask strategy, known-good baselines and testing against both benign and suspicious examples.

## Validation record

For each detection that is actually tested, retain:

- Query version and date.
- Index, sourcetype and time range.
- Event fields confirmed from raw records.
- Test data source and test method.
- Positive and negative test results.
- False positives and tuning changes.
- Known telemetry gaps.
- Screenshot or event references that another analyst can review.

Do not call a rule tested because it parses, returns events or looks plausible. Record what was tested and what the results demonstrated.

**Repository status:** this folder contains detection-design notes. No rule here is claimed to be production-ready.
