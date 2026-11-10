# Initial Access

## Objective

Determine how an unauthorised actor may have obtained an initial foothold, which identity or service was affected, and what evidence supports the suspected access path.

## Investigative questions

- Was access obtained through a remote service, exposed application, valid account or another entry point?
- Which account, source address and target system were involved?
- Was there an unusual password reset, authentication pattern or account recovery event?
- Did a successful logon follow repeated failures or a suspicious identity-management event?
- What activity occurred immediately after the suspected initial access?

## Relevant telemetry

| Source | Useful evidence |
|---|---|
| Windows Security | 4624 successful logon, 4625 failed logon, 4720 user created, 4723/4724 password change/reset attempts, 4732 group membership change |
| Identity provider | Sign-in risk, MFA outcome, password reset and session details |
| Application logs | Authentication, administrative actions and request source |
| VPN / firewall | Remote source, destination, session time and connection outcome |
| EDR / Sysmon | Process activity following authentication |

Event IDs and field availability vary by audit policy and platform. Confirm the event provider and schema before relying on a field.

## Analysis method

1. Establish the earliest credible suspicious event and preserve the original time zone.
2. Identify the account, source system, destination and authentication method.
3. Compare the event with the account's normal activity and expected administrative workflow.
4. Review preceding failures, password or MFA changes, new sessions and privilege changes.
5. Pivot from the authentication event to process execution and network activity on the destination host.
6. Record alternative explanations, such as approved IT support or automated identity-management activity.

## Detection considerations

Prioritise identity events that combine unusual source context with a consequential action: a new privileged account, an unexpected password reset, a risky sign-in followed by administrative activity, or access outside the account's normal pattern.

## Conclusion standard

A successful logon establishes that authentication succeeded; it does not alone prove compromise. Attribute malicious access only when identity, source, timing and follow-on activity provide sufficient corroboration.