# Security handling

## Repository policy

Do not commit passwords, API tokens, private keys, AWS secret access keys,
session tokens, connection strings or personal credentials. Lab data must be
reviewed before publication, even when it comes from a public training source.

## BOTSv3 CloudTrail fixture review

GitHub secret scanning identified 11 AWS temporary access key identifiers in
the original AWS CloudTrail fixture. The values were part of the public
BOTSv3-derived training records. An access key identifier is not the secret
access key or session token required to authenticate to AWS, but it is still
credential metadata and should not be needlessly republished.

The current version of
`09-BOTSv3-Investigation/data/fixtures/01-aws-recon-bstoll.jsonl` replaces
each distinct identifier with a stable label such as `REDACTED_AWS_KEY_01`.
This preserves the ability to group events that used the same identifier.
The local pipeline tests verify that the original identifier pattern is no
longer present in the current fixture.

## Git history and alert resolution

The sanitization commit changes the current file. It does not remove the
original values from earlier Git commits. The historical values also appear
in the upstream public training fixture. Review the corresponding GitHub
secret scanning alerts and confirm that each alert points to this known
training data before resolving it. If GitHub offers the `used in tests`
resolution reason, use it only for alerts that have been verified against
the upstream fixture.

If an alert identifies an actual credential belonging to an account you
control, revoke or rotate it with the account owner immediately. Removing a
value from the latest file does not invalidate a credential or erase Git
history. Do not attempt to rotate credentials belonging to the BOTSv3
training environment.

## Review before future commits

1. Inspect raw event exports for credential fields and personal information.
2. Redact secrets before adding files to Git.
3. Preserve event relationships with stable replacement labels where useful.
4. Record the transformation in the evidence log and provenance notes.
5. Run the fixture pipeline tests before publishing.
