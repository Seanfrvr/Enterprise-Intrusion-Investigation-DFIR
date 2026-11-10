# Dataset provenance and acquisition record

## Dataset reference

| Property | Value |
|---|---|
| Dataset | Splunk Boss of the SOC v3 (BOTSv3) |
| Official project | https://github.com/splunk/botsv3 |
| Historical archive size | Approximately 320.1 MB |
| Published archive MD5 | \`d7ccca99a01cff070dff3c139cdc10eb\` |
| Expected Splunk index | \`botsv3\` |
| Historical licence statement | CC0, as described by the upstream project |

The archive size and MD5 are upstream reference metadata. They are not
measurements from a local download in this workspace.

## Fixture source

The six JSONL files under \`data/fixtures/\` are selected event slices from the
public repository:

https://github.com/JacobRHess/splunk-bots-hunts

Its documentation identifies the scenarios as investigations based on
BOTSv3. The upstream Git blob SHA for each original fixture is retained below.

| Local fixture | Upstream source path | Original source blob SHA |
|---|---|---|
| \`01-aws-recon-bstoll.jsonl\` | \`scenarios/01-aws-recon-bstoll/fixtures/main.jsonl\` | \`a389d3641a1626504031bdbea345fb1faccad6b6\` |
| \`02-bstoll-l-endpoint.jsonl\` | \`scenarios/02-bstoll-l-endpoint/fixtures/main.jsonl\` | \`81711648ca3dbdd9c32d2dc2e67ff6f0e34a46e4\` |
| \`03-bstoll-coinhive-cryptojacking.jsonl\` | \`scenarios/03-bstoll-coinhive-cryptojacking/fixtures/main.jsonl\` | \`a15b0554556e8ff20da94239c6d86a4b2ad61f4c\` |
| \`04-fyodor-powershell-empire.jsonl\` | \`scenarios/04-fyodor-powershell-empire/fixtures/main.jsonl\` | \`b99680cba7caa4d885d959f425dbeaec1584a068\` |
| \`05-azure-ad-signin-anomaly.jsonl\` | \`scenarios/05-azure-ad-signin-anomaly/fixtures/main.jsonl\` | \`fe93d025a22a8261e377b7c73b7ca0646af4ac1c\` |
| \`06-o365-cloud-account-abuse.jsonl\` | \`scenarios/06-o365-cloud-account-abuse/fixtures/main.jsonl\` | \`d044d1ea6194a8b42eb53ccd296774b3dbae1a04\` |

These identifiers are Git blob SHAs for the upstream source files. They do
not describe the modified local fixture bytes.

## Local sanitization

GitHub secret scanning flagged AWS temporary access key identifiers in the
AWS CloudTrail fixture. The current committed version replaces each distinct
\`userIdentity.accessKeyId\` value with a stable label such as
\`REDACTED_AWS_KEY_01\`.

The replacement preserves event structure and makes it possible to group
records that used the same original identifier. It does not preserve the
credential identifier itself. No secret access key or session token is
intentionally included in the committed fixture.

The source blob SHA above points to the unmodified upstream file. The pipeline
calculates SHA-256 for the exact sanitized local bytes and records it in
\`output/fixture-integrity.json\`.

## Acquisition status

| Activity | Status |
|---|---|
| Official BOTSv3 project metadata reviewed | Complete |
| Six public BOTSv3-derived fixture extracts obtained | Complete |
| Upstream source paths and blob SHAs recorded | Complete |
| AWS temporary access key identifiers redacted in current fixture | Complete |
| Local SHA-256 generated for sanitized fixtures | Run pipeline |
| Full BOTSv3 archive downloaded and MD5 verified | Not performed |
| Full archive installed in Splunk | Not performed |
| Full-index searches and raw event review | Not performed |

The committed records are real records from a public BOTSv3-derived source,
with the stated AWS identifier redaction. They are selected extracts, not a
complete acquisition of the BOTSv3 archive.
