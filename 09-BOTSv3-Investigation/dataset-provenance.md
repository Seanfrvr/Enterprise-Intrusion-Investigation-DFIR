# Dataset provenance and acquisition record

## Dataset reference

- Dataset: Splunk Boss of the SOC v3 (BOTSv3)
- Official project: https://github.com/splunk/botsv3
- Historical published archive size: approximately 320.1 MB
- Historical published MD5: `d7ccca99a01cff070dff3c139cdc10eb`
- Expected Splunk index: `botsv3`
- Upstream project historically describes the dataset as CC0.

The archive size and MD5 above are upstream-published reference metadata. They
are **not** measurements from a local acquisition in this workspace.

## Fixture source and attribution

The six JSONL files under `data/fixtures/` are selected event slices copied
without content modification from the public repository
https://github.com/JacobRHess/splunk-bots-hunts. Its README describes the
scenarios as investigations of BOTSv3. The source blob SHA is recorded for
each file so the copied content can be traced to a specific upstream Git blob.

| Local fixture | Upstream source path | Source blob SHA |
|---|---|---|
| `01-aws-recon-bstoll.jsonl` | `scenarios/01-aws-recon-bstoll/fixtures/main.jsonl` | `a389d3641a1626504031bdbea345fb1faccad6b6` |
| `02-bstoll-l-endpoint.jsonl` | `scenarios/02-bstoll-l-endpoint/fixtures/main.jsonl` | `81711648ca3dbdd9c32d2dc2e67ff6f0e34a46e4` |
| `03-bstoll-coinhive-cryptojacking.jsonl` | `scenarios/03-bstoll-coinhive-cryptojacking/fixtures/main.jsonl` | `a15b0554556e8ff20da94239c6d86a4b2ad61f4c` |
| `04-fyodor-powershell-empire.jsonl` | `scenarios/04-fyodor-powershell-empire/fixtures/main.jsonl` | `b99680cba7caa4d885d959f425dbeaec1584a068` |
| `05-azure-ad-signin-anomaly.jsonl` | `scenarios/05-azure-ad-signin-anomaly/fixtures/main.jsonl` | `fe93d025a22a8261e377b7c73b7ca0646af4ac1c` |
| `06-o365-cloud-account-abuse.jsonl` | `scenarios/06-o365-cloud-account-abuse/fixtures/main.jsonl` | `d044d1ea6194a8b42eb53ccd296774b3dbae1a04` |

These source identifiers are Git blob SHAs, not SHA-256 hashes of the file
contents. The local pipeline calculates SHA-256 for the exact committed bytes
and writes the values to `output/fixture-integrity.json`.

## Acquisition status

| Item | Status |
|---|---|
| Official BOTSv3 project metadata reviewed | Complete |
| Six public BOTSv3-derived fixture extracts copied and source blob IDs recorded | Complete |
| Local fixture SHA-256 calculated by pipeline | Run pipeline |
| Full BOTSv3 archive downloaded and MD5 verified locally | Not performed |
| Full archive installed in Splunk | Not performed |
| Full-index searches and raw-event review | Not performed |

The committed extracts are real records from the upstream public fixture
repository, but this is not a complete acquisition of BOTSv3. No claim is made
that the full archive was downloaded or queried.
