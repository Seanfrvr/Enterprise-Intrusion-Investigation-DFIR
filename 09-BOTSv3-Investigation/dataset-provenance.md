# Dataset Provenance and Acquisition Record

## Upstream reference

- Dataset: Boss of the SOC version 3 (BOTSv3)
- Maintainer: Splunk
- Repository: https://github.com/splunk/botsv3
- Published format: pre-indexed Splunk dataset
- Published archive size: 320.1 MB
- Published MD5 reference: `d7ccca99a01cff070dff3c139cdc10eb`
- Published search index: `botsv3`
- Licence: CC0 dedication, as stated by the upstream repository

The values above describe the upstream publication. They are not evidence that this project has downloaded, installed or verified a local copy.

## Acquisition record

| Field | Recorded value |
|---|---|
| Acquisition date/time (UTC) | Not acquired in this work session |
| Download URL | https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz |
| Local filename | Pending |
| Local file size | Pending |
| Published MD5 comparison | Pending |
| Locally calculated MD5 | Pending |
| Locally calculated SHA-256 | Pending |
| Storage location | Pending |
| Splunk version | Pending |
| Installation path | Pending |
| Index verification | Pending |

## Integrity procedure

After downloading the archive, calculate both MD5 (for comparison with the publisher's historical reference) and SHA-256 (for this project's evidence-integrity record).

**PowerShell**
```powershell
Get-FileHash .\botsv3_data_set.tgz -Algorithm MD5
Get-FileHash .\botsv3_data_set.tgz -Algorithm SHA256
```

**Linux**
```bash
md5sum botsv3_data_set.tgz
sha256sum botsv3_data_set.tgz
```

Record the command output exactly. Do not copy the published MD5 into the local hash field.

## Compatibility considerations

The upstream installation documentation lists Splunk Enterprise 7.1.7 and specific historical add-on versions used when the dataset was assembled. A newer Splunk installation may require compatibility checks and may produce different field extractions. Record the actual versions used and validate the index and source schemas after installation.

## Provenance statement for the portfolio

Use this statement until local acquisition and validation have been completed:

> The investigation plan is based on Splunk's publicly documented BOTSv3 dataset. Local acquisition, checksum verification, installation and event-level analysis have not yet been completed. All searches in this repository are prepared hunt logic, not reported dataset findings.
