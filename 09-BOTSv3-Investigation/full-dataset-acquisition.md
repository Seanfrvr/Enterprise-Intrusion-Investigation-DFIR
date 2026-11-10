# Full BOTSv3 archive acquisition

The official Splunk project publishes the historical BOTSv3 pre-indexed dataset.
The upstream reference size is approximately 320.1 MB and the published MD5 is
`d7ccca99a01cff070dff3c139cdc10eb`. These are reference values, not a local
download result.

Official project: https://github.com/splunk/botsv3

Direct archive: https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz

## Download and verify

From the BOTSv3 investigation directory on macOS or Linux:

```bash
bash scripts/acquire-botsv3.sh
```

The script saves the archive under `data/raw/`. It verifies the published MD5
before reporting success. A failed or partial download is not treated as valid.

To extract the verified archive into a dedicated lab Splunk installation:

```bash
bash scripts/acquire-botsv3.sh "/path/to/SPLUNK_HOME"
```

Restart Splunk and verify the index:

```spl
index=botsv3 earliest=0
| stats count by sourcetype
| sort -count
```

## Compatibility and safety

The original dataset and add-ons target a historical Splunk environment.
Check the official project instructions and add-on compatibility before use.
Use a disposable lab instance. Do not install the old dataset or its add-ons
into a production Splunk deployment.

The archive is intentionally excluded from Git. Keep it in local lab storage.
A matching MD5 verifies the downloaded archive against the published reference.
It does not prove successful Splunk indexing. Confirm event counts, sourcetypes,
time coverage and representative raw events after installation.

## Acquisition record

Record the download date, source URL, local file size, expected and actual MD5,
Splunk version, installation result, index count and sourcetype inventory in
the case notes. Do not write a successful acquisition status until those
checks have been performed.
