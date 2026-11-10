# Full BOTSv3 archive acquisition

The official Splunk project publishes the BOTSv3 archive as a 320.1 MB
pre-indexed Splunk dataset. Its published MD5 is
\`d7ccca99a01cff070dff3c139cdc10eb\`.

Official source:
https://github.com/splunk/botsv3

Direct archive:
https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz

## Download and verify

On macOS or Linux, run:

\`\`\`bash
bash scripts/acquire-botsv3.sh
\`\`\`

The script downloads the archive into \`data/raw/\` and verifies its MD5
before reporting success. It does not extract or install anything by default.

To install into an existing Splunk installation:

\`\`\`bash
bash scripts/acquire-botsv3.sh "/path/to/SPLUNK_HOME"
\`\`\`

The script checks the archive checksum before extracting it into
\`$SPLUNK_HOME/etc/apps\`. Restart Splunk after extraction.

Then verify the index:

\`\`\`spl
index=botsv3 earliest=0
| stats count by sourcetype
| sort -count
\`\`\`

The expected index name and installation procedure are documented by Splunk.
The original dataset was built around Splunk Enterprise 7.1.7 and a set of
historical add-ons. Current Splunk and add-on compatibility may differ.
Review the official requirements before installing old add-ons into a
production environment.

## Important

The full archive is not committed to this Git repository. It is large,
pre-indexed data and should remain in local lab storage. Do not upload it to
GitHub.

A successful download and matching MD5 establish archive integrity. They do
not establish that Splunk imported the dataset correctly. Confirm the index,
event count, sourcetypes and representative raw events after installation.
