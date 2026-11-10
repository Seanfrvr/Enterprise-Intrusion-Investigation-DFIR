#!/usr/bin/env bash
set -euo pipefail

URL="https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz"
EXPECTED_MD5="d7ccca99a01cff070dff3c139cdc10eb"
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="\${SCRIPT_DIR}/../data/raw"
ARCHIVE="\${DEST_DIR}/botsv3_data_set.tgz"

mkdir -p "$DEST_DIR"

if [[ -f "$ARCHIVE" ]]; then
  echo "Archive already exists: $ARCHIVE"
else
  echo "Downloading the official BOTSv3 archive..."
  if command -v curl >/dev/null 2>&1; then
    curl --fail --location --retry 3 --output "$ARCHIVE" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget --output-document="$ARCHIVE" "$URL"
  else
    echo "Install curl or wget and retry." >&2
    exit 1
  fi
fi

if command -v md5sum >/dev/null 2>&1; then
  ACTUAL_MD5="$(md5sum "$ARCHIVE" | awk '{print $1}')"
elif command -v md5 >/dev/null 2>&1; then
  ACTUAL_MD5="$(md5 -q "$ARCHIVE")"
else
  echo "Install md5sum or md5 to verify the archive." >&2
  exit 1
fi

echo "Expected MD5: $EXPECTED_MD5"
echo "Actual MD5:   $ACTUAL_MD5"

if [[ "$ACTUAL_MD5" != "$EXPECTED_MD5" ]]; then
  echo "Checksum mismatch. Do not extract or install this archive." >&2
  exit 1
fi

echo "Checksum verified."

if [[ $# -gt 0 ]]; then
  SPLUNK_HOME="$1"
  if [[ ! -d "$SPLUNK_HOME/etc/apps" ]]; then
    echo "Splunk apps directory not found: $SPLUNK_HOME/etc/apps" >&2
    exit 1
  fi
  echo "Extracting into $SPLUNK_HOME/etc/apps"
  tar -xzf "$ARCHIVE" -C "$SPLUNK_HOME/etc/apps"
  echo "Extraction complete. Restart Splunk and verify with:"
  echo 'index=botsv3 earliest=0 | stats count by sourcetype'
else
  echo "Archive verified and saved. To install, run:"
  echo "\"$0\" \"/path/to/SPLUNK_HOME\""
fi
