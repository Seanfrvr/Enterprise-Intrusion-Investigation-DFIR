# Environment and Data Map

## Dataset provenance

| Attribute | Published information |
|---|---|
| Dataset | Boss of the SOC version 3 (BOTSv3) |
| Publisher | Splunk |
| Upstream repository | [splunk/botsv3](https://github.com/splunk/botsv3) |
| Published archive size | 320.1 MB |
| Distribution format | Pre-indexed Splunk dataset |
| Published MD5 | `d7ccca99a01cff070dff3c139cdc10eb` |
| Published index | `botsv3` |
| Licence | CC0 dedication, as stated by upstream |
| Local acquisition | Not yet recorded |
| Local integrity verification | Not yet performed |
| Local Splunk version | Not yet recorded |

The published MD5 is an upstream reference value, not a hash calculated from a locally acquired archive. Record the local file's checksum after download and compare it with the published value before installation.

## Installation notes

Follow the current instructions in the [upstream BOTSv3 repository](https://github.com/splunk/botsv3). The upstream README describes unpacking the pre-indexed dataset into the Splunk Enterprise apps directory and restarting Splunk. It also lists companion add-ons and versions used when the dataset was created.

Do not assume that a modern Splunk installation or current add-on versions will behave identically to the original environment. Record version differences and any field-extraction issues encountered.

## Initial validation searches

Run these searches only after the dataset is installed and the index is available.

### 1. Confirm index access and event volume

```spl
index=botsv3 earliest=0
| stats count AS event_count
```

### 2. Identify sourcetype coverage

```spl
| metadata type=sourcetypes index=botsv3
| convert ctime(firstTime) AS first_seen ctime(lastTime) AS last_seen
| table sourcetype totalCount first_seen last_seen
| sort - totalCount
```

### 3. Identify host and sourcetype distribution

```spl
| tstats count WHERE index=botsv3 BY host sourcetype
| sort - count
```

### 4. Establish event-time coverage

```spl
index=botsv3 earliest=0
| stats min(_time) AS first_event max(_time) AS last_event count
| convert ctime(first_event) ctime(last_event)
```

These are environment and inventory searches. They do not establish malicious activity.

## Published sourcetype families

The upstream README lists a broad set of telemetry, including:

| Source family | Published examples | Potential investigative value |
|---|---|---|
| Windows | `wineventlog`, `winhostmon`, `xmlwineventlog:microsoft-windows-sysmon/operational` | Authentication, host activity and process telemetry |
| Microsoft cloud | `ms:aad:audit`, `ms:aad:signin`, `ms:o365:management` | Identity, sign-in and SaaS administration |
| AWS | `aws:cloudtrail`, `aws:cloudwatch`, `aws:cloudwatch:guardduty`, `aws:s3:accesslogs` | Cloud control-plane and service activity |
| Network | `stream:dns`, `stream:http`, `stream:tcp`, `stream:smb`, `cisco:asa` | Name resolution, web, transport and network security |
| Endpoint / security products | `symantec:ep:behavior:file`, `symantec:ep:security:file`, `osquery:results` | Endpoint detections and host state |
| Linux / Unix | `linux_secure`, `linux_audit`, `bash_history`, `syslog` | Authentication, audit and command activity |

This is an upstream inventory, not confirmation that every source type is populated in the local installation. Confirm actual coverage with the inventory searches.

## Environment record

Complete this section during local setup.

| Field | Value |
|---|---|
| Acquisition date | Pending |
| Archive filename | Pending |
| Local archive size | Pending |
| Local MD5 | Pending |
| Local SHA-256 | Pending |
| Splunk Enterprise version | Pending |
| Operating system | Pending |
| Installed add-ons | Pending |
| Index visible | Pending |
| Event count | Pending |
| Earliest / latest event | Pending |
| Sourcetype inventory saved | Pending |
| Host inventory saved | Pending |

## References

- [Splunk BOTSv3 repository and installation instructions](https://github.com/splunk/botsv3)
- [Splunk: Boss of the SOC v3 dataset released](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html)
