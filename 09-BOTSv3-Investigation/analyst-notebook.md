# Analyst Investigation Notebook

This document is the working record for the BOTSv3 investigation. It is designed to capture decisions and pivots as they happen, not to manufacture a completed incident narrative in advance.

## Investigation identity

| Field | Value |
|---|---|
| Case ID | BOTSV3-01 |
| Dataset | Splunk Boss of the SOC v3 |
| Index | `botsv3` |
| Analyst | Project author |
| Investigation start | Pending local execution |
| Splunk version | Pending |
| Dataset archive checksum | Pending local verification |
| Scope | To be set after source inventory |

## Initial questions

The investigation begins with questions, not assumed answers:

1. Which source families and entities are represented in this dataset installation?
2. What suspicious or high-impact activity is visible in the available cloud, identity, endpoint and network records?
3. Can any activity be reconstructed across multiple sources using stable identifiers?
4. Which explanations are supported, contradicted or still unresolved?
5. Can a detection be written that identifies the behaviour without alerting indiscriminately on normal administration?

## Decision log

| Decision ID | Date (UTC) | Question / decision | Reason | Effect on investigation |
|---|---|---|---|---|
| D-001 | Pending | Select investigation thread after inventory | Avoid preselecting an attack narrative | Pending |

## Hypothesis register

| Hypothesis ID | Hypothesis | Required telemetry | Evidence for | Evidence against | Status |
|---|---|---|---|---|---|
| HT-01 | A cloud principal performed activity outside its expected role or pattern | CloudTrail; identity/role context; related service logs | Pending | Pending | Not tested |
| HT-02 | An identity event is anomalous in its user, application, device or source context | AAD sign-in and audit; O365 activity | Pending | Pending | Not tested |
| HT-03 | Endpoint process activity indicates execution requiring investigation | Sysmon / Windows event records; host context | Pending | Pending | Not tested |
| HT-04 | Network activity can be linked to a specific host or process and merits investigation | DNS, HTTP, TCP, endpoint telemetry | Pending | Pending | Not tested |

Hypotheses are candidate questions, not findings. Retire or rewrite them when source coverage does not support a meaningful test.

## Event analysis worksheet

Create one worksheet per material event or tightly related event group.

### Event group: [ID]

- **Question being tested:**
- **Search ID / Hunt ID:**
- **Exact SPL:**
- **Time range and timezone:**
- **Result count:**
- **Source / sourcetype:**
- **Host / principal / resource:**
- **Event timestamp:**
- **Stable identifiers:**
- **Raw event reference:**
- **Direct observation:**
- **Correlation to other evidence IDs:**
- **Analyst assessment:**
- **Alternative explanation:**
- **Confidence and rationale:**
- **Next pivot:**
- **Disposition:** supported / rejected / unresolved

## Timeline worksheet

| Time (UTC) | Evidence ID | Source | Entity | Event description (factual) | Relationship / confidence |
|---|---|---|---|---|---|
| Pending | Pending | Pending | Pending | Pending | Pending |

Normalize timestamps to UTC only after recording the original timestamp and timezone assumption. Preserve original values in the underlying export.

## Finding format

A final finding should be concise and defensible:

**Finding title**  
**Severity:** informational / low / medium / high / critical (with rationale)  
**Confidence:** low / moderate / high  
**Evidence:** exact evidence IDs  
**Observation:** what the records directly show  
**Assessment:** why the activity matters  
**Scope:** affected entities and known limits  
**Alternative explanations:** credible benign causes  
**Impact:** confirmed impact versus potential impact  
**ATT&CK mapping:** only behaviour supported by evidence  
**Recommended action:** proportionate and evidence-based  
**Open questions:** what remains unresolved

## Final report gate

Do not write a definitive incident conclusion until:
- The dataset acquisition and integrity details are recorded.
- Relevant source coverage and time range are known.
- Material events are preserved and referenced.
- The event sequence is reproducible.
- Conflicting and benign explanations are addressed.
- The scope and limitations are explicit.
- Any detection claims are backed by executed tests.

The final report may conclude that a hypothesis is unresolved. An evidence-based unresolved conclusion is stronger than an unsupported attack narrative.
