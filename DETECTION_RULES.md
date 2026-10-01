# Windows Service & Process Monitoring Agent
# Detection Rules Documentation

## 1. Purpose

This document describes the detection rules implemented in the Windows Service & Process Monitoring Agent.

The rules are designed to identify suspicious processes, service configurations, startup persistence, permission risks, and other host-based indicators relevant to Windows security monitoring.

---

## 2. Severity Levels

| Severity | Meaning |
|---|---|
| CRITICAL | Strong indicator of potentially malicious activity requiring immediate investigation |
| HIGH | Significant suspicious activity requiring investigation |
| MEDIUM | Suspicious or anomalous activity requiring validation |
| REVIEW | Configuration requiring security review |
| LOW | Low-risk observation |
| INFO | Informational security context |

---

## 3. Unauthorized Process Detection

### Rule Name
Unauthorized / Unknown Process Detection

### Module
`agent/unauthorized_process.py`

### Logic

The detector compares running processes against configured process rules.

The following conditions are evaluated:

1. Blacklisted process name
2. Suspicious executable directory
3. Process not present in the configured whitelist

### Severity

| Condition | Severity |
|---|---|
| Blacklisted process | CRITICAL |
| Suspicious executable path | HIGH |
| Unknown process | MEDIUM |

### Configuration

Rules are stored in:

```text
config/process_rules.json