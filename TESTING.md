# Windows Service & Process Monitoring Agent
# Testing Documentation

## 1. Testing Overview

The Windows Service & Process Monitoring Agent was tested on a Windows host to verify its ability to monitor processes and Windows services, detect suspicious activity, identify configuration changes, and generate security findings.

The testing process covers:

- Process enumeration
- Process metadata collection
- Process tree analysis
- Unauthorized process detection
- Process baseline creation
- New process detection
- Windows service auditing
- Service baseline creation
- Service change detection
- Startup service auditing
- Startup service change detection
- Service permission auditing
- Process injection behavioral indicators
- Unsigned/high-risk process detection
- Real-time process monitoring
- Central detection engine

Testing was performed using Python, psutil, PowerShell/WMI/CIM, and Windows system processes and services.

---

## 2. Test Environment

| Component | Details |
|---|---|
| Operating System | Microsoft Windows |
| Programming Language | Python |
| Process Monitoring | psutil |
| Windows Service Enumeration | PowerShell / WMI / CIM |
| Signature Verification | PowerShell Authenticode |
| Virtual Environment | Python venv |
| Shell | Git Bash |
| Detection Type | Host-based Blue Team Monitoring |
| Monitoring Mode | On-demand and real-time |

---

## 3. Testing Methodology

Testing was performed using the following approach:

1. Execute each monitoring module independently.
2. Verify that the module starts without errors.
3. Verify that expected Windows process/service data is collected.
4. Test detection logic against the current host state.
5. Verify that suspicious or changed configurations generate findings.
6. Verify that clean configurations do not generate unnecessary alerts.
7. Test real-time process monitoring using a controlled process start and termination.
8. Execute the central detection engine to verify integration of individual detection modules.
9. Capture screenshots as evidence for important test cases.

---

# 4. Test Cases

## TC-01: Process Enumeration

### Objective
Verify that the agent can enumerate active Windows processes and collect process metadata.

### Module
`agent/process_monitor.py`

### Test Procedure

Run:

```bash
python agent/process_monitor.py