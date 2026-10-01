# Windows Service & Process Monitoring Agent

A host-based Blue Team security monitoring agent designed to monitor Windows processes and services, establish trusted baselines, detect suspicious changes, and generate security findings.

## Project Overview

The Windows Service & Process Monitoring Agent provides visibility into process and Windows service activity on a Windows endpoint.

The project combines process monitoring, service auditing, baseline comparison, behavioral detection, permission analysis, signature verification, real-time monitoring, and centralized detection.

The goal is to provide a lightweight security monitoring solution for identifying suspicious endpoint activity and configuration changes.

## Objectives

The primary objectives of the project are:

- Monitor active Windows processes.
- Collect process metadata.
- Analyze parent-child process relationships.
- Detect unauthorized or suspicious processes.
- Maintain a trusted process baseline.
- Detect newly introduced processes.
- Audit Windows services.
- Maintain a Windows service baseline.
- Detect service configuration changes.
- Audit startup services.
- Detect startup service changes.
- Analyze service permissions.
- Identify process injection behavioral indicators.
- Identify unsigned or high-risk process activity.
- Monitor process creation and termination in real time.
- Aggregate security findings through a central detection engine.

## Technology Stack

| Component | Technology |
|---|---|
| Operating System | Windows |
| Programming Language | Python |
| Process Monitoring | psutil |
| Windows Service Enumeration | PowerShell / WMI / CIM |
| Signature Verification | PowerShell Authenticode |
| Environment | Python Virtual Environment |
| Shell | Git Bash |

## Project Structure

```text
Windows-Service-Process-Monitor/
│
├── agent/
│   ├── process_monitor.py
│   ├── process_tree.py
│   ├── unauthorized_process.py
│   ├── baseline_manager.py
│   ├── new_process_detector.py
│   ├── service_audit.py
│   ├── service_baseline.py
│   ├── service_change_detector.py
│   ├── startup_audit.py
│   ├── startup_change_detector.py
│   ├── service_permission_audit.py
│   ├── process_injection_monitor.py
│   ├── unsigned_process_detector.py
│   ├── realtime_monitor.py
│   └── detection_engine.py
│
├── config/
│   ├── process_rules.json
│   ├── baseline.json
│   └── service_baseline.json
│
├── diagrams/
│   ├── architecture_diagram.png
│   └── workflow_diagram.png
│
├── logs/
├── reports/
├── screenshots/
├── tests/
├── TESTING.md
├── DETECTION_RULES.md
└── README.md