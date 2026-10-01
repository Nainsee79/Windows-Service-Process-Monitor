# Windows Service & Process Monitoring Agent

## Final Project Report

---

## 1. Project Title

**Windows Service & Process Monitoring Agent**

---

## 2. Abstract

The Windows Service & Process Monitoring Agent is a host-based Blue Team security monitoring solution designed to provide visibility into Windows processes and services.

The project monitors running processes, analyzes parent-child relationships, maintains process and service baselines, detects unauthorized and newly introduced processes, audits Windows services and startup services, analyzes service permissions, identifies process injection behavioral indicators, performs Authenticode signature checks, and provides real-time process monitoring.

A central detection engine integrates multiple detection modules and provides a unified security finding and risk assessment view.

The project demonstrates practical endpoint monitoring and detection techniques that can support security analysts during Windows host investigations.

---

## 3. Problem Statement

Windows endpoints continuously execute processes and services that may change because of legitimate software activity, system updates, administrative actions, or malicious activity.

Security monitoring becomes difficult when unexpected processes, modified services, startup persistence, or suspicious executable locations are not identified quickly.

The purpose of this project is to develop a lightweight host-based monitoring agent capable of identifying suspicious Windows process and service activity through rule-based detection, baseline comparison, behavioral indicators, and real-time monitoring.

---

## 4. Project Objectives

The main objectives are:

- Monitor active Windows processes.
- Collect detailed process metadata.
- Analyze parent-child process relationships.
- Detect unauthorized and suspicious processes.
- Create and maintain a trusted process baseline.
- Detect newly introduced processes.
- Enumerate and audit Windows services.
- Create a Windows service baseline.
- Detect service configuration changes.
- Monitor startup services.
- Detect startup service changes.
- Analyze service permissions.
- Identify process injection behavioral indicators.
- Identify unsigned or high-risk process activity.
- Monitor process creation and termination in real time.
- Centralize detection findings through a detection engine.
- Provide evidence suitable for Blue Team investigation and reporting.

---

## 5. Scope

The project focuses on host-based monitoring of Windows processes and services.

### In Scope

- Process monitoring
- Process metadata collection
- Process tree analysis
- Unauthorized process detection
- Process baseline comparison
- New process detection
- Windows service auditing
- Service baseline comparison
- Service change detection
- Startup service monitoring
- Startup service change detection
- Service permission auditing
- Process injection behavioral indicators
- Authenticode signature analysis
- Real-time process monitoring
- Central detection and risk aggregation

### Out of Scope

- Full enterprise EDR functionality
- Advanced memory forensics
- Confirmed process injection analysis
- Network traffic monitoring
- Enterprise-wide SIEM deployment
- Automated malware removal
- Automated endpoint isolation

---

## 6. Technology Stack

| Component | Technology |
|---|---|
| Operating System | Microsoft Windows |
| Programming Language | Python |
| Process Monitoring | psutil |
| Windows Services | PowerShell / WMI / CIM |
| Signature Verification | PowerShell Authenticode |
| Environment | Python Virtual Environment |
| Shell | Git Bash |

---

## 7. System Architecture

The system consists of a Windows host, process monitoring layer, service monitoring layer, central detection engine, and output/evidence layer.

The architecture is represented in:

```text
diagrams/architecture_diagram.png