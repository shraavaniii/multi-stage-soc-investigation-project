# Multi-Stage SOC Investigation

A hands-on Security Operations Center (SOC) investigation project built in a controlled lab environment using **Windows 11, Sysmon, Splunk Universal Forwarder, and Splunk Enterprise**.

The project focuses on investigating suspicious Windows activity, correlating endpoint telemetry, performing IOC pivots, mapping activity to MITRE ATT&CK, and documenting investigation decisions.

---

## 🎯 Project Objective

The objective of this project is to simulate real-world SOC investigation workflows:

* Monitor Windows endpoint activity
* Collect Sysmon telemetry
* Forward logs to Splunk
* Investigate suspicious process execution
* Analyze parent-child process relationships
* Perform IOC and hash pivots
* Correlate process and network telemetry
* Map observed behavior to MITRE ATT&CK
* Classify activity as suspicious, benign, or requiring escalation
* Document investigation findings

---

## 🏗️ Lab Architecture

```text
┌──────────────────────┐
│     Windows 11       │
│      SHRAVANI        │
│                      │
│       Sysmon         │
└──────────┬───────────┘
           │
           │ Windows Event Logs
           ▼
┌──────────────────────┐
│ Splunk Universal     │
│ Forwarder            │
└──────────┬───────────┘
           │
           │ Forwarded Telemetry
           ▼
┌──────────────────────┐
│   Ubuntu Server VM   │
│     SOC-Splunk       │
│                      │
│  Splunk Enterprise   │
└──────────┬───────────┘
           │
           │ SPL Queries
           ▼
┌──────────────────────┐
│     Splunk Web       │
│                      │
│    SOC Analyst       │
└──────────────────────┘
```

Detailed architecture documentation:

➡️ [`lab/architecture.md`](lab/architecture.md)

---

## 🔍 Investigations

| Investigation    | Topic                            | Status    |
| ---------------- | -------------------------------- | --------- |
| Investigation 01 | Suspicious PowerShell Execution  | Completed |
| Investigation 02 | Suspicious `mshta.exe` Execution | Completed |

---

### Investigation 01 — Suspicious PowerShell Execution

**Date:** August 26, 2026

Investigation of a suspicious PowerShell process launched through `cmd.exe`.

The investigation covered:

* Process creation telemetry
* Parent-child process relationship
* Hidden PowerShell execution
* Base64 encoded command
* Command-line analysis
* PowerShell decoding
* MITRE ATT&CK mapping
* Final classification

**Observed behavior:**

```text
cmd.exe
   │
   └── powershell.exe
          │
          └── Encoded PowerShell command
```

The decoded command created a harmless marker file:

```text
C:\Users\Public\soclab_marker.txt
```

**Final classification:** Controlled Simulation

➡️ [`View Investigation 01`](investigations/investigation-01-powershell/README.md)

---

### Investigation 02 — Suspicious `mshta.exe` Execution

**Date:** September 17, 2026

Investigation of `mshta.exe` execution using a controlled benign HTA test file.

The investigation covered:

* Sysmon Event ID 1 process creation
* Sysmon Event ID 5 process termination
* Parent-child process analysis
* HTA file IOC pivot
* SHA256 hash pivot
* Network connection check
* File creation check
* Timeline correlation
* MITRE ATT&CK mapping

**Observed process relationships:**

```text
cmd.exe
   │
   └── mshta.exe
```

and

```text
powershell.exe
   │
   └── mshta.exe
```

The test used:

```text
C:\Users\Public\soclab_test.hta
```

No Sysmon Event ID 3 network connection associated with `mshta.exe` was observed in the available telemetry.

No Sysmon Event ID 11 file creation attributed to `mshta.exe` was observed in the available telemetry.

**Final classification:** Controlled / Benign Lab Activity

➡️ [`View Investigation 02`](investigations/investigation-02-mshta/README.md)

---

## 🧪 Investigation Workflow

The investigations follow a simplified SOC workflow:

```text
Alert / Suspicious Activity
          │
          ▼
      Triage
          │
          ▼
   Process Analysis
          │
          ▼
 Parent-Child Correlation
          │
          ▼
      IOC Pivot
          │
          ▼
 Network / File Checks
          │
          ▼
 MITRE ATT&CK Mapping
          │
          ▼
 Classification
          │
          ▼
 Escalation Decision
          │
          ▼
 Investigation Report
```

---

## 📊 Sysmon Telemetry Used

| Event ID    | Purpose             |
| ----------- | ------------------- |
| Event ID 1  | Process Creation    |
| Event ID 3  | Network Connection  |
| Event ID 5  | Process Termination |
| Event ID 11 | File Create         |

These events were used to correlate endpoint activity during investigations.

---

## 🛠️ Technologies & Tools

### Endpoint

* Windows 11
* Sysmon

### Log Collection

* Splunk Universal Forwarder

### SIEM

* Splunk Enterprise
* Splunk Web
* Splunk Search Processing Language (SPL)

### Investigation

* MITRE ATT&CK
* IOC analysis
* Hash pivoting
* Process tree analysis
* Timeline correlation

### Virtualization

* VirtualBox
* Ubuntu Server

---

## 🔎 Key Investigation Techniques

### Process Analysis

Analyzing:

* Process image
* Process ID
* Parent Process ID
* Parent image
* User
* Integrity level
* Command line

## IOC Pivoting

Investigating indicators such as:

* File paths
* Process names
* SHA256 hashes
* Command-line values

## Timeline Analysis

Correlating:

* Process creation
* Process termination
* Network activity
* File creation

to understand the sequence of events.

## 🗺️ MITRE ATT&CK Mapping

Observed behaviors are mapped to relevant MITRE ATT&CK techniques to provide standardized context.

---

## 📁 Repository Structure

```text
multi-stage-soc-investigation-project/
│
├── README.md
├── portfolio-logo(final).jpg
│
├── investigations/
│   │
│   ├── investigation-01-powershell/
│   │   ├── README.md
│   │   └── screenshots/
│   │       ├── 01-search-results.png
│   │       ├── 02-process-creation.png
│   │       └── 03-command-line.png
│   │
│   └── investigation-02-mshta/
│       ├── README.md
│       └── screenshots/
│           ├── 01-process-creation.png
│           ├── 02-raw-event.png
│           ├── 03-timeline.png
│           ├── 04-network-check.png
│           ├── 05-file-creation-check.png
│           └── 06-hash-pivot.png
│
└── lab/
    └── architecture.md
```

---

## 🧠 Skills Demonstrated

* SOC alert triage
* Windows security monitoring
* Sysmon log analysis
* Splunk investigation
* Basic SPL querying
* Process tree analysis
* Parent-child process correlation
* PowerShell investigation
* LOLBin analysis
* IOC pivoting
* Hash analysis
* Timeline correlation
* Network telemetry analysis
* MITRE ATT&CK mapping
* Security investigation documentation
* Incident classification
* Escalation decision-making

---

## 📌 Project Scope

The project currently focuses on:

* Alert Triage
* PowerShell investigation
* LOLBin investigation
* Network correlation and C2-related analysis
* IOC pivoting
* MITRE ATT&CK mapping
* Investigation reporting
* Escalation decisions

The investigations are performed in a controlled laboratory environment for learning and security analysis.

---

## ⚠️ Disclaimer

This project was performed in a controlled lab environment using intentionally generated benign activity.

The observed commands, files, and executions were created for security monitoring and investigation practice.

No unauthorized systems or real-world targets were involved.

---

## 👩‍💻 Analyst

**Shravani Achal Hendre**

Final-Year B.Tech Information Technology Student

### Focus Areas

* Cybersecurity
* Security Operations
* Cloud Security

---

⭐ This repository documents the practical SOC investigation work, evidence, analysis, and methodology developed throughout the project.

