# SOC Lab Architecture

## 🏗️ Environment Overview

This project uses a controlled SOC laboratory environment to collect and investigate Windows endpoint telemetry.

The main components are:

* Windows 11 endpoint
* Sysmon
* Splunk Universal Forwarder
* Ubuntu Server
* Splunk Enterprise
* Splunk Web

---

## 🔄 Data Flow

```text
Windows 11 Endpoint
       │
       │ Sysmon Telemetry
       ▼
     Sysmon
       │
       │ Windows Event Logs
       ▼
Splunk Universal Forwarder
       │
       │ Forwarded Logs
       ▼
Ubuntu Server
SOC-Splunk
       │
       │
       ▼
Splunk Enterprise
       │
       │ SPL Queries
       ▼
Splunk Web
       │
       ▼
SOC Analyst
```

---

## 🖥️ Windows Endpoint

**Hostname:**

```text
SHRAVANI
```

The Windows endpoint generates security telemetry through Sysmon.

---

## 🔍 Sysmon

Sysmon provides detailed Windows system activity used during the investigations.

### Event IDs Used

| Event ID | Description         | Investigation Use                 |
| -------- | ------------------- | --------------------------------- |
| 1        | Process Creation    | Process and command-line analysis |
| 3        | Network Connection  | Network activity checks           |
| 5        | Process Termination | Process timeline correlation      |
| 11       | File Create         | File creation checks              |

---

## 📡 Splunk Universal Forwarder

The Splunk Universal Forwarder runs on the Windows endpoint.

Its role is to collect and forward Windows telemetry to the Splunk Enterprise server.

```text
Windows / Sysmon
       │
       ▼
Universal Forwarder
       │
       ▼
Splunk Enterprise
```

---

## 🗄️ Splunk Enterprise

Splunk Enterprise runs on an Ubuntu Server virtual machine.

**VM Name:**

```text
SOC-Splunk
```

Splunk Enterprise receives the forwarded telemetry and makes it available for investigation.

---

## 🔎 Splunk Web

Splunk Web provides the investigation interface used by the analyst.

The analyst uses SPL queries to:

* Search events
* Filter telemetry
* Investigate processes
* Analyze command lines
* Pivot on IOCs
* Correlate events
* Build timelines

---

## 🧑‍💻 Analyst Workflow

```text
Telemetry
   │
   ▼
Alert / Suspicious Activity
   │
   ▼
Initial Triage
   │
   ▼
Process Analysis
   │
   ▼
IOC Pivoting
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
```

---

## 🧪 Lab Purpose

The environment is designed for hands-on SOC investigation practice.

All suspicious activities documented in this repository were generated or investigated within a controlled laboratory environment.

No unauthorized systems were targeted.
