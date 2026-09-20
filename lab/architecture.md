\# SOC Lab Architecture



\## Overview



This project uses a Windows 11 endpoint to generate security telemetry that is collected by Sysmon and forwarded to Splunk Enterprise for investigation.



\---



\## Architecture



```text

┌──────────────────────────────┐

│       Windows 11 Host        │

│          SHRAVANI            │

│                              │

│  Test Activity               │

│       ↓                      │

│  Sysmon                      │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              │ Windows Telemetry

&#x20;              ▼

┌──────────────────────────────┐

│ Splunk Universal Forwarder   │

│       Windows Endpoint       │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              │ Forwarded Events

&#x20;              ▼

┌──────────────────────────────┐

│       Ubuntu Server VM       │

│                              │

│      Splunk Enterprise       │

│         Indexer             │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│         Splunk Web           │

│                              │

│       SOC Analyst            │

└──────────────────────────────┘

```



\---



\## Components



\### Windows 11



The Windows endpoint generates the activity being investigated.



Hostname:



```text

SHRAVANI

```



\---



\### Sysmon



Sysmon provides detailed Windows endpoint telemetry.



Important events used in the investigations include:



| Event ID | Purpose             |

| -------: | ------------------- |

|        1 | Process Creation    |

|        3 | Network Connection  |

|        5 | Process Termination |

|       11 | File Create         |



\---



\### Splunk Universal Forwarder



The Universal Forwarder collects Windows telemetry and forwards it to the Splunk Enterprise server.



\---



\### Ubuntu Server



The Ubuntu Server virtual machine hosts Splunk Enterprise.



\---



\### Splunk Enterprise



Splunk receives and indexes the forwarded Windows telemetry.



The analyst uses SPL searches to investigate the collected events.



\---



\### Splunk Web



Splunk Web provides the interface used by the analyst to search, filter, correlate, and investigate security events.



\---



\## Data Flow



```text

Windows Activity

&#x20;      ↓

Sysmon

&#x20;      ↓

Splunk Universal Forwarder

&#x20;      ↓

Splunk Enterprise

&#x20;      ↓

Splunk Web

&#x20;      ↓

SOC Investigation

```



\---



\## Investigation Method



The general investigation process is:



1\. Identify suspicious activity

2\. Search relevant Sysmon events

3\. Examine process information

4\. Analyze command lines

5\. Identify parent-child relationships

6\. Build a timeline

7\. Check network activity

8\. Check file activity

9\. Pivot using IOCs such as paths and hashes

10\. Map observed behavior to MITRE ATT\&CK

11\. Classify the activity using available evidence

12\. Determine whether escalation is required



