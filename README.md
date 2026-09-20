\# Multi-Stage SOC Investigation



A hands-on Security Operations Center (SOC) investigation project built in a controlled lab environment using \*\*Windows 11, Sysmon, Splunk Universal Forwarder, Splunk Enterprise, and Splunk Web\*\*.



The project focuses on investigating suspicious endpoint activity through process telemetry, command-line analysis, timeline reconstruction, network and file activity checks, IOC pivots, and MITRE ATT\&CK mapping.



> \*\*Environment:\*\* Controlled Lab Simulation

> \*\*Analyst:\*\* Shravani Hendre



\---



\## 🔎 Investigations



| Investigation                                                   | Topic                            | Status    |

| --------------------------------------------------------------- | -------------------------------- | --------- |

| \[Investigation 01](investigations/investigation-01-powershell/) | Suspicious PowerShell Execution  | Completed |

| \[Investigation 02](investigations/investigation-02-mshta/)      | Suspicious `mshta.exe` Execution | Completed |



\---



\## 🧪 Lab Architecture



```text

Windows 11 Endpoint

&#x20;      │

&#x20;      │ Sysmon

&#x20;      ▼

Splunk Universal Forwarder

&#x20;      │

&#x20;      │ Windows Event Telemetry

&#x20;      ▼

Ubuntu Server

Splunk Enterprise

&#x20;      │

&#x20;      ▼

Splunk Web

&#x20;      │

&#x20;      ▼

SOC Analyst

```



Detailed lab architecture and data flow:



\[View Lab Architecture](lab/architecture.md)



\---



\## 🛠️ Tools Used



\* Windows 11

\* Sysmon

\* Splunk Universal Forwarder

\* Splunk Enterprise

\* Splunk Web

\* PowerShell

\* Windows Command Shell

\* SPL

\* MITRE ATT\&CK



\---



\## 📊 Investigation Workflow



Each investigation follows a practical SOC investigation process:



1\. Alert / suspicious activity identification

2\. Process creation analysis

3\. Command-line investigation

4\. Parent-child process analysis

5\. Timeline reconstruction

6\. Network activity check

7\. File activity check

8\. IOC / hash pivoting

9\. MITRE ATT\&CK mapping

10\. Activity classification

11\. Escalation decision



\---



\## 🎯 Skills Demonstrated



\* SOC alert investigation

\* Windows process analysis

\* Sysmon telemetry analysis

\* Splunk log investigation

\* Basic SPL querying

\* PowerShell investigation

\* LOLBin analysis

\* Parent-child process analysis

\* Timeline reconstruction

\* IOC pivoting

\* Network and file activity validation

\* MITRE ATT\&CK mapping

\* Evidence-based incident classification



\---



\## 📁 Repository Structure



```text

multi-stage-soc-investigation-project/

│

├── README.md

│

├── investigations/

│   │

│   ├── investigation-01-powershell/

│   │   ├── README.md

│   │   └── screenshots/

│   │

│   └── investigation-02-mshta/

│       ├── README.md

│       └── screenshots/

│

├── lab/

│   └── architecture.md

│

└── portfolio-logo(final).jpg

```



\---



\## ⚠️ Disclaimer



All investigations in this repository were performed in a controlled lab environment for educational and defensive security analysis.



The presence of a suspicious Windows utility, command, or technique in the telemetry does not by itself indicate malicious activity. Findings are classified based on the available evidence and investigation context.



