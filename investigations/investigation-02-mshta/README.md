\# Investigation 02 — Suspicious mshta.exe Execution



\*\*Date:\*\* September 17, 2026

\*\*Analyst:\*\* Shravani Hendre

\*\*Environment:\*\* Controlled Lab Simulation

\*\*Status:\*\* Completed

\*\*Classification:\*\* Controlled / Benign Lab Activity



\---



\## 1. Investigation Overview



The investigation focused on repeated execution of the Windows utility `mshta.exe`.



`mshta.exe` is a legitimate Windows binary that can execute HTML Applications (HTA files). Because it can be abused to execute code, its execution was investigated using Sysmon telemetry and Splunk.



The activity was generated as part of a controlled laboratory test using a harmless HTA file.



\---



\## 2. Lab Environment



\* \*\*Endpoint:\*\* Windows 11

\* \*\*Hostname:\*\* `SHRAVANI`

\* \*\*User:\*\* `SHRAVANI\\shrav`

\* \*\*Telemetry:\*\* Sysmon

\* \*\*Log Collection:\*\* Splunk Universal Forwarder

\* \*\*SIEM:\*\* Splunk Enterprise

\* \*\*Investigation Interface:\*\* Splunk Web



\---



\## 3. Test File



A harmless HTA file was created at:



```text

C:\\Users\\Public\\soclab\_test.hta

```



The file displayed a test message and then closed.



The test command was:



```text

mshta.exe C:\\Users\\Public\\soclab\_test.hta

```



No malicious payload was used.



\---



\## 4. Initial Search



A search for `mshta.exe` identified \*\*8 Sysmon events\*\* in the available telemetry:



\* 4 × Event ID 1 — Process Creation

\* 4 × Event ID 5 — Process Termination



This showed four separate executions of the test file.



\---



\## 5. Process Timeline



| Time         | Event ID | Process                | Parent     |

| ------------ | -------: | ---------------------- | ---------- |

| 13:02:18.349 |        1 | `mshta.exe`            | `cmd.exe`  |

| 13:02:35.730 |        5 | `mshta.exe` terminated | —          |

| 16:05:48.957 |        1 | `mshta.exe`            | `cmd.exe`  |

| 16:05:54.583 |        5 | `mshta.exe` terminated | —          |

| 16:27:52.179 |        1 | `mshta.exe`            | PowerShell |

| 16:27:56.422 |        5 | `mshta.exe` terminated | —          |

| 22:56:45.592 |        1 | `mshta.exe`            | PowerShell |

| 22:56:49.661 |        5 | `mshta.exe` terminated | —          |



\---



\## 6. Process Creation Evidence



The observed executable was:



```text

C:\\Windows\\System32\\mshta.exe

```



The file was identified as the legitimate Microsoft HTML Application host.



Important fields included:



```text

Description: Microsoft (R) HTML Application host

Company: Microsoft Corporation

OriginalFileName: MSHTA.EXE

User: SHRAVANI\\shrav

IntegrityLevel: High

```



Observed SHA-256:



```text

1F1AABE87E5E93A8FFF769BF3614DD559C51C80FC045E11868F3843D9A004D1E

```



\---



\## 7. Parent-Child Analysis



Two parent processes were observed.



\### Execution through Command Shell



```text

cmd.exe

&#x20;  │

&#x20;  └── mshta.exe

&#x20;      └── C:\\Users\\Public\\soclab\_test.hta

```



\### Execution through PowerShell



```text

powershell.exe

&#x20;  │

&#x20;  └── mshta.exe

&#x20;      └── C:\\Users\\Public\\soclab\_test.hta

```



The available telemetry did not show additional child-process activity originating from `mshta.exe`.



\---



\## 8. Network Activity Check



Sysmon Event ID 3 was searched to determine whether `mshta.exe` generated a recorded network connection.



\### Result



\*\*0 events found.\*\*



No Sysmon Event ID 3 network connection associated with `mshta.exe` was observed in the available telemetry.



This does not prove that network activity is impossible; it only reflects the telemetry available during this investigation.



\---



\## 9. File Activity Check



Sysmon Event ID 11 was searched to determine whether `mshta.exe` was associated with recorded file creation.



\### Result



\*\*0 events found.\*\*



No Sysmon Event ID 11 file creation attributed to `mshta.exe` was observed in the available telemetry.



\---



\## 10. IOC Pivot — HTA File Path



The following path was searched:



```text

C:\\Users\\Public\\soclab\_test.hta

```



The search returned the same four known process creation events.



No additional activity associated with the test file was identified.



\---



\## 11. IOC Pivot — SHA-256



The observed SHA-256 was searched:



```text

1F1AABE87E5E93A8FFF769BF3614DD559C51C80FC045E11868F3843D9A004D1E

```



The search returned the same known `mshta.exe` process creation events.



No additional activity was identified from the hash pivot.



\---



\## 12. MITRE ATT\&CK Mapping



\### T1218.005 — Mshta



`mshta.exe` was used to execute an HTA file.



\### T1059.001 — PowerShell



PowerShell was observed as a parent process for two executions.



\### T1059.003 — Windows Command Shell



`cmd.exe` was observed as a parent process for two executions.



These mappings describe observed techniques and do not by themselves establish malicious activity.



\---



\## 13. Investigation Assessment



`mshta.exe` is a legitimate Windows executable, but its ability to execute HTA content makes its use relevant to SOC investigations.



In this case, the evidence showed:



\* Legitimate Microsoft `mshta.exe`

\* Known laboratory HTA file

\* Controlled execution

\* No observed Sysmon network connections

\* No observed Sysmon file creation attributed to `mshta.exe`

\* No additional child-process activity in the available telemetry

\* IOC searches returned only the known test activity



\### Final Classification



\*\*Controlled / Benign Lab Activity\*\*



\### Escalation



\*\*No escalation required based on the available evidence.\*\*



\---



\## 14. Evidence



\### Process Creation



!\[Process Creation](screenshots/01\_process\_creation.png)



\### Raw Sysmon Event



!\[Raw Event](screenshots/02\_raw\_event.png)



\### Process Timeline



!\[Timeline](screenshots/03\_process\_timeline.png)



\### Network Activity Check



!\[Network Check](screenshots/04\_network\_check.png)



\### File Activity Check



!\[File Activity](screenshots/05\_file\_creation\_check.png)



\### Hash Pivot



!\[Hash Pivot](screenshots/06\_hash\_pivot.png)



\---



\## 15. Investigation Workflow



```text

mshta.exe Detected

&#x20;      │

&#x20;      ▼

Process Creation Analysis

&#x20;      │

&#x20;      ▼

Parent-Child Analysis

&#x20;      │

&#x20;      ▼

Timeline Reconstruction

&#x20;      │

&#x20;      ├── Network Check

&#x20;      │

&#x20;      ├── File Activity Check

&#x20;      │

&#x20;      └── IOC / Hash Pivot

&#x20;      │

&#x20;      ▼

MITRE ATT\&CK Mapping

&#x20;      │

&#x20;      ▼

Evidence-Based Classification

```



\---



\## 16. Key Learning



This investigation demonstrated how a SOC analyst can investigate a potentially suspicious Windows utility without immediately assuming malicious activity.



The investigation used process telemetry, parent-child relationships, timelines, network and file checks, and IOC pivots to determine whether the observed `mshta.exe` activity required escalation.



