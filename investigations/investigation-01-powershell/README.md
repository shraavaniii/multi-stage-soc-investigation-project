\# Investigation 01 — Suspicious PowerShell Execution



\*\*Date:\*\* August 26, 2026

\*\*Analyst:\*\* Shravani Hendre

\*\*Environment:\*\* Controlled Lab Simulation

\*\*Status:\*\* Completed

\*\*Classification:\*\* Suspicious Activity — Controlled Simulation



\---



\## 1. Investigation Overview



A black terminal window briefly appeared on the Windows 11 workstation and disappeared.



The investigation focused on identifying the process responsible, examining its command line, determining the parent-child process relationship, and understanding the executed PowerShell command.



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



\## 3. Initial Investigation



The following SPL query was used to identify Sysmon Process Creation events involving PowerShell and Command Shell:



```spl

index="windows" "<EventID>1</EventID>" "powershell.exe" "cmd.exe"

```



The search identified a PowerShell process launched through `cmd.exe`.



\---



\## 4. Process Evidence



\### Process Creation



\*\*Timestamp:\*\*



`2026-08-26 08:20:48.653 AM`



\*\*Host:\*\*



`SHRAVANI`



\*\*User:\*\*



`SHRAVANI\\shrav`



\*\*Process ID:\*\*



`7956`



\*\*Image:\*\*



```text

C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

```



\*\*Parent Process ID:\*\*



`9252`



\*\*Command Line:\*\*



```text

powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand <Base64>

```



\*\*Parent Command Line:\*\*



```text

"C:\\windows\\system32\\cmd.exe" /c powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand <Base64>

```



\---



\## 5. Parent-Child Relationship



The process relationship was:



```text

cmd.exe

PID 9252

&#x20;  │

&#x20;  └── powershell.exe

&#x20;      PID 7956

```



This shows that `cmd.exe` launched the PowerShell process.



\---



\## 6. Command-Line Analysis



The PowerShell command contained several parameters:



| Parameter             | Meaning                                              |

| --------------------- | ---------------------------------------------------- |

| `-NoProfile`          | Starts PowerShell without loading the user's profile |

| `-NonInteractive`     | Runs without interactive user input                  |

| `-WindowStyle Hidden` | Hides the PowerShell window                          |

| `-EncodedCommand`     | Executes a Base64-encoded PowerShell command         |



The combination of a hidden PowerShell window and an encoded command was treated as suspicious and required further investigation.



\---



\## 7. Decoded Command



The Base64 command was decoded during the investigation.



Decoded command:



```powershell

New-Item -Path "$env:PUBLIC\\soclab\_marker.txt" -ItemType File -Force

```



This command creates:



```text

C:\\Users\\Public\\soclab\_marker.txt

```



The command was part of the controlled SOC lab simulation.



\---



\## 8. MITRE ATT\&CK Mapping



\### T1059.001 — PowerShell



PowerShell was used to execute the command.



\### T1027 — Obfuscated Files or Information



The PowerShell command was supplied using the `-EncodedCommand` parameter.



These mappings describe the observed techniques and do not by themselves establish malicious activity.



\---



\## 9. Investigation Assessment



The observed execution contained characteristics that commonly require investigation in a SOC environment:



\* Hidden PowerShell execution

\* Encoded command

\* PowerShell launched through `cmd.exe`

\* File creation command



The decoded command, however, was associated with the controlled laboratory simulation.



\### Final Classification



\*\*Suspicious Activity — Controlled Simulation\*\*



\---



\## 10. Evidence



Screenshots from the investigation are stored in the `screenshots` directory.



\### Splunk Search



!\[Initial Splunk Search](screenshots/01\_search\_results.png)



\### Process Creation



!\[Process Creation](screenshots/02\_process\_creation.png)



\### Command-Line Evidence



!\[Command Line](screenshots/03\_command\_line.png)



\---



\## 11. Investigation Workflow



```text

Suspicious Activity

&#x20;      │

&#x20;      ▼

Splunk Search

&#x20;      │

&#x20;      ▼

Process Creation

&#x20;      │

&#x20;      ▼

Parent-Child Analysis

&#x20;      │

&#x20;      ▼

Command-Line Analysis

&#x20;      │

&#x20;      ▼

Decode PowerShell Command

&#x20;      │

&#x20;      ▼

MITRE ATT\&CK Mapping

&#x20;      │

&#x20;      ▼

Evidence-Based Classification

```



\---



\## 12. Key Learning



This investigation demonstrated how a SOC analyst can use Sysmon and Splunk to move from a suspicious process to the actual command being executed.



It also demonstrated why command-line parameters, parent-child relationships, and decoded PowerShell content are important when investigating suspicious endpoint activity.



