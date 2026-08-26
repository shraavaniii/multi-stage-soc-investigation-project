# Multi-Stage SOC Investigation Project

Welcome to my security portfolio. This repository documents a comprehensive, multi-stage threat hunting project designed to simulate real-world adversarial behavior, monitor host telemetry via native tools, and reconstruct the complete attack lifecycle using a centralized SIEM platform.

## 🛠️ Lab Architecture
* **SIEM Platform:** Splunk Enterprise Server (Hosted on Ubuntu Server 24.04 VM)
* **Endpoint Logging:** Microsoft Sysinternals Sysmon (Windows 11 Host)
* **Data Transport:** Splunk Universal Forwarder (Configured with system-level local inputs)

---

## 🔬 Investigation 01: Insiders & Obfuscated PowerShell Execution
**Date:** August 26, 2026  
**Analyst:** shrav  
**Phase Status:** Completed (Telemetry Confirmed)

### 📋 Phase Brief & Scenario
A user reported that a black terminal window flashed briefly on their Windows 11 workstation (`SHRAVANI`) and immediately disappeared. This investigation focused on hunting the initial foothold without shortcut indicators to map the parent-child relationship of the execution loop.

### 🕵️‍♂️ Step 1: Threat Hunting (SPL Query)
To isolate native shell process creation events without using keyword shortcuts like `EncodedCommand` or filename metrics, the following structured **Splunk Search Processing Language (SPL)** query was deployed:

```spl
index="windows" "<EventID>1</EventID>" "powershell.exe" "cmd.exe"
```

### 📊 Collected Forensic Evidence

| Metric / Log Field | Extracted Telemetry Value |
| :--- | :--- |
| 🕒 **Timestamp** | `2026-08-26 08:20:48.653 AM` |
| 💻 **Affected Host** | `SHRAVANI` |
| 👤 **User Context** | `SHRAVANI\shrav` |
| 🔢 **Process ID (PID)** | `7956` |
| 📄 **Executed Image** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| ⌨️ **Command Line** | `powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand TgBlAHcALQBJAHQAZQBtACAALQBQAGEAdABoACAAIgAkAGUAbgB2ADoAUABVAEIATABJAEMAXABzAG8AYwBsAGEAYgBfAG0AYQByAGsAZQByAC4AdAB4AHQAIgAgAC0ASQB0AGUAbQBUAHkAcABlACAARgBpAGwAZQAgAC0ARgBvAHIAYwBlAA==` |
| 🌳 **Parent Process Image** | `C:\Windows\System32\cmd.exe` |
| 🆔 **Parent Process ID** | `9252` |
| 🛠️ **Parent Command Line** | `"C:\windows\system32\cmd.exe" /c powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand [Base64_String]` |

### 🔍 Behavioral Analysis & TTP Breakdown

1. **Abnormal Parent-Child Relationship (`cmd.exe` ➡️ `powershell.exe`):**  
   The execution loop reveals a native command shell being leveraged to proxy execution into an administrative PowerShell console, a pattern frequently used to break tracking detection tools.
   
2. **Operational Evasion Flags:**  
   The execution parameters explicitly suppressed visibility to remain hidden from the interactive desktop user:
   * `-NoProfile`: Bypasses default configuration loading, decreasing execution overhead and avoiding user profile detection scripts.
   * `-NonInteractive`: Disables user execution prompts, keeping the payload automated in the background.
   * `-WindowStyle Hidden`: Drops the GUI window completely. This matches the user's report of a brief, flashing screen.

3. **Data Obfuscation:**  
   The underlying script payload was hidden via Base64 compilation using the `-EncodedCommand` flag to bypass static network perimeter filtering.

### 🧠 MITRE ATT&CK Mapping
* **T1059.001 (Execution):** Command and Scripting Interpreter: PowerShell
* **T1027 (Defense Evasion):** Obfuscated Files or Information

### 🏁 Initial Assessment
**Classification:** `Suspicious (Controlled Simulation Verified)`  
While structurally identical to an adversarial evasion campaign, the timeline aligns with a signature framework baseline test. The telemetry pipeline is operating at 100% fidelity.
