# Windows Endpoint Detection Engineering & SOC Telemetry Monitoring with Splunk

A hands-on detection engineering project demonstrating the end-to-end pipeline of advanced Windows audit policy configuration, native log ingestion into Splunk Enterprise, real-time attack simulation, SPL rule engineering, alert throttling, and SOC dashboard visualization.

---

## 📌 Project Overview

This project implements an endpoint threat detection pipeline designed to identify brute-force credential stuffing and adversary reconnaissance techniques (MITRE ATT&CK T1110, T1087, T1082). 

By enabling Windows Advanced Security Auditing, collecting structured event logs, and implementing custom Search Processing Language (SPL) correlation rules, the environment provides automated SOC alerting with false-positive suppression and a unified monitoring dashboard.

---

## 📊 SOC Monitoring Dashboard

<p align="center">
  <img src="SOC%20Security%20Monitoring%20-%20Windows%20Endpoint.png" alt="Splunk SOC Dashboard" width="850">
</p>

---

## 🛠️ Architecture & Technologies

* **SIEM Platform:** Splunk Enterprise
* **Target OS:** Windows 10/11 Endpoint
* **Log Sources:** Windows Security Event Log (`WinEventLog:Security`)
* **Detection Engine:** Splunk SPL (Scheduled Alerts, Timechart Aggregations, Throttling)
* **Framework:** MITRE ATT&CK Framework

---

## 🎯 Threat Vectors & MITRE ATT&CK Mapping

| Detection Use Case | MITRE ATT&CK ID | Windows Event ID | Sub-Status / Mechanism |
| :--- | :--- | :--- | :--- |
| **Brute-Force / Password Spraying** | T1110.001 / T1110.003 | `4625` (Logon Failure) | `0xC000006A` (Bad Password), `0xC0000064` (User Does Not Exist) |
| **Account Discovery & Enumeration** | T1087.001 (Local Accounts) | `4688` (Process Creation) | Execution of `net user`, `net1.exe` |
| **Privilege / System Discovery** | T1033 / T1082 / T1016 | `4688` (Process Creation) | Execution of `whoami /priv`, `ipconfig /all` |

---

## ⚙️ Engineering & Implementation Steps

### 1. Windows Advanced Audit Policy Configuration
Modern Windows systems require granular subcategory auditing to log credential validation failures and full command-line arguments.

* **Logon Failure Auditing:**
  ```powershell
  auditpol /set /subcategory:"Logon" /failure:enable /success:enable
  auditpol /set /subcategory:"Account Lockout" /failure:enable /success:enable
  auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable /success:enable
Process Creation & Command-Line Telemetry:

PowerShell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
gpupdate /force
2. Attack Simulation & Telemetry Generation
Simulating Credential Guessing / Failed Auth:

DOS
cmd /c "echo wrongpass | runas /user:TestHacker cmd.exe"
Simulating Situational Awareness Reconnaissance:

DOS
cmd.exe /c "whoami /priv && net user && ipconfig /all"
3. Detection Rule Development (SPL)
Rule 1: Threshold-Based Brute Force Alert
Plaintext
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count by Account_Name, Workstation_Name
| where count >= 3
Schedule: Every 5 minutes (*/5 * * * *)

Time Range: -15m to now

Alert Throttling: Suppressed for 15 minutes per unique Account_Name to prevent SOC alert fatigue.

Rule 2: Living-off-the-Land (LOLBin) Reconnaissance Detection
Plaintext
index=* sourcetype="WinEventLog:Security" EventCode=4688 NOT Account_Name="Splunkd" NOT SubjectUserName="Splunkd"
| eval Proc=lower(coalesce(New_Process_Name, ""))
| eval Cmd=lower(coalesce(Process_Command_Line, ""))
| where match(Proc, "(whoami|net1?\.exe|ipconfig|quser|vssadmin|nltest|tasklist)") OR match(Cmd, "(whoami|net user|ipconfig /all|downloadstring|bypass)")
| table _time, Account_Name, New_Process_Name, Process_Command_Line
| sort - _time
🔍 Key Findings & SOC Takeaways
Sub-Status Code Analysis: Distinguishing 0xC0000064 (invalid username) from 0xC000006A (valid account, wrong password) allows triage analysts to prioritize between broad user enumeration scans and targeted account compromise attempts.

Alert Fatigue Management: Transitioning detection rules from static All time schedules to sliding rolling windows with field-level throttling eliminates duplicate alerts while maintaining immediate detection coverage.
