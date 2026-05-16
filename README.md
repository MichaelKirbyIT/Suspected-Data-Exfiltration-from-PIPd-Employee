# 🛡️ Project: Insider-Threat-Data-Exfiltration-and-Cloud-Smuggling
> **Threat Hunt & Incident Analysis Report** | *Platform: Microsoft Defender for Endpoint (MDE)*

---
```
[ TRUSTED ENDPOINT ] 
            │
            │  (Unauthorized Data Staging)
            ▼
  ┌───────────────────┐
  │ 📦 C:\ProgramData │  <-- Sensitive Employee CSV Zip Archive
  └─────────┬─────────┘
            │
            ▼
 ┌─────────────────────┐     ┌───────────────────────┐
 │   michael-mde-vm    │ ──> │ MDE EDR Telemetry     │
 │  (Outbound Surge)   │     │ (sacyberrangedanger)  │
 └──────────┬──────────┘     └───────────────────────┘
            │
            ▼
  ┌───────────────────┐
  │ 🔒 Host Isolated  │  <-- Containment Action (Success)
  └───────────────────┘
```
## Platforms and Languages Leveraged
- Operating System / Infrastructure: Windows 11 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Query Language: Kusto Query Language (KQL)
- Threat Vector: Insider Threat / Unauthorized Data Staging and Cloud Exfiltration

##  Scenario

A high-risk employee currently on a Performance Improvement Plan (PIP) was suspected of exfiltrating proprietary organizational data. Security analysts initiated a proactive threat hunt focused on archival file creations and unauthorized outbound cloud connections.
The investigation confirmed that a malicious script (`exfiltratedata.ps1`) was used to download a command-line archiving utility (`7z.exe`), compress a sensitive local CSV file containing employee records into a `.zip` archive within a common data staging directory (`C:\ProgramData\`), and upload the archive directly to an unauthorized external Azure Blob Storage container (`sacyberrangedanger.blob.core.windows.net`). The endpoint was instantly isolated upon detection of the data transfer.

### High-Level Data Exfiltration IoC Discovery Plan

- **Audit Compressed File Formats:** Query `DeviceFileEvents` to pinpoint newly generated or modified compressed extensions (`.zip`, `.rar`) indicating potential data staging.
- **Reconstruct Execution Temporal Context:** Target a $\pm2$-minute time window around the archive's creation date in `DeviceProcessEvents` to map out the commands and scripts driving the consolidation.
- **Trace the Process Lineage:** Track the explicit parent/child process tree linked to the script's Process ID (PID) to confirm what files were processed and packed.
- **Analyze Network Destination Symmetry:** Audit `DeviceNetworkEvents` within the identical execution time window to map the exact outbound external IP or cloud domain capturing the network surge.
- **Cross-Reference Data Staging Folders:** Verify if intermediate staging actions or local artifact purging occurred inside typical high-write folders like `C:\ProgramData\` or `\Temp`.

---

## Steps Taken

### 1. Discovery of Archival Data Staging

An initial broad search across the `DeviceFileEvents` table identified an unusual compressed `.zip` archive creation event on `michael-mde-vm`, establishing a starting point for the timeline.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "michael-mde-vm"
| where FileName endswith ".zip"
| summarize by DeviceName, TimeGenerated, Timestamp, ActionType, FileName, FolderPath
| order by TimeGenerated desc
```
**Results:**

<img width="840" height="83" alt="image" src="https://github.com/user-attachments/assets/63c36e4d-7d8d-41b4-be98-42d088c5c667" />


---

### 2. Time-Window Process Analysis ($\pm2$-Minute Pivot)

Pivoting to the `DeviceProcessEvents` table using a narrow $\pm2$-minute window around the archive's timestamp ($2026\text{-}05\text{-}02T17:28:09Z$) caught a PowerShell script silently downloading and leveraging the 7-Zip compression binary to bundle sensitive internal files.

**Query used to locate events:**

```kql
// Focus on the precise execution timeline window
let VMName = "michael-mde-vm";
let specificTime = datetime(2026-05-02T17:28:09.7453446Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine
```
**Results:**

<img width="840" height="290" alt="image" src="https://github.com/user-attachments/assets/5e1751ca-4c7a-42c7-a072-0ea4f64f7b84" />


---

### 3. Script Lineage and Data Payload Verification

Filtering process events by the explicit Process ID ($6916$) tied to `exfiltratedata.ps1` exposed the exact targets: the command line used `7z.exe` to sweep up a local CSV file filled with proprietary employee records and drop the resulting package into a hidden directory.

**Query used to locate events:**

```kql
// Analyze the exact operations conducted by the malicious script PID
DeviceProcessEvents
| where DeviceName == "michael-mde-vm"
| where InitiatingProcessId == 6916
| project Timestamp, FileName, ProcessCommandLine
```
**Results:**

<img width="840" height="207" alt="image" src="https://github.com/user-attachments/assets/64718c4a-34f9-4b12-abca-104a92849513" />

---

### 4. High-Fidelity Network Exfiltration Correlation

Reviewing network logs over the exact $\pm2$-minute compromise window revealed a successful outbound network handshake between `michael-mde-vm` and an unauthorized, adversarial external Azure Blob Storage endpoint (`sacyberrangedanger.blob.core.windows.net`), verifying exfiltration.

**Query used to locate events:**

```kql
// Correlate network activity to map out exfiltration endpoints
let VMName = "michael-mde-vm";
let specificTime = datetime(2026-05-02T17:28:09.7453446Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
**Results:**

<img width="842" height="74" alt="image" src="https://github.com/user-attachments/assets/e5d41a18-7839-4975-b1e1-a3dd1dce2013" />


---

### 5. Staging Folder Forensic Audit

A specialized file inquiry targeting the `C:\ProgramData\` and `\Temp\` paths during the exfiltration surge verified that `exfiltratedata.ps1` generated temporary archives to hide data before execution, followed by automated cleanup.

**Query used to locate events:**

```kql
let specificTime = datetime(2026-05-02T17:28:09.7453446Z);
DeviceFileEvents
| where DeviceName == "michael-mde-vm"
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where FolderPath startswith "c:\\programdata" or FolderPath contains "temp"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessCommandLine
| order by Timestamp desc
```
**Results:**

<img width="840" height="190" alt="image" src="https://github.com/user-attachments/assets/cd532eb2-cdab-477b-bcc2-7f2bf31c3e4a" />

---

### Summary of Findings

Using KQL, I correlated various high-fidelity indicators, including the execution of obfuscated PowerShell scripts and the "just-in-time" installation of 7-Zip to stage sensitive employee data in `C:\ProgramData\`. The hunt concluded by confirming the exfiltration of this data to an external Azure Blob Storage account, providing a complete forensic record of the incident. Following the identification of these threats, the host was isolated and specific indicators of compromise (IOCs) were documented to refine future detection rules and strengthen the environment’s defensive posture.

---

### Threat Hunt Documentation: Michael-MDE-VM Compromise

* **Incident Summary**: Confirmed malicious execution of obfuscated PowerShell scripts and "just-in-time" installation of 7-Zip to stage sensitive employee data in `C:\ProgramData\`. The hunt concluded by confirming the data exfiltration surge to an external Azure Blob Storage account, providing a complete forensic timeline.
* **Timeline of Events (2026-05-02)**: 
    * **17:26 UTC**: External tool ingress and installation of the 7-Zip utility package (`7z2408-x64.exe`).
    * **17:28 UTC**: Execution of `exfiltratedata.ps1` (PID 6916) compressing a local employee data CSV file.
    * **17:29 UTC**: Successful outbound data transfer surge established to `sacyberrangedanger.blob.core.windows.net`.
* **Key Indicators of Compromise (IOCs)**:
    * **Exfiltration Domain**: `sacyberrangedanger.blob.core.windows.net`
    * **Files / Tools**: `exfiltratedata.ps1`, `7z2408-x64.exe`, `7z.exe`

---

### MITRE ATT&CK TTP Mapping

* **Tactic: Collection**
    * **Technique:** Data from Local System (T1005) — Targeting internal employee CSV records.
    * **Technique:** Archive Collected Data: Archive via Utility (T1560.001) — Utilizing `7z.exe` to compress staged payloads.
* **Tactic: Exfiltration**
    * **Technique:** Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002) — Smuggling data to a rogue Azure Blob Container.
* **Tactic: Execution**
    * **Technique:** Command and Scripting Interpreter: PowerShell (T1059.001) — Automated data collection via script.
* **Tactic: Defense Evasion**
    * **Technique:** Obfuscated Files or Information (T1027) — Utilizing Base64 script masking.
    * **Technique:** Indicator Removal on Host: File Deletion (T1070.004) — Cleaning up temporary paths post-staging.
* **Tactic: Resource Development**
    * **Technique:** Ingress Tool Transfer (T1587.001) — Fetching rogue binaries (`7z.exe`) to stage files.

 ---

### Response Actions

* **Endpoint Isolation**: Immediately isolated `michael-mde-vm` from the network via Microsoft Defender for Endpoint upon discovery of the active cloud data transfer.
* **Management & HR Escalation**: Security Operations formally briefed the employee's direct manager and Human Resources, presenting the KQL timestamps, process execution trees, and file path evidence.
* **Cloud Ingress/Egress Restriction**: Blacklisted the rogue storage account URL (`sacyberrangedanger.blob.core.windows.net`) at the corporate web proxy and egress firewall levels.
* **Identity Token Revocation**: Suspended the user account's corporate identity, revoked all active cloud authentication tokens, and forced an immediate credential reset.

---

### Continuous Security Improvement (Post-Incident Hardening)

#### Prevention (Hardening Posture)
* **Access Control**: Disable public-facing management ports and transition exclusively to Azure Bastion or VPN access frameworks to completely eliminate the initial intrusion vector.
* **Authentication**: Enforce strict phishing-resistant Multi-Factor Authentication (MFA) across all local and cloud user environments to stop account hijack.
* **Execution Prevention**: Implement PowerShell Constrained Language Mode (CLM) via AppLocker rules to stop the execution of unauthorized scripts, arbitrary API functions, and dual-use compilation tools.

---

#### Hunting Process Refinement

* **Silent Executable Detections**: Deploy a persistent Microsoft Sentinel Analytic Rule targeting silent, automated software installers executing from non-standard system directories.

```
// Custom Alert Rule: Detect silent executables running outside expected system paths
DeviceProcessEvents
| where DeviceName == "michael-mde-vm"
| where ProcessCommandLine has_any (" /s", " -s", " /quiet", " -quiet", " /silent", " -silent", " /verysilent", " -qn", " /qn")
| where not(FolderPath startswith "c:\\windows\\system32")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```
* **Detection Automation:** Convert this successful KQL data exfiltration hunt template into an active SIEM detection model to immediately trigger high-priority alerts on process-to-network cloud sync correlations.

* **Enhanced Visibility:** Mandate the deployment of Advanced Command Line Logging (Event ID 4688) across all active machines to record full raw script parameters rather than relying on ephemeral EDR process snapshots.

* **Proactive Staging Audits:** Automate a recurring, daily threat hunting query that checks for bulk file creations or unexpected archival modifications inside C:\ProgramData\ and C:\Windows\Temp\ paths to arrest data staging before exfiltration can occur.


 


