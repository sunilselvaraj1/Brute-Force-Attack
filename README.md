# 🛡️ Incident Response - **Brute Force Attack**

## 📌 Executive Summary
A custom Threat Analytics rule was created and enabled in Microsoft Sentinel to detect brute-force login attempts on the devices in the organisation. The rule trigered an Incident, detecting brute-force attempt on 2 devices by 2 RemoteIPs. Investigation revealed **13 RemoteIPs targetting 3 Devices** with highest number of attempts as 178. The incident was confirmed as a **true positive**, but **no successful logons occurred**. Affected devices were isolated, scanned, and protected through updated network controls.

**Followed NIST 800-61 Incident Response LifeCycle**

---

## Table of Contents

- [Tools Used](https://github.com/sunilselvaraj1/Brute-Force-Attack/blob/main/README.md#-tools-used)
- [Preparation: Alert rule to detect Brute-force attack]
- [Detection & Analysis]
- [Containment, Eradication & Recovery]
- [Post-Incident Activity]
- [Incident Closure]
- 
- [Vulnerability Management Policy Draft Creation](#vulnerability-management-policy-draft-creation)
- [Mock Meeting: Policy Buy-In (Stakeholders)](#step-2-mock-meeting-policy-buy-in-stakeholders)
- [Policy Finalization and Senior Leadership Sign-Off](#step-3-policy-finalization-and-senior-leadership-sign-off)


## 🧰 Tools Used

- **Microsoft Sentinel** – Custom analytics rule creation and incident investigation  
- **KQL (Kusto Query Language)** – Threat hunting and brute-force correlation  
- **Microsoft Defender for Endpoint (MDE)** – Device isolation, AV scans, and investigation packages  
- **Azure Network Security Groups (NSG)** – Restricting external access  
- **DeviceLogonEvents** – Primary log source for authentication activity

---


## ⚙️ 1. Preparation: Alert rule to detect Brute-force attack

A custom KQL detection rule to identify brute-force attempts was created, tested and deployed in Microsoft Sentinel

### **Detection Rule (KQL)**
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedCount = count() by DeviceName, RemoteIP
| where FailedCount >= 5
| order by FailedCount desc
```
Analytics Rule Settings:
- Run query every 4 hours
- Lookup data for last 5 hours
- Stop running query after alert is generated == Yes
- Configure Entity Mappings for the Remote IP and DeviceName
- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

<img width="1242" height="802" alt="image" src="https://github.com/user-attachments/assets/b1d9a90a-1a1c-42d2-9939-c3237ef7775d" />
<img width="1141" height="628" alt="image" src="https://github.com/user-attachments/assets/cfba4923-d5ab-42cd-af86-f11760f06e29" />


The rule was successfully created, tested, deployed and enabled.

<img width="1813" height="102" alt="image" src="https://github.com/user-attachments/assets/dab1f2cd-451d-41e1-af16-306cb442b687" />

---

## 🔍 3. Detection & Analysis

### 3.1 Alert Trigger

The rule generated an alert for brute-force attempts on:

Targeted Devices

windows-target-1

keith-vm-2025

Suspicious External IPs

196.219.39.203

45.136.68.79

Incident metadata:

Assigned to: Self

Status: Active

Severity: Medium

3.2 Initial Investigation

KQL used to profile all brute-force attempts on the above devices:

DeviceLogonEvents
| where DeviceName == "windows-target-1" or DeviceName == "keith-vm-2025"
| where ActionType == "LogonFailed"
| summarize AttemptCount = count() by DeviceName, RemoteIP


Findings

13 external IPs involved

Maximum failed attempts: 178

3.3 Identifying Additional Impacted Devices

KQL query used to determine if other devices were targeted:

let attackerIP = 
    DeviceLogonEvents
    | where DeviceName in ("windows-target-1", "keith-vm-2025")
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;
DeviceLogonEvents
| where RemoteIP in (attackerIP)
| summarize attemptCount = count() by DeviceName, RemoteIP, ActionType
| order by attemptCount desc


Result

Additional affected device discovered: leon-test-mde

This device was not part of the original alert but was detected through extended investigation.

3.4 Checking for Successful Logons

To ensure no brute-force attempts were successful:

let attackerIP = 
    DeviceLogonEvents
    | where DeviceName in ("windows-target-1", "keith-vm-2025")
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;
DeviceLogonEvents
| where RemoteIP in (attackerIP)
| summarize attemptCount = count() by DeviceName, RemoteIP, ActionType
| distinct ActionType


Outcome

✔️ No successful logins detected

Only LogonFailed events were found

🚧 4. Containment, Eradication & Recovery
4.1 Containment Actions

The following devices were isolated using Microsoft Defender for Endpoint:

windows-target-1

keith-vm-2025

leon-test-mde

Additional measures:

Triggered Anti-Virus scans on all affected machines

Collected investigation packages for forensic review

Updated NSG rules to allow only internal IP traffic

4.2 Eradication

No successful intrusion detected

No malicious persistence found

No eradication steps necessary at this stage

Awaiting AV scan and forensic package results for confirmation

4.3 Recovery

Devices remain isolated until validated as clean

Strengthened network restrictions

Improved monitoring rules for external login attempts

📚 5. Post-Incident Activity
Lessons Learned

Custom analytics rules are highly effective for deeper detection.

NSG restrictions significantly minimise external exposure.

Logging and monitoring should be expanded to all externally reachable assets.

✅ 6. Incident Closure

Incident Status: Closed

Classification: True Positive

Impact: No compromise. Brute-force attempts blocked successfully.
