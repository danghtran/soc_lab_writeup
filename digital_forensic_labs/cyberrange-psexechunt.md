# CyberDefenders - PsExec Hunt (PCAP) Write-up

**Challenge:** [PsExec Hunt](https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, Wireshark, SMB2, PsExec, lateral movement

---

## Summary

An IDS alert flagged **PsExec-style lateral movement**. PCAP analysis shows host **`10.0.0.130`** (**HR-PC**) using SMB2/NTLM as **`ssales`** to pivot to **`SALES-PC`** (`10.0.0.133`), drop **`PSEXESVC.exe`** via **`ADMIN$`**, communicate over **`IPC$`**, then target **`MARKETING-PC`** for further movement.

---

## Scenario

An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, investigate the provided PCAP file to trace the attacker's activities.

---

## Objectives

- Identify the attacker's entry point and compromised credentials.
- Determine first and second pivot targets, PsExec service artifacts, and SMB shares used.
- Map lateral movement tactics and key indicators.

---

## Environment

- **Artifact:** PsExec Hunt PCAP (lab package)
- **Tools:** Wireshark (filters: `smb`, `smb2`, `ntlmssp`, `smb2.tree`, `smb2.filename`)

**Useful filters:**

```text
smb || smb2
ip.addr == 10.0.0.130 && (smb || smb2)
smb2 && smb2.filename contains "PSEXESVC"
smb2.tree
ntlmssp.challenge.target_name
```

---

## Evidence & Findings (Wireshark)

### T1 — Attacker source IP (initial access)

**Question:** Can you identify the IP address of the machine from which the attacker initially gained access?

- **What I checked:** Early SMB2 activity; **Statistics → Conversations → IPv4** for hosts with heavy outbound SMB to multiple targets.
- **Evidence:** Packet **130** — **SMB2 Session Setup Request**, source **`10.0.0.130`**. Conversation stats show **`10.0.0.130`** talking to multiple internal IPs over SMB (lateral movement hub).
- **Reasoning:** The staging/foothold host initiates admin-share connections and PsExec transfers; NTLM **Host** field on auth frames also identifies this machine as **`HR-PC`**.

**Answer:** **`10.0.0.130`**

---

### T2 — First pivot hostname

**Question:** What is the hostname of the machine to which the attacker first pivoted?

- **What I checked:** SMB2 **Session Setup Response** from first target **`10.0.0.133`** following packet 130; NTLMSSP challenge **Target Name** / NetBIOS computer name.
- **Evidence:** NTLM Secure Service Provider on response — target hostname **`SALES-PC`** (also appears in Target Info fields as `SALES-PC` / `Sales-PC`).
- **Reasoning:** First remote SMB session from **`10.0.0.130`** lands on **`10.0.0.133`**, identified as **`SALES-PC`**.

**Answer:** **`SALES-PC`**

---

### T3 — Authentication username

**Question:** What is the username utilized by the attacker for authentication?

- **What I checked:** SMB2 **Session Setup** following the initial connection; **NTLMSSP** auth blob (**User name** field).
- **Evidence:** NTLMSSP — **`User name: ssales`** (session authenticated from **`HR-PC`** / **`10.0.0.130`**).

  ![Wireshark — NTLMSSP username ssales](images/wireshark_ntlmssp_ssales.png)

- **Reasoning:** PsExec requires valid admin credentials; **`ssales`** is the account used for the first pivot session to **`SALES-PC`**.

**Answer:** **`ssales`**

---

### T4 — PsExec service executable

**Question:** What's the name of the service executable the attacker set up on the target?

- **What I checked:** SMB2 **Create/Write** requests after authentication to **`10.0.0.133`**; filter for `.exe` filenames.
- **Evidence:** Packet **144** — **SMB2 Create Request**, file handle **`PSEXESVC.exe`** (PsExec remote service binary).

  ![Wireshark — SMB2 Create PSEXESVC.exe](images/wireshark_smb2_psexesvc.png)

- **Reasoning:** PsExec copies **`PSEXESVC.exe`** to the remote system and starts it as a service — classic PsExec network signature.

**Answer:** **`PSEXESVC.exe`**

---

### T5 — Share used to install the service

**Question:** Which network share was used by PsExec to install the service on the target machine?

- **What I checked:** SMB2 **Tree Connect** before the **`PSEXESVC.exe`** write; **`smb2.tree`** filter.
- **Evidence:** Packet **138** — **Tree Connect** to **`\\10.0.0.133\ADMIN$`**. Subsequent writes (e.g., packet 144) use the same **Tree ID** tied to **`ADMIN$`**.

  ![Wireshark — SMB2 Tree Connect ADMIN$](images/wireshark_tree_admin.png)

- **Reasoning:** PsExec drops the service binary into the remote **`%SystemRoot%`** via the hidden administrative share **`ADMIN$`**.

**Answer:** **`ADMIN$`**

---

### T6 — Share used for PsExec communication

**Question:** Which network share did PsExec use for communication?

- **What I checked:** Post-installation SMB2 activity on **`10.0.0.133`**; tree connects and named-pipe style file operations.
- **Evidence:** Packet **371** — **SMB2 Create Request** for **`PSEXESVC.exe`** with **Tree ID** → **`\\10.0.0.133\IPC$`**. PsExec uses **`IPC$`** for stdin/stdout/stderr named pipes during remote command execution.
- **Reasoning:** After staging the binary on **`ADMIN$`**, interactive PsExec traffic runs over **`IPC$`** (inter-process communication share).

**Answer:** **`IPC$`**

---

### T7 — Second pivot hostname

**Question:** What is the hostname of the second machine the attacker targeted to pivot within our network?

- **What I checked:** Later NTLM challenges from **`10.0.0.130`** to additional hosts; filter **`ntlmssp.challenge.target_name`**.
- **Evidence:** Packet **38514** (and related SMB2 sessions to **`10.0.0.131`**) — NTLMSSP challenge **Target Name: MARKETING-PC**. Same PsExec pattern (`ADMIN$` + **`PSEXESVC.exe`**) repeats toward the second target.

  ![Wireshark — NTLMSSP target MARKETING-PC](images/wireshark_smb2_marketingpc.png)

- **Reasoning:** After compromising **`SALES-PC`**, **`10.0.0.130`** initiates a new lateral movement chain toward **`MARKETING-PC`**.

**Answer:** **`MARKETING-PC`**

---

## Attack Reconstruction

```text
HR-PC (10.0.0.130)  — foothold / staging
        |
        |  SMB2 + NTLM (ssales)
        v
SALES-PC (10.0.0.133)
        |  Tree: \\10.0.0.133\ADMIN$
        |  Write: PSEXESVC.exe
        |  Tree: \\10.0.0.133\IPC$  (stdin/stdout/stderr pipes)
        v
   Remote command execution on SALES-PC
        |
        |  Repeat PsExec pattern
        v
MARKETING-PC (10.0.0.131)
```

1. Attacker operates from **`10.0.0.130`** (**HR-PC**).
2. Authenticates as **`ssales`** over SMB2 to **`SALES-PC`**.
3. Connects **`ADMIN$`**, uploads **`PSEXESVC.exe`**, starts remote service.
4. Uses **`IPC$`** for PsExec pipe communication.
5. Pivots again toward **`MARKETING-PC`**.

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Attacker IP** | `10.0.0.130` (HR-PC) |
| **First target** | `10.0.0.133` / `SALES-PC` |
| **Second target** | `10.0.0.131` / `MARKETING-PC` |
| **Compromised user** | `ssales` |
| **PsExec binary** | `PSEXESVC.exe` |
| **Admin share** | `ADMIN$` |
| **IPC share** | `IPC$` |
| **Protocol / port** | SMB2 over TCP/445 |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| **T1021.002** | Remote Services: SMB/Windows Admin Shares |
| **T1570** | Lateral Tool Transfer (`PSEXESVC.exe`) |
| **T1569.002** | System Services: Service Execution (PsExec) |
| **T1078** | Valid Accounts (`ssales`) |
| **T1021.001** | Remote Desktop Protocol (related remote exec family) |

---

## Mitigation / Hardening

- Restrict **administrative shares** (`ADMIN$`, `C$`) to management subnets; require **SMB signing** and **EPA**.
- Monitor for **`PSEXESVC.exe`** over SMB and rapid **`ADMIN$` → `IPC$`** sequences from non-admin workstations.
- Enforce **tiered admin** accounts; investigate **`ssales`**-style service accounts with broad local admin.
- Alert on **PsExec** (Sysmon Event ID 13/1, EDR) and unusual SMB445 fan-out from a single host.
- Prefer **LAPS**, **JIT admin**, and **PAW** jump hosts over shared local admin passwords.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/
- MITRE T1021.002: https://attack.mitre.org/techniques/T1021/002/
- Sysinternals PsExec: https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
