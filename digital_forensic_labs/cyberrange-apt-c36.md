# CyberDefenders - Amadey APT-C-36 (Memory Forensics) Write-up

**Challenge:** [Amadey - APT-C-36](https://cyberdefenders.org/blueteam-ctf-challenges/amadey-apt-c-36/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Memory forensics, Volatility 3, Amadey, endpoint forensics

---

## Summary

An after-hours EDR alert flagged **Amadey Trojan Stealer** activity on a Windows 7 workstation. Analysis of **`Windows 7 x64-Snapshot4.vmem`** with **Volatility 3** revealed a masquerading process **`lssass.exe`** (typo-squat of `lsass.exe`) staged under `%Temp%`, C2 to **`41.75.84.12`**, download of two plugin DLLs, execution via **`rundll32.exe`** loading **`clip64.dll`**, and persistence via a scheduled task under **`C:\Windows\System32\Tasks\`**.

---

## Scenario

An after-hours alert from the Endpoint Detection and Response (EDR) system flags suspicious activity on a Windows workstation. The flagged malware aligns with the Amadey Trojan Stealer.

---

## Objectives

- Analyze the provided memory dump and document malware actions.
- Identify malicious processes, C2, downloaded modules, execution chain, and persistence.

---

## Environment

- **Artifact:** `Windows 7 x64-Snapshot4.vmem`
- **Tools:** [Volatility 3](https://github.com/volatilityfoundation/volatility3) (`vol.py`)

**Example base command:**

```bash
vol.py --single-location "/path/to/Windows 7 x64-Snapshot4.vmem" -q "<plugin>"
```

---

## Evidence & Findings (Volatility 3)

### T1 — Malicious parent process

**Question:** What is the name of the parent process that triggered this malicious behavior?

- **What I checked:** `windows.pstree.PsTree` — process tree and parent/child relationships.
- **Evidence:**

  ```bash
  vol.py ... -q "windows.pstree.PsTree"
  ```

  Suspicious process **`lssass.exe`** (PID **2748**) — masquerades as legitimate **`lsass.exe`**. It spawns child **`rundll32.exe`** (PID 3064).

- **Reasoning:** Misspelled `lssass` + spawns `rundll32` from a non-system path = Amadey loader behavior. Lab identifies **`lssass.exe`** as the root malicious process in the attack chain.

**Answer:** **`lssass.exe`**

---

### T2 — Process location on disk

**Question:** Where is this process housed on the workstation?

- **What I checked:** `windows.cmdline` for PID 2748.
- **Evidence:**

  ```text
  2748  lssass.exe  "C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe"
  ```

- **Reasoning:** Short 8.3 path `0XSH3R~1` = user profile `0xSh3rl0ck`; malware staged in `%Temp%` subfolder (common dropper location).

**Answer:** **`C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe`**

---

### T3 — C2 server IP

**Question:** Can you identify the Command and Control (C2) server IP that the process interacts with?

- **What I checked:** `windows.netscan` filtered to PID **2748**.
- **Evidence:**

  | Local | Foreign | Port | State | PID | Owner |
  |-------|---------|------|-------|-----|-------|
  | 192.168.195.136 | **41.75.84.12** | **80** | CLOSED | 2748 | lssass.exe |

- **Reasoning:** Outbound TCP to port **80** on a public IP indicates HTTP C2 / module download (vs. ephemeral closed connection to `56.75.178.2`).

**Answer:** **`41.75.84.12`**

---

### T4 — Distinct files fetched from C2

**Question:** How many distinct files is it trying to bring onto the compromised workstation?

- **What I checked:** Dumped malicious process memory, extracted HTTP GET strings.
- **Evidence:**

  ```bash
  vol.py ... -q "windows.memmap.Memmap" --pid 2748 --dump
  strings pid.2748.dmp | grep 'GET /'
  ```

  ```text
  GET /rock/Plugins/cred64.dll HTTP/1.1
  GET /rock/Plugins/clip64.dll HTTP/1.1
  ```

- **Reasoning:** Two unique plugin DLL paths requested from C2 — credential and clipper modules typical of Amadey.

**Answer:** **2**

---

### T5 — Downloaded file path used in activity

**Question:** What is the full path of the file downloaded and used by the malware in its malicious activity?

- **What I checked:** `windows.cmdline` for child **`rundll32.exe`** (PID 3064).
- **Evidence:**

  ```text
  3064  rundll32.exe  "C:\Windows\System32\rundll32.exe" C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll, Main
  ```

- **Reasoning:** Amadey uses **`rundll32.exe`** to run exported function **`Main`** from downloaded **`clip64.dll`** under `%AppData%\Roaming\`.

**Answer:** **`C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`**

---

### T6 — Child process for module execution

**Question:** Which child process is initiated by the malware to execute these files?

- **What I checked:** Process tree — children of **`lssass.exe`** (PID 2748).
- **Evidence:** **`rundll32.exe`** (PID 3064) spawned by **`lssass.exe`**, command line loads **`clip64.dll, Main`**.
- **Reasoning:** Living-off-the-land execution via **`rundll32`** is standard Amadey module activation (T1218.011).

**Answer:** **`rundll32.exe`**

---

### T7 — Additional persistence location

**Question:** Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?

- **What I checked:** `windows.filescan` filtered for **`lssass.exe`**.
- **Evidence:**

  ```text
  \Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe
  \Windows\System32\Tasks\lssass.exe
  ```

- **Reasoning:** **`System32\Tasks`** indicates a **scheduled task** persistence mechanism (survives reboot).

**Answer:** **`C:\Windows\System32\Tasks\lssass.exe`**

---

## Attack Reconstruction

```text
[Dropper/staging] → lssass.exe (%Temp%\925e7e99c5\)
        |
        +→ C2 HTTP :80 → 41.75.84.12
        |       GET /rock/Plugins/cred64.dll
        |       GET /rock/Plugins/clip64.dll
        |
        +→ rundll32.exe → clip64.dll (Main) in %AppData%\Roaming\
        |
        +→ Scheduled task: C:\Windows\System32\Tasks\lssass.exe
```

1. **Masquerading** process **`lssass.exe`** runs from user **Temp** folder.
2. **C2** over HTTP to **`41.75.84.12`** — downloads **`cred64.dll`** and **`clip64.dll`**.
3. **Executes** payload via **`rundll32.exe`** + **`clip64.dll, Main`**.
4. **Persists** via scheduled task under **`System32\Tasks`**.

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Malicious process** | `lssass.exe` (masquerade of `lsass.exe`) |
| **Staging path** | `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` |
| **C2 IP** | `41.75.84.12` (TCP/80) |
| **Downloaded DLLs** | `cred64.dll`, `clip64.dll` (`/rock/Plugins/`) |
| **Active payload** | `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll` |
| **LOLBin** | `rundll32.exe` |
| **Persistence** | `C:\Windows\System32\Tasks\lssass.exe` |
| **Malware family** | Amadey (APT-C-36) |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| **T1036.005** | Masquerading (misspelled `lssass.exe`) |
| **T1071.001** | Application Layer Protocol: Web (HTTP C2) |
| **T1105** | Ingress Tool Transfer (DLL plugins) |
| **T1218.011** | Signed Binary Proxy Execution: Rundll32 |
| **T1053.005** | Scheduled Task persistence |
| **T1555** | Credentials from Password Stores (`cred64.dll`) |

---

## Mitigation / Hardening

- Hunt for **`lssass.exe`** (double-s) and **`lsass.exe`** running from non-system paths.
- Block/lalert egress to known Amadey C2 IPs; monitor HTTP GETs to `/rock/Plugins/`.
- Remove scheduled task **`lssass.exe`** under `C:\Windows\System32\Tasks\`.
- Delete **`925e7e99c5`** Temp folder and **`116711e5a2ab05`** Roaming folder artifacts.
- Restrict **`rundll32`** loading DLLs from `%AppData%` via AppLocker/WDAC where feasible.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/amadey-apt-c-36/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
