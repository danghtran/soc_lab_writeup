# CyberDefenders - RedLine (Memory Forensics) Write-up

**Challenge:** [RedLine](https://cyberdefenders.org/blueteam-ctf-challenges/redline/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Endpoint forensics, memory forensics, Volatility 3, RedLine Stealer

---

## Summary

User **Tammam**’s machine ran **`oneetx.exe`** from a random Temp folder — it spawned **`rundll32.exe`**, used **`PAGE_EXECUTE_READWRITE`** memory (injection-friendly), and talked to **`77.91.124.20:80`** over **`http://77.91.124.20/store/games/index.php`**. **Outline VPN** (**`Outline.exe`** → **`tun2socks.exe`**) was active at the same time, which explains how C2 traffic may have slipped past the **NIDS**. Full path: **`C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe`** — consistent with **RedLine Stealer**–style infostealer activity.

---

## Scenario

As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools.

Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System (NIDS). Your investigation will identify the specific malware family employed in the attack and its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

---

## Objectives

- Find suspicious processes and parent/child relationships in RAM.
- Inspect memory protections and on-disk paths for the malware.
- Recover network IOCs (C2 IP, URL) and explain NIDS bypass (VPN tunnel).
- Document artifacts for containment and host cleanup.

---

## Environment

- **Artifact:** `MemoryDump.mem` (lab ZIP `106-RedLine`)
- **Victim user:** `Tammam`
- **Capture window (from processes):** 2023-05-21 ~22:30–23:01 UTC
- **Tools:** [Volatility 3](https://github.com/volatilityfoundation/volatility3), strings / `grep` on the dump, optional Microsoft Redline (lab mentions both)

**Volatility 3 commands used:**

```text
vol -f MemoryDump.mem -q windows.pstree
vol -f MemoryDump.mem -q windows.vadinfo --pid 5896
vol -f MemoryDump.mem -q windows.netscan
strings MemoryDump.mem | grep 77.91.124.20
```

---

## Evidence & Findings

### T1 — Suspicious process name

**Question:** What is the name of the suspicious process?

- **What I checked:** **`windows.pstree`** — look for processes running from **`Temp`** with odd names, not signed Microsoft paths.
- **Evidence:**

  ```text
  vol -f MemoryDump.mem -q windows.pstree

  5896  8844  oneetx.exe  ...  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
  ```

- **Reasoning:** Legitimate apps rarely run as random `.exe` names from a hex-like folder under **`AppData\Local\Temp`**. **`oneetx.exe`** stands out immediately in the process tree.

**Answer:** **`oneetx.exe`**

---

### T2 — Child process name

**Question:** What is the child process name of the suspicious process?

- **What I checked:** Same **`pstree`** output — children of PID **5896** (`oneetx.exe`).
- **Evidence:**

  ```text
  * 7732  5896  rundll32.exe  ...  \Windows\SysWOW64\rundll32.exe
  ```

- **Reasoning:** Malware often launches **`rundll32.exe`** to run DLL payloads or proxy execution so the parent process does not look like a direct network client. One child under **`oneetx.exe`** → **`rundll32.exe`**.

**Answer:** **`rundll32.exe`**

---

### T3 — Memory protection on suspicious region

**Question:** What is the memory protection applied to the suspicious process memory region?

- **What I checked:** **`windows.vadinfo --pid 5896`** — Virtual Address Descriptor (VAD) entries show how memory pages are protected.
- **Evidence:**

  ```text
  vol -f MemoryDump.mem -q windows.vadinfo --pid 5896

  5896  oneetx.exe  ...  0x400000  ...  VadS  PAGE_EXECUTE_READWRITE  ...
  ```

- **Reasoning:** **`PAGE_EXECUTE_READWRITE`** (RWX) means the region can be read, written, and executed. That is a red flag for shellcode injection or unpacked malware — normal executables usually separate code (RX) from data (RW).

**Answer:** **`PAGE_EXECUTE_READWRITE`**

---

### T4 — VPN parent process

**Question:** What is the name of the process responsible for the VPN connection?

- **What I checked:** **`windows.netscan`** for active connections, then **`pstree`** to see who owns the tunnel helper.
- **Evidence:**

  ```text
  netscan → tun2socks.exe (network activity — typical Outline tunnel component)

  pstree:
  *** 6724  3580  Outline.exe  ...  \Program Files (x86)\Outline\Outline.exe
  **** 4628  6724  tun2socks.exe  ...  outline-go-tun2socks\win32\tun2socks.exe
  ```

- **Reasoning:** **`tun2socks.exe`** handles the actual tunneled traffic, but it is spawned by **Outline VPN**. The lab asks for the process **responsible for the VPN** — that is **`Outline.exe`** (parent), not the helper binary.

**Answer:** **`outline.exe`**

---

### T5 — Attacker IP address

**Question:** What is the attacker's IP address?

- **What I checked:** **`windows.netscan`** filtered on **`oneetx.exe`** (PID **5896**).
- **Evidence:**

  ```text
  TCPv4  10.0.85.2  55462  77.91.124.20  80  CLOSED  5896  oneetx.exe  2023-05-21 23:01:22 UTC
  ```

- **Reasoning:** The suspicious process initiated outbound HTTP to **`77.91.124.20`** — external IP, port **80**, not a known CDN or update server. That is your C2/staging host.

**Answer:** **`77.91.124.20`**

---

### T6 — PHP URL visited by attacker

**Question:** What is the full URL of the PHP file that the attacker visited?

- **What I checked:** String search on the memory image for the C2 IP from T5.

  ```bash
  strings MemoryDump.mem | grep 77.91.124.20
  ```

- **Evidence:** HTTP URL embedded in process memory:

  ```text
  http://77.91.124.20/store/games/index.php
  ```

- **Reasoning:** Infostealers often use innocent-looking paths (`/store/games/`) on plain HTTP. The **`.php`** endpoint is the callback the malware contacted.

**Answer:** **`http://77.91.124.20/store/games/index.php`**

---

### T7 — Full path of malicious executable

**Question:** What is the full path of the malicious executable?

- **What I checked:** **`windows.vadinfo --pid 5896`** — VAD records can include the **file path** mapped into memory.
- **Evidence:**

  ```text
  5896  oneetx.exe  ...  0xec0000  ...  Vad  PAGE_EXECUTE_WRITECOPY  ...
       \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
  ```

  Full path on disk:

  ```text
  C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
  ```

- **Reasoning:** This is the footprint to delete during IR, hash for VT, and hunt across other hosts (`**\Temp\*\oneetx.exe`**).

**Answer:** **`C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Malware process** | `oneetx.exe` (PID **5896**) |
| **Child process** | `rundll32.exe` |
| **On-disk path** | `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe` |
| **Memory protection** | `PAGE_EXECUTE_READWRITE` |
| **C2 IP** | `77.91.124.20` |
| **C2 URL** | `http://77.91.124.20/store/games/index.php` |
| **VPN (NIDS bypass)** | `Outline.exe` / `tun2socks.exe` |
| **Victim user** | `Tammam` |
| **Likely family** | RedLine Stealer (infostealer) |

---

## Attack reconstruction

```text
[User Tammam]
    → Runs oneetx.exe from Temp\c3912af058\  (likely RedLine Stealer dropper)
    → Spawns rundll32.exe; RWX memory (injection / unpack)
    → Outline VPN (tun2socks) encrypts egress → NIDS misses cleartext C2 pattern
    → HTTP to 77.91.124.20/store/games/index.php
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1055** | Process Injection | RWX VAD (T3), rundll32 child (T2) |
| **T1218.011** | Rundll32 | Child process (T2) |
| **T1071.001** | Web Protocols | HTTP C2 URL (T5–T6) |
| **T1572** | Protocol Tunneling | Outline VPN / tun2socks (T4) — NIDS bypass |
| **T1036** | Masquerading | Random name `oneetx.exe` in Temp |
| **T1005** | Data from Local System | RedLine Stealer behavior (scenario) |

---

## Mitigation / IR steps

1. Isolate host; kill **`oneetx.exe`** / **`rundll32.exe`**; delete **`c3912af058`** folder under Temp.
2. Block **`77.91.124.20`** and URL **`/store/games/index.php`** at proxy/firewall.
3. Review **Outline VPN** policy — untrusted VPN tunnels can hide malware C2 from NIDS.
4. Hunt: **`PAGE_EXECUTE_READWRITE`** regions + **`rundll32`** parented by unknown Temp executables.
5. Reset credentials for user **Tammam** if RedLine-style cookie/password theft is suspected.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/redline/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Related TI write-up: [Red Stealer](../threat_intelligence_labs/cyberrange-redstealer.md) (same malware family, hash-based analysis)
- MITRE T1572: https://attack.mitre.org/techniques/T1572/
