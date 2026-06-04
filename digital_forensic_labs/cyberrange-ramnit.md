# CyberDefenders - Ramnit (Memory Forensics) Write-up

**Challenge:** [Ramnit](https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Memory forensics, Volatility 3, Ramnit, endpoint forensics

---

## Summary

An IDS alert on user **alex**'s workstation pointed to post-compromise activity. Memory analysis shows a fake **`ChromeSetup.exe`** launched from **`Downloads`**, immediately attempting TCP to **`58.64.204.181:5202`** (Hong Kong). The in-memory binary (SHA1 **`280c9d36039f9432433893dee6126d72b9112ad2`**, compiled **2019-12-01**) enriches to **Ramnit** and domain **`dnsnb8.net`** — a banking trojan chain: user-run dropper → C2 beacon → credential-theft family.

---

## Scenario

Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis.

---

## Objectives

- Analyze the memory dump and trace malware actions from initial execution through C2.
- Produce process, path, network, and file IOCs suitable for blocking and enterprise-wide hunting.

---

## Environment

- **Artifact:** `memory.dmp` (lab package `159-Ramnit.zip`)
- **Victim context:** User profile **`alex`**, host **`192.168.19.133`**, activity around **2024-02-01 19:48 UTC**
- **Tools:** [Volatility 3](https://github.com/volatilityfoundation/volatility3), [VirusTotal](https://www.virustotal.com/), IP geolocation

```bash
vol -f memory.dmp -q "<plugin>"
```

---

## Investigation narrative

The IDS did not tell us *what* ran — only that something on the workstation behaved abnormally. With no live disk access, the memory dump is the timeline: running processes, open sockets, and file objects still resident in RAM. The investigation follows the malware's own sequence: **what executed → from where → who it called → what binary it is → what infrastructure it belongs to**.

---

### Phase 1 — Find the process that should not be there

**Story:** A legitimate Chrome install is signed, delivered through Google's update channel, and runs from **`Program Files`**. Anything named **`ChromeSetup.exe`** sitting in a user's **`Downloads`** folder and actively networking is a masquerade — a common Ramnit delivery pattern (fake browser installer).

**What I checked:** Process tree and command lines — look for installer names in user-writable paths.

```bash
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.cmdline --pid 4628
```

**Evidence:**

```text
PID 4628  ChromeSetup.ex  "C:\Users\alex\Downloads\ChromeSetup.exe"
Parent 4568 — spawned 2024-02-01 19:48:50 UTC
Image:  \Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe
```

**Reasoning:** **`alex`** likely double-clicked or ran a downloaded **`ChromeSetup.exe`**. That user execution created PID **4628**, which becomes the anchor for all later network and file analysis. The process name and path together identify the suspicious activity — not a system service, but a userland fake installer.

**Finding:** **`ChromeSetup.exe`** at **`C:\Users\alex\Downloads\ChromeSetup.exe`**

---

### Phase 2 — Follow the callback (C2 over the network)

**Story:** After execution, banking trojans typically beacon outward to receive modules or exfiltrate data. Whatever PID **4628** talks to on the public Internet is the command infrastructure for this infection.

**What I checked:** Network scan table filtered to the suspect process.

```bash
vol -f memory.dmp windows.netscan
```

**Evidence:**

| Local | Foreign | Port | State | PID | Owner |
|-------|---------|------|-------|-----|-------|
| 192.168.19.133:49682 | **58.64.204.181** | **5202** | CLOSED | 4628 | ChromeSetup.ex |
| 192.168.19.133:49682 | **58.64.204.181** | **5202** | SYN_SENT | 4628 | ChromeSetup.ex |

**Reasoning:** Both entries tie the **same PID** to **58.64.204.181** within one second of process start (**19:48:50** → **19:48:51 UTC**). **`SYN_SENT`** shows an active connection attempt; **`CLOSED`** shows a completed or torn-down session — consistent with a brief C2 handshake, not browsing traffic. Port **5202** is not a standard web port, which fits custom trojan protocols rather than HTTPS to a CDN. Internal RFC1918 **`192.168.19.133`** is the victim; **58.64.204.181** is external attacker infrastructure.

**Finding:** C2 IP **`58.64.204.181`**

---

### Phase 3 — Place the infrastructure geographically

**Story:** Knowing *where* the callback lands helps IR prioritize (regional hosting patterns, legal process, threat intel clusters) and gives context for whether **58.64.204.181** is bulletproof hosting or residential noise.

**What I checked:** Geolocation enrichment on **58.64.204.181**.

**Evidence:** WHOIS / geo databases associate **58.64.204.181** with **Hong Kong**.

**Reasoning:** The malware did not connect to a local subnet or corporate proxy — it reached offshore infrastructure immediately after launch. **Hong Kong** is the city tied to that C2 node in public geo data, matching the external pivot seen in **`netscan`**.

**Finding:** **`Hong Kong`**

---

### Phase 4 — Recover the binary from memory (prove what ran)

**Story:** Process name alone is spoofable; the IDS team and enterprise AV need a **hash** to hunt the same payload on other hosts. The executable bytes for PID **4628** are still mapped in memory as an **`ImageSectionObject`** — recoverable even if the file was deleted from disk after run.

**What I checked:** Dump in-memory file objects for the malicious PID.

```bash
vol -f memory.dmp -o . -q windows.dumpfiles --pid 4628
sha1sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe-1.img
```

**Evidence:**

```text
ImageSectionObject  ChromeSetup.exe → file....ChromeSetup.exe-1.img
SHA1: 280c9d36039f9432433893dee6126d72b9112ad2
```

**Reasoning:** Dumping from **`ImageSectionObject`** captures the PE as loaded, not just a data fragment. That SHA1 becomes the shared fingerprint for SOC tickets, SIEM hash alerts, and VT lookup — linking this workstation to the wider Ramnit corpus.

**Finding:** SHA1 **`280c9d36039f9432433893dee6126d72b9112ad2`**

---

### Phase 5 — Attribute the sample (family, age, DNS infrastructure)

**Story:** The hash closes the loop: confirm family, see how old the builder is, and pull domain IOCs that may outlive the IP (operators rotate IPs, reuse domains).

**What I checked:** VirusTotal on **`280c9d36039f9432433893dee6126d72b9112ad2`** — PE header, relations graph.

**Evidence:**

| Field | Value |
|-------|--------|
| **Malware family** | Ramnit (banking / modular trojan) |
| **Compilation timestamp** | **2019-12-01 08:36** UTC |
| **Contacted domain (Relations)** | **`dnsnb8.net`** (multi-vendor malicious) |
| **Infection vs build** | Built **2019**, executed **2024-02-01** — reused/staged payload |

**Reasoning:** A **2019** compile date on a **2024** infection means this is not a fresh bespoke attack — it is a recycled Ramnit binary still effective enough to pass as **`ChromeSetup.exe`**. VT's **Contacted Domains** shows **`dnsnb8.net`**, giving a DNS blocklist target alongside IP **58.64.204.181**. Together, IP + domain + hash describe the full C2 layer for containment.

**Findings:** Compile **`2019-12-01 08:36`** · Domain **`dnsnb8.net`**

---

## Attack timeline (reconstructed)

| Time (UTC) | Event |
|------------|--------|
| **2019-12-01 08:36** | Malware PE compiled (builder artifact) |
| **2024-02-01 ~19:48:50** | **`alex`** runs **`C:\Users\alex\Downloads\ChromeSetup.exe`** → PID **4628** |
| **2024-02-01 ~19:48:51** | Outbound TCP **58.64.204.181:5202** (SYN_SENT → CLOSED) |
| **Post-beacon** | Ramnit-style credential theft / module fetch (family behavior; **`dnsnb8.net`** in VT relations) |

```text
[alex] user execution
   ChromeSetup.exe (fake installer in Downloads)
        |
        v
   PID 4628 — masquerade, not real Google Chrome
        |
        +→ 58.64.204.181:5202  (Hong Kong)
        +→ dnsnb8.net          (VT domain relation)
        |
        v
   Ramnit — banking trojan / credential theft
```

---

## Lab answers (reference)

| # | Finding | Answer |
|---|---------|--------|
| 1 | Suspicious process | **`ChromeSetup.exe`** |
| 2 | Executable path | **`C:\Users\alex\Downloads\ChromeSetup.exe`** |
| 3 | C2 IP | **`58.64.204.181`** |
| 4 | C2 city | **`Hong Kong`** |
| 5 | SHA1 | **`280c9d36039f9432433893dee6126d72b9112ad2`** |
| 6 | Compile time | **`2019-12-01 08:36`** |
| 7 | Related domain | **`dnsnb8.net`** |

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **User / host** | `alex` @ `192.168.19.133` |
| **Process** | `ChromeSetup.exe` (PID 4628) |
| **Path** | `C:\Users\alex\Downloads\ChromeSetup.exe` |
| **C2 IP:port** | `58.64.204.181:5202` |
| **Geo** | Hong Kong |
| **SHA1** | `280c9d36039f9432433893dee6126d72b9112ad2` |
| **Compile time** | 2019-12-01 08:36 UTC |
| **Domain** | `dnsnb8.net` |
| **Family** | Ramnit |

---

## MITRE ATT&CK

| Technique | Name | In this incident |
|-----------|------|------------------|
| **T1204.002** | User Execution: Malicious File | `alex` runs fake installer from Downloads |
| **T1036.005** | Masquerading | Name **`ChromeSetup.exe`** imitates Google Chrome |
| **T1071** | Application Layer Protocol | Custom TCP **5202** to **58.64.204.181** |
| **T1555** | Credentials from Password Stores | Ramnit family objective |
| **T1105** | Ingress Tool Transfer | Secondary modules typical post-beacon |

---

## Mitigation / Hardening

- Block **`58.64.204.181`** and **`dnsnb8.net`** at firewall/DNS.
- Hunt **`ChromeSetup.exe`** outside official Google install paths; alert SHA1 **`280c9d36039f9432433893dee6126d72b9112ad2`**.
- Restrict execution from **`Downloads`** via AppLocker/WDAC where feasible.
- User training: Chrome updates come from **google.com**, not random **`ChromeSetup.exe`** attachments.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/ramnit/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Ramnit: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Ramnit
