# CyberDefenders - Lockdown (PCAP + Memory + Malware) Write-up

**Challenge:** [Lockdown](https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, memory forensics, web shell, malware analysis

---

## Summary

TechNova’s public **IIS** server (**`10.0.2.15`**) was probed by **`10.0.2.4`** using **Nmap**, then accessed over **SMB** (`\\10.0.2.15\Documents`, `\\10.0.2.15\IPC$`). The attacker uploaded **`shell.aspx`**, established a reverse shell on port **`4443`**, and **`w3wp.exe`** (PID **4332**) spawned persistence binary **`updatenow.exe`** in the Startup folder. The recovered sample is **UPX**-packed **AgentTesla** beaconing to **`cp8nl.hyperhost.ua`**.

---

## Scenario

TechNova Systems’ SOC has detected suspicious outbound traffic from a public-facing IIS server in its cloud platform—activity suggestive of a web-shell drop and covert connections to an unknown host.

As the forensic examiner, you have three critical artefacts in hand: a PCAP capturing the initial traffic, a full memory image of the server, and a malware sample recovered from disk. Reconstruct the intrusion and all of the attacker’s activities so TechNova can contain the breach and strengthen its defenses.

---

## Objectives

- Trace reconnaissance, SMB abuse, and web-shell upload in the PCAP.
- Analyze the memory dump with Volatility 3 for kernel context, persistence, and process parentage.
- Profile the malware sample (packer, C2, family) via VirusTotal and MalwareBazaar.

---

## Environment

- **Artifacts:** PCAP (initial traffic), `memdump.mem` (Windows Server memory image), malware executable from disk
- **Victim IIS host:** **`10.0.2.15`**
- **Attacker:** **`10.0.2.4`**
- **Tools:** Wireshark, [Volatility 3](https://github.com/volatilityfoundation/volatility3), VirusTotal, MalwareBazaar

**Useful Wireshark filters:**

```text
nmap
http.user_agent contains "Nmap"
smb2
smb2.tree
smb2.filename contains "shell"
ip.addr == 10.0.2.4 && tcp.port == 4443
```

**Volatility 3 commands:**

```text
vol -f memdump.mem -q windows.info
vol -f memdump.mem -q windows.cmdline
vol -f memdump.mem -q windows.pstree
```

---

## Evidence & Findings

### PCAP analysis

#### T1 — Reconnaissance source IP

**Question:** After flooding the IIS host with rapid-fire probes, the attacker reveals their origin. Which IP address generated this reconnaissance traffic?

- **What I checked:** Wireshark search for **`nmap`**; HTTP User-Agent strings indicating scanning tools.
- **Evidence:** Traffic with User-Agent **`Nmap Scripting Engine`** sourced from **`10.0.2.4`** toward the IIS host.
- **Reasoning:** Nmap Scripting Engine (NSE) in HTTP headers identifies the scanner origin IP during the reconnaissance phase.

**Answer:** **`10.0.2.4`**

---

#### T2 — HTTP enumeration tool

**Question:** The attacker is carrying out targeted enumeration against the HTTP service on the IIS host. Based on the HTTP request headers, which tool is being used?

- **What I checked:** HTTP request headers from **`10.0.2.4`**; User-Agent and scanner fingerprints.
- **Evidence:** User-Agent **`Nmap Scripting Engine`** — consistent with **Nmap** HTTP/script scanning.
- **Reasoning:** Same recon traffic as T1; the tool name in lab context is the scanner itself.

**Answer:** **`nmap`**

---

#### T3 — First SMB shares probed (UNC paths)

**Question:** While reviewing the SMB traffic, you observe two consecutive Tree Connect requests that expose the first shares the intruder probes on the IIS host. Which two full UNC paths are accessed?

- **What I checked:** Filter **`smb2`**; **SMB2 Tree Connect Request** packets in order.
- **Evidence:** Tree Connect requests at packets **2672** and **2678**:
  - **`\\10.0.2.15\Documents`**
  - **`\\10.0.2.15\IPC$`**
- **Reasoning:** First two share mounts after SMB session setup show initial lateral/file-access targets on the IIS server.

**Answer:** **`\\10.0.2.15\Documents`**, **`\\10.0.2.15\IPC$`**

---

#### T4 — Malicious uploaded filename

**Question:** Inside the share, the attacker plants a web-accessible payload that will grant remote code execution. What is the filename of the malicious file they uploaded?

- **What I checked:** SMB2 **Write Request** / **Create Request** after share access; filter for web-shell extensions.
- **Evidence:** Write Request creates **`shell.aspx`**. **Follow TCP Stream** from packet **3505** shows ASPX content importing **`kernel32`** (typical web-shell / RCE pattern).
- **Reasoning:** `.aspx` dropped into a web-accessible share on an IIS server enables remote code execution via the web stack.

**Answer:** **`shell.aspx`**

---

#### T5 — Reverse shell listener port

**Question:** The newly planted shell calls back to the attacker over an uncommon but firewall-friendly port. Which listening port did the attacker use for the reverse shell?

- **What I checked:** Post-upload traffic from victim **`10.0.2.15`** to attacker **`10.0.2.4`**; unusual TCP destination ports.
- **Evidence:** Sustained TCP sessions on port **`4443`** after shell deployment.
- **Reasoning:** High-volume callback traffic on a non-standard port (not 80/443) indicates the reverse-shell C2 listener.

**Answer:** **`4443`**

---

### Memory dump analysis

#### T6 — Kernel base address

**Question:** Your memory snapshot captures the system’s kernel in situ, providing vital context for the breach. What is the kernel base address in the dump?

- **What I checked:** Volatility 3 **`windows.info`** plugin.
- **Evidence:**

  ```text
  vol -f memdump.mem -q windows.info

  Kernel Base     0xf80079213000
  SystemTime      2024-09-10 06:14:13+00:00
  NtSystemRoot    C:\Windows
  NtProductType   NtProductServer
  Major/Minor     15.17763
  ```

- **Reasoning:** **`windows.info`** reports the virtual address where the Windows kernel is loaded — baseline for kernel forensics and symbol resolution.

**Answer:** **`0xf80079213000`**

---

#### T7 — Persistence executable path

**Question:** A trusted service launches an unfamiliar executable residing outside the usual IIS stack, signalling a persistence implant. What is the final full on-disk path of that executable?

- **What I checked:** Volatility 3 **`windows.cmdline`** for suspicious command lines; Startup folder paths.
- **Evidence:**

  ```text
  vol -f memdump.mem -q windows.cmdline

  900   updatenow.exe   "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe"
  ```

- **Reasoning:** The **Startup** folder is a common persistence location (MITRE **T1547**). IIS services do not normally launch executables from user Startup paths — indicates post-exploitation implant.

**Answer:** **`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe`**

---

#### T8 — Parent process and PID (reverse shell handler)

**Question:** The reverse shell’s outbound traffic is handled by a built-in Windows process that also spawns the implanted executable. What is the name of this process, and what PID does it run under?

- **What I checked:** Volatility 3 **`windows.pstree`** — parent/child relationships for **`updatenow.exe`**.
- **Evidence:**

  ```text
  vol -f memdump.mem -q windows.pstree

  *** 4332   2452   w3wp.exe        ...  \Device\HarddiskVolume1\Windows\System32\inetsrv\w3wp.exe
  **** 900   4332   updatenow.exe   ...  \Device\HarddiskVolume1\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\updatenow.exe
  ```

- **Reasoning:** **`w3wp.exe`** is the IIS worker process — it executed the web shell, which spawned **`updatenow.exe`**. PID **4332** is the parent handling outbound shell traffic context.

**Answer:** **`w3wp.exe`**, **`4332`**

---

### Malware sample analysis

#### T9 — Packer

**Question:** Static inspection reveals the binary has been packed to hinder analysis. Which packer was used to obfuscate it?

- **What I checked:** VirusTotal upload — **Details** tab / packer detection.
- **Evidence:** Sample flagged as compressed/packed by **UPX**.
- **Reasoning:** UPX is a common packer used to shrink binaries and evade static signature matching.

**Answer:** **`UPX`**

---

#### T10 — C2 FQDN

**Question:** Threat-intel analysis shows the malware beaconing to its command-and-control host. Which fully qualified domain name (FQDN) does it contact?

- **What I checked:** VirusTotal **Behavior → IP Traffic** / network connections.
- **Evidence:** Outbound connection **`TCP 185.174.175.187:587`** associated with FQDN **`cp8nl.hyperhost.ua`**.
- **Reasoning:** SMTP port **587** is a typical AgentTesla exfil/C2 channel; FQDN is the C2 hostname to block.

**Answer:** **`cp8nl.hyperhost.ua`**

---

#### T11 — Malware family

**Question:** Open-source intel associates that hash with a well-known commodity RAT. To which malware family does the sample belong?

- **What I checked:** MalwareBazaar lookup by SHA256 hash.
- **Evidence:**

  ```text
  SHA256: c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
  ```

  MalwareBazaar category: **AgentTesla**

- **Reasoning:** Hash matches public intel for **Agent Tesla** — commodity .NET infostealer/RAT often delivered via phishing and web shells.

**Answer:** **`AgentTesla`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Attacker IP** | `10.0.2.4` |
| **Victim IIS** | `10.0.2.15` |
| **Web shell** | `shell.aspx` |
| **Reverse shell port** | `4443` |
| **Persistence binary** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| **Parent process** | `w3wp.exe` (PID **4332**) |
| **C2 FQDN** | `cp8nl.hyperhost.ua` |
| **C2 IP:port** | `185.174.175.187:587` |
| **Malware SHA256** | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` |
| **Packer** | UPX |
| **Family** | AgentTesla |

---

## Attack reconstruction

```text
[10.0.2.4 — attacker]
    |
    +→ Nmap recon (HTTP User-Agent: Nmap Scripting Engine)
    +→ SMB Tree Connect: \\10.0.2.15\Documents, \\10.0.2.15\IPC$
    +→ Upload shell.aspx (web RCE)
    +→ Reverse shell callback → attacker:4443
    |
    v
[10.0.2.15 — IIS server]
    w3wp.exe (4332) spawns updatenow.exe
    → Startup folder persistence (updatenow.exe)
    → AgentTesla (UPX) → cp8nl.hyperhost.ua:587
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1046** | Network Service Discovery | Nmap recon (T1–T2) |
| **T1190** | Exploit Public-Facing Application | IIS / web shell (T4) |
| **T1505.003** | Server Software Component: Web Shell | `shell.aspx` (T4) |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | SMB shares (T3) |
| **T1547.001** | Boot or Logon Autostart Execution: Startup Folder | `updatenow.exe` (T7) |
| **T1059** | Command and Scripting Interpreter | Web shell execution |
| **T1071.001** | Application Layer Protocol: Web Protocols | HTTP C2 / exfil |
| **T1027.002** | Obfuscated Files: Software Packing | UPX (T9) |
| **T1071** | Application Layer Protocol | Reverse shell :4443 (T5) |

---

## Mitigation / hardening

1. **Disable or restrict SMB** on internet-facing IIS hosts; require auth and least-privilege share ACLs.
2. **Block egress** to **`cp8nl.hyperhost.ua`** and **`185.174.175.187`**; alert on non-standard outbound **4443**.
3. **Remove** `shell.aspx`; rotate credentials; inspect Startup folders and IIS app pools.
4. **EDR rules:** `w3wp.exe` spawning non-Microsoft binaries; Startup folder writes from web processes.
5. **Harden IIS:** disable unnecessary handlers, WAF for `.aspx` uploads, file-integrity monitoring on web roots and shares.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/lockdown/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- MalwareBazaar: https://bazaar.abuse.ch/
- MITRE T1547.001: https://attack.mitre.org/techniques/T1547/001/
- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
