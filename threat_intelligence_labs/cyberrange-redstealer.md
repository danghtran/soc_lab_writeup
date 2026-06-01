# CyberDefenders - Red Stealer (Threat Intel) Write-up

**Challenge:** [Red Stealer](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, VirusTotal, RedLine Stealer, infostealer

---

## Summary

A suspicious executable on a colleague’s workstation is suspected of **C2** communication. Hash analysis on **VirusTotal**, **MalwareBazaar**, and **ThreatFox** identifies **RedLine Stealer** (`Trojan:Win32/Redline!rfn`), commonly submitted as **`Wextract`**, with collection behavior **T1005**, DNS to **`facebook.com`**, C2 **`77.91.124.55:19071`**, YARA rule **`detect_Redline_Stealer`** (Varp0s), ThreatFox alias **`RECORDSTEALER`**, and privilege escalation via **`ADVAPI32.dll`** (`AdjustTokenPrivileges`).

---

## Scenario

You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection.

---

## Objectives

- Investigate the executable by analyzing its hash.
- Produce IOCs, MITRE mappings, and enrichment for IR and network defense (firewall blocks, DLL monitoring).

---

## Environment

- **Artifact:** File hash provided in lab package (`hash.txt` / challenge ZIP)
- **Tools used:**
  - [VirusTotal](https://www.virustotal.com/) — detections, details, behavior, imports
  - [MalwareBazaar](https://bazaar.abuse.ch/) — YARA rules
  - [ThreatFox](https://threatfox.abuse.ch/) — malware aliases for C2 IP

---

## Evidence & Findings

### T1 — Microsoft malware category (VirusTotal)

**Question:** What category has Microsoft identified for that malware in VirusTotal?

- **What I checked:** VirusTotal → **Detection** tab → **Microsoft** engine result.
- **Evidence:** **`Trojan:Win32/Redline!rfn`** — family name **Redline**; Microsoft classifies the sample under the **Trojan** category.
- **Reasoning:** VT lab answer is the high-level **category** (not the full detection string).

**Answer:** **`trojan`**

---

### T2 — Associated file name

**Question:** What is the file name associated with this malware?

- **What I checked:** VirusTotal → **Details** tab → **Names** (community submission names).
- **Evidence:** Multiple submitters report the sample as **`Wextract`** (masquerades as a Windows extractor utility).
- **Reasoning:** **Names** reflects how the file appeared on victim systems — critical for host-based hunting.

**Answer:** **`Wextract`**

---

### T3 — First VirusTotal submission (UTC)

**Question:** What is the UTC timestamp of the malware's first submission to VirusTotal?

- **What I checked:** VirusTotal → **Details** → **History** → **First Submission**.
- **Evidence:** **`2023-10-06 04:41`** UTC (some VT views show seconds: `04:41:50`).
- **Reasoning:** First submission time drives containment priority for newly seen threats.

**Answer:** **`2023-10-06 04:41`**

---

### T4 — MITRE technique (data collection)

**Question:** What is the MITRE ATT&CK technique ID for the malware's data collection from the system before exfiltration?

- **What I checked:** VirusTotal → **Behavior** tab → **MITRE ATT&CK Tactics and Techniques**.
- **Evidence:** Under **Collection** — collects data from the local system (browser credentials, files, etc.) mapped to **T1005 — Data from Local System**.
- **Reasoning:** RedLine Stealer harvests local data before exfiltration to C2 — classic infostealer collection phase.

**Answer:** **`T1005`**

---

### T5 — Social media-related DNS domain

**Question:** Following execution, which social media-related domain names did the malware resolve via DNS queries?

- **What I checked:** VirusTotal → **Behavior** → **DNS Resolutions**.
- **Evidence:** Resolutions include **`facebook.com`** (and related FB CDN names in IP traffic); lab expects the primary social domain used for disguise/blending.
- **Reasoning:** Malware often resolves legitimate social domains to blend with normal user traffic or support lure pages.

**Answer:** **`facebook.com`**

---

### T6 — Malicious IP and destination port

**Question:** Can you provide the IP address and destination port the malware communicates with?

- **What I checked:** VirusTotal → **Behavior** → **IP Traffic**.
- **Evidence:**

  | Protocol | Endpoint | Notes |
  |----------|----------|--------|
  | **TCP** | **`77.91.124.55:19071`** | Non-standard port — **C2** |
  | TCP | `57.144.198.1:443` | www.facebook.com |
  | TCP | `13.107.6.158:443` | business.bing.com |
  | TCP/UDP | `157.240.229.x:443` | Facebook CDN (static.xx.fbcdn.net, fbsbx.com) |

- **Reasoning:** Legitimate HTTPS to Facebook/Bing/CDN vs. **`77.91.124.55:19071`** — uncommon port, no major provider hostname → blocklist for IR/firewall.

**Answer:** **`77.91.124.55:19071`**

---

### T7 — MalwareBazaar YARA rule (Varp0s)

**Question:** Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?

- **What I checked:** [MalwareBazaar](https://bazaar.abuse.ch/) — search lab hash → **YARA** tab; filter author **Varp0s**.
- **Evidence:** Rule name **`detect_Redline_Stealer`** matches RedLine Stealer patterns.
- **Reasoning:** YARA enables detection in sandboxes, email gateways, and disk scans beyond AV signatures.

**Answer:** **`detect_Redline_Stealer`**

---

### T8 — ThreatFox malware alias

**Question:** Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?

- **What I checked:** [ThreatFox](https://threatfox.abuse.ch/) — search **`ioc:77.91.124.55`** or browse **RedLine Stealer** entries linked to the C2.
- **Evidence:** IOC record lists malware alias **`RECORDSTEALER`** (alongside RedLine Stealer family tagging).
- **Reasoning:** Aliases help correlate the same infrastructure across campaigns and reporting names.

**Answer:** **`RECORDSTEALER`**

---

### T9 — DLL for privilege escalation

**Question:** Can you provide the DLL utilized by the malware for privilege escalation?

- **What I checked:** VirusTotal → **Details** → **PE** → **Imports**.
- **Evidence:**

  | DLL | Relevant APIs (privilege escalation) |
  |-----|--------------------------------------|
  | **`ADVAPI32.dll`** | `AdjustTokenPrivileges`, token/security APIs |
  | KERNEL32.dll | Process/thread |
  | USER32.dll / GDI32.dll | UI |
  | msvcrt.dll, COMCTL32.dll, Cabinet.dll, VERSION.dll | Support |

- **Reasoning:** **`ADVAPI32.dll`** provides Windows security APIs; **`AdjustTokenPrivileges`** is commonly abused to enable privileges (e.g., **SeDebugPrivilege**) — maps to **T1134** / privilege escalation tactics.

**Answer:** **`ADVAPI32.dll`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Malware family** | RedLine Stealer (`Trojan:Win32/Redline!rfn`) |
| **Common filename** | `Wextract` |
| **First VT submission** | 2023-10-06 04:41 UTC |
| **C2** | `77.91.124.55:19071` (TCP) |
| **DNS (social)** | `facebook.com` |
| **ThreatFox alias** | `RECORDSTEALER` |
| **YARA (Varp0s)** | `detect_Redline_Stealer` |
| **Priv esc DLL** | `ADVAPI32.dll` |

---

## Attack Reconstruction

1. User executes **`Wextract`** (RedLine Stealer payload).
2. Sample elevates privileges via **`ADVAPI32.dll`** APIs.
3. **Collection (T1005)** — local browser credentials, wallets, session tokens.
4. DNS resolutions include **`facebook.com`** (traffic blending / lure infrastructure).
5. **Exfiltration / C2** over **`77.91.124.55:19071`**.
6. Hunt with **`detect_Redline_Stealer`**; enrich C2 on ThreatFox as **`RECORDSTEALER`**.

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| **T1005** | Data from Local System |
| **T1071** | Application Layer Protocol (C2 comms) |
| **T1134** | Access Token Manipulation (via `AdjustTokenPrivileges`) |
| **T1555** | Credentials from Password Stores (RedLine behavior) |
| **T1041** | Exfiltration Over C2 Channel |

---

## Mitigation / Hardening

- Block **`77.91.124.55`** egress (TCP **19071** and related ports) at firewall/proxy.
- Hunt for **`Wextract`** and RedLine YARA **`detect_Redline_Stealer`** on endpoints.
- Monitor loading of **`ADVAPI32.dll`** with suspicious **`AdjustTokenPrivileges`** call chains (EDR).
- Reset credentials for users on affected hosts; check stealer markets for leaked org data.
- User awareness: RedLine often spreads via cracked software, fake updates, and phishing.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/
- VirusTotal: https://www.virustotal.com/
- MalwareBazaar: https://bazaar.abuse.ch/
- ThreatFox: https://threatfox.abuse.ch/
- Microsoft — RedLine Stealer: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FRedLineStealer.PP%21MTB
