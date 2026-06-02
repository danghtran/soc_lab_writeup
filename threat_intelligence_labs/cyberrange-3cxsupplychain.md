# CyberDefenders - 3CX Supply Chain (Threat Intel) Write-up

**Challenge:** [3CX Supply Chain](https://cyberdefenders.org/blueteam-ctf-challenges/3cx-supply-chain/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, supply chain, VirusTotal, SmoothOperator, Lazarus

---

## Summary

After a **3CX Desktop App** update, AV flagged sporadic wipes and odd egress. Investigation of the trojanized **MSI** (campaign **SmoothOperator**, **CVE-2023-29059**) shows **two** malicious Windows builds (**18.12.416**, **18.12.407**), side-loaded **`ffmpeg.dll`** and **`d3dcompiler_47.dll`** (**T1574**), **RC4**-encrypted payloads, **VMware** sandbox checks (**T1497**), and attribution to **Lazarus Group** (**LABYRINTH CHOLLIMA** / DPRK) with second-stage **ICONIC Stealer**.

---

## Scenario

A large multinational corporation heavily relies on the 3CX software for phone communication, making it a critical component of their business operations. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Dismissing this as a false positive, the IT team overlooks the alerts, only to notice degraded performance and strange network traffic to unknown servers.

---

## Objectives

- Uncover how attackers compromised the 3CX app.
- Identify the threat actor and assess incident scope.
- Extract IOCs, MITRE mappings, and DLL/persistence behavior from the malicious **MSI** and dropped files.

---

## Environment

- **Artifacts:** Malformed/trojanized **3CX Desktop App** `.msi` (lab package); hashes for dropped DLLs
- **Tools used:**
  - [VirusTotal](https://www.virustotal.com/) — behavior, MITRE graph, dropped files, detections
  - OSINT — [Trend Micro 3CX advisory](https://www.trendmicro.com/en_us/research/23/c/information-on-attacks-involving-3cx-desktop-app.html), CrowdStrike, Mandiant reporting

---

## Evidence & Findings

### T1 — Flagged Windows 3CX versions

**Question:** How many versions of 3CX running on Windows have been flagged as malware?

- **What I checked:** Public reporting on the March 2023 **3CX supply chain** incident (Trend Micro, 3CX/Huntress notifications).
- **Evidence:** **Two** trojanized **Windows** desktop builds: **18.12.416** and **18.12.407** (signed with legitimate 3CX certificates).
- **Reasoning:** Scope assessment for enterprise patch/uninstall decisions — only these builds are confirmed backdoored on Windows.

**Answer:** **`2`**

---

### T2 — MSI creation time (UTC)

**Question:** What's the UTC creation time of the .msi malware?

- **What I checked:** Upload lab **MSI** to VirusTotal → **Details** → **History** → **Creation Time**.
- **Evidence:** **`2023-03-13 06:33`** UTC.
- **Reasoning:** Creation timestamp helps timeline the build-chain compromise vs. public discovery (late March 2023).

**Answer:** **`2023-03-13 06:33`**

---

### T3 — Malicious DLLs dropped by MSI

**Question:** Which malicious DLLs were dropped by the .msi file?

- **What I checked:** VirusTotal → **Behavior** → **Files Dropped**; per-DLL SHA256 lookups on VT.
- **Evidence:**

  | DLL | SHA256 (dropped) | VT verdict |
  |-----|------------------|------------|
  | d3dcompiler_47.dll | `11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03` | Malicious |
  | **ffmpeg.dll** | `7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896` | Malicious |
  | libEGL.dll | `44febbc02e69d492d39e2cd5d025bbf0d81b1889b37725bd700cc0c21e5ba22a` | Benign (legitimate names) |
  | libGLESv2.dll | `7897eb2441975523e3e78dbeabf2d9deba66534c69b6cefbf87ea638ee641ea6` | Benign |
  | vk_swiftshader.dll | `18436e3ffaa5ad29f0fa0daba05cfd99ad6ae2ccc7d6a5bff9d4decd97c0993e` | Benign |
  | vulkan-1.dll | `1c7fe50af9f2c7722274ee55c28bc1e786effbed15943909d8da8f3492275574` | Benign |

- **Reasoning:** Attackers bundle trojanized DLLs beside legitimate Electron/graphics DLLs; only **`ffmpeg.dll`** and **`d3dcompiler_47.dll`** are flagged malicious — they side-load shellcode and stage **ICONIC Stealer**.

**Answer:** **`ffmpeg.dll, d3dcompiler_47.dll`** (lab may accept comma-separated or space-separated)

---

### T4 — MITRE technique (load malicious DLL)

**Question:** What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?

- **What I checked:** VirusTotal **Behavior** → **MITRE ATT&CK** graph — **Execution** phase.
- **Evidence:** **DLL side-loading** under **Hijack Execution Flow** → **T1574** (sub-technique **T1574.002** DLL Side-Loading).
- **Reasoning:** Trojanized installer places malicious DLLs where **`3CXDesktopApp.exe`** loads them instead of legitimate libraries.

**Answer:** **`T1574`**

---

### T5 — Threat category of malicious DLLs

**Question:** What is the threat category of the two malicious DLLs?

- **What I checked:** VirusTotal **Detection** tab for **`ffmpeg.dll`** and **`d3dcompiler_47.dll`** hashes.
- **Evidence:** Multiple vendors classify both as **Trojan** (e.g., trojanized library / dropper behavior).
- **Reasoning:** Lab asks for category (not family name) — aligns with Microsoft/vendor **trojan** classification.

**Answer:** **`trojan`**

---

### T6 — Virtualization/sandbox evasion MITRE ID

**Question:** What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

- **What I checked:** VT **Behavior** → MITRE **Discovery** — **Virtualization/Sandbox Evasion**.
- **Evidence:** **Dynamic sleep** and environment checks → **T1497 — Virtualization/Sandbox Evasion**.
- **Reasoning:** Malware delays execution and probes analysis environments before decrypting payloads.

**Answer:** **`T1497`**

---

### T7 — Hypervisor targeted (ffmpeg.dll)

**Question:** Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?

- **What I checked:** VirusTotal behavior/MITRE details for **`ffmpeg.dll`** hash — **Stealth** / evasion descriptions.
- **Evidence:** **System checks** targeting **VMware** guest artifacts (registry/files/process indicators).
- **Reasoning:** Specific hypervisor fingerprinting narrows sandbox evasion vs. generic sleep-only behavior.

**Answer:** **`VMware`**

---

### T8 — Encryption algorithm (ffmpeg.dll)

**Question:** What encryption algorithm is used by the ffmpeg.dll file?

- **What I checked:** VT **Behavior** — **Obfuscated Files or Information** / encryption notes on **`ffmpeg.dll`**.
- **Evidence:** Payload/data encrypted with **RC4** (**KSA** + **PRGA** stages).
- **Reasoning:** RC4 decrypts C2 URLs/shellcode before second-stage download (**ICONIC Stealer**).

**Answer:** **`RC4`**

---

### T9 — Responsible APT group

**Question:** Which group is responsible for this attack?

- **What I checked:** CrowdStrike reporting (campaign **SmoothOperator**); Qualys/Mandiant; MITRE threat actor overlap.
- **Evidence:**
  - CrowdStrike: **LABYRINTH CHOLLIMA** (DPRK nexus) with high confidence on beacon structure.
  - Widely tracked as **Lazarus Group** (also **Hidden Cobra**, **ZINC**); MITRE **G0032**.
  - Double supply chain: compromised **X_TRADER** → 3CX build environment (Mandiant).

- **Reasoning:** Lab expects the overarching APT name used in industry reporting; CrowdStrike cluster maps to **Lazarus Group**.

**Answer:** **`Lazarus Group`** (alternates accepted by some platforms: **`Lazarus`**, **`Labyrinth Chollima`**)

---

## Attack Reconstruction (SmoothOperator)

```text
[Upstream] Trojanized X_TRADER on 3CX engineer laptop
        |
        v
3CX build pipeline compromised (signed MSI: 18.12.407 / 18.12.416)
        |
        v
Victim installs 3CXDesktopApp.msi (legitimate cert, malicious payload)
        |
        +→ DLL side-load: ffmpeg.dll + d3dcompiler_47.dll (T1574)
        +→ RC4 decrypt shellcode / C2 URLs
        +→ Sandbox evasion: VMware checks, dynamic sleep (T1497)
        |
        v
Second stage: ICONIC Stealer (GitHub-hosted ICO/shellcode chain) — selective targets
```

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Campaign** | SmoothOperator |
| **CVE** | CVE-2023-29059 |
| **Affected versions** | 3CX Desktop App **18.12.407**, **18.12.416** (Windows) |
| **MSI creation (lab sample)** | 2023-03-13 06:33 UTC |
| **Malicious DLLs** | `ffmpeg.dll`, `d3dcompiler_47.dll` |
| **Second stage** | ICONIC Stealer / SUDDENICON |
| **Threat actor** | Lazarus Group (LABYRINTH CHOLLIMA) |

---

## MITRE ATT&CK (summary)

| Technique | Name |
|-----------|------|
| **T1195.002** | Supply Chain Compromise: Software Supply Chain |
| **T1574.002** | Hijack Execution Flow: DLL Side-Loading |
| **T1497** | Virtualization/Sandbox Evasion |
| **T1027** | Obfuscated Files or Information (RC4) |
| **T1071** | Application Layer Protocol (HTTPS C2) |
| **T1555** | Credentials from Password Stores (ICONIC Stealer) |

---

## Mitigation / Hardening

- Remove **18.12.407** and **18.12.416**; reinstall from known-good 3CX builds per vendor guidance.
- Hunt for trojanized **`ffmpeg.dll`** / **`d3dcompiler_47.dll`** beside 3CX install paths.
- Block known **SmoothOperator** C2/GitHub staging IOCs from threat intel feeds.
- Monitor DLL loads from **`3CXDesktopApp.exe`** (EDR, Sysmon Event ID 7).
- Treat signed updates skeptically after supply-chain incidents — verify version, hash, and vendor advisories.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/3cx-supply-chain/
- Trend Micro — 3CX Desktop App attacks: https://www.trendmicro.com/en_us/research/23/c/information-on-attacks-involving-3cx-desktop-app.html
- CrowdStrike — LABYRINTH CHOLLIMA / 3CX: https://www.crowdstrike.com/blog/crowdstrike-detects-and-prevents-active-intrusion-campaign-targeting-3cxdesktopapp-customers/
- MITRE G0032 Lazarus Group: https://attack.mitre.org/groups/G0032/
