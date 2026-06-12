# CyberDefenders - IcedID (Threat Intel) Write-up

**Challenge:** [IcedID](https://cyberdefenders.org/blueteam-ctf-challenges/icedid/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, VirusTotal, IcedID, banking malware

---

## Summary

An APT-linked phishing campaign distributes **IcedID** via macro-enabled **`document-1982481273.xlsm`**. The Excel macro uses **`URLDownloadToFileA`** to fetch second-stage **`3003.gif`** (a disguised PE/DLL) from **5** redundant domains, predominantly registered through **NameCheap**. [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) attributes the campaign to **Gold Cabin** (also tracked as **TA551** / **Shathak**).

---

## Scenario

A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID.

You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

---

## Objectives

- Enrich the provided sample hash on VirusTotal and threat-intel platforms.
- Extract delivery filenames, staging URLs, infrastructure, threat-actor attribution, and execution APIs.

---

## Environment

- **Artifact:** SHA-1 hash in lab `hash.txt` — **`191eda0c539d284b29efe556abb05cd75a9077a0`**
- **Tools:**
  - [VirusTotal](https://www.virustotal.com/) — names, relations, behavior, MITRE mapping
  - [MalwareBazaar](https://bazaar.abuse.ch/) — malware family tags
  - [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) — family ↔ threat-actor mapping
  - Optional: [Tria.ge](https://tria.ge/), ANY.RUN (lab-recommended)

---

## Evidence & Findings

### T1 — Associated filename

**Question:** What is the name of the file associated with the given hash?

- **What I checked:** VirusTotal → **Details** → **Names** for hash **`191eda0c539d284b29efe556abb05cd75a9077a0`**.
- **Evidence:** Primary submission name **`document-1982481273.xlsm`** — Excel macro-enabled workbook (`.xlsm`).
- **Reasoning:** IcedID is commonly delivered through malicious Office macros; the filename mimics a benign document lure.

**Answer:** **`document-1982481273.xlsm`**

---

### T2 — Deployed GIF filename

**Question:** Can you identify the filename of the GIF file that was deployed?

- **What I checked:** VirusTotal → **Relations** → **Contacted URLs**; **Behavior** → HTTP requests.
- **Evidence:** Multiple **`GET`** requests fetch the same path across staging domains:

  ```text
  .../ds/3003.gif
  ```

  Despite the **`.gif`** extension, sandbox analysis identifies the payload as a **PE/DLL** (masquerading evasion).

- **Reasoning:** IcedID stage-1 macros download a second-stage binary disguised as an image file to bypass simple extension filters.

**Answer:** **`3003.gif`**

---

### T3 — Staging domain count

**Question:** How many domains does the malware look to download the additional payload file in Q2?

- **What I checked:** **Contacted URLs** hosting **`3003.gif`** — unique domains.
- **Evidence:** Five distinct domains requested the same GIF payload:

  | Domain |
  |--------|
  | `agenbolatermurah.com` |
  | `tajushariya.com` |
  | `columbia.aula-web.net` |
  | `metaflip.io` |
  | `partsapp.com.br` |

  Example requests:

  ```text
  GET https://agenbolatermurah.com:443/ds/3003.gif
  GET https://tajushariya.com/ds/3003.gif
  GET https://columbia.aula-web.net/ds/3003.gif
  GET https://metaflip.io/ds/3003.gif
  GET https://partsapp.com.br/ds/3003.gif
  ```

- **Reasoning:** Redundant staging hosts provide resilience if one domain is sinkholed or blocked.

**Answer:** **`5`**

---

### T4 — Predominant DNS registrar

**Question:** From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content. Can you specify the Registrar INC?

- **What I checked:** VirusTotal → **Relations** → **Contacted Domains** — registrar field per domain.
- **Evidence:** **`tajushariya.com`** (and related staging domains) registered via **`NameCheap, Inc.`** (VT shows **NameCheap, Inc.** on contacted-domain metadata dated **2022-07-30**).
- **Reasoning:** Registrar concentration supports proactive blocking and registration-pattern hunting for Gold Cabin / TA551 infrastructure.

**Answer:** **`NameCheap`**

---

### T5 — Threat actor

**Question:** Could you specify the threat actor linked to the sample provided?

- **What I checked:** MalwareBazaar hash lookup → family **IcedID**; Malpedia entry for IcedID / associated actors.
- **Evidence:** Malpedia maps IcedID distribution (this campaign pattern) to threat actor **Gold Cabin** (MITRE also references **TA551** / **Shathak** for similar IcedID phishing).
- **Reasoning:** Family alone is not enough for CTI — actor attribution drives hunt rules and campaign tracking.

**Answer:** **`Gold Cabin`**

---

### T6 — Payload download API (Execution)

**Question:** In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?

- **What I checked:** VirusTotal → **Behavior** → MITRE **Execution**; macro import / sandbox API traces.
- **Evidence:**

  ```text
  Exploitation for Client Execution
  \KnownDlls\WININET.dll
  origin: URLDownloadToFileA
  ```

  The malicious **`.xlsm`** VBA macro imports **`URLDownloadToFileA`** from **WININET** to download **`3003.gif`** in one call (network fetch + local write).

- **Reasoning:** [T1203 — Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/) via Office macros; **`URLDownloadToFileA`** is the specific WinINet API used for stage-2 retrieval.

**Answer:** **`URLDownloadToFileA`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **SHA-1** | `191eda0c539d284b29efe556abb05cd75a9077a0` |
| **Delivery file** | `document-1982481273.xlsm` |
| **Stage-2 (disguised)** | `3003.gif` (PE/DLL) |
| **Staging path** | `/ds/3003.gif` |
| **Domains** | `agenbolatermurah.com`, `tajushariya.com`, `columbia.aula-web.net`, `metaflip.io`, `partsapp.com.br` |
| **Registrar** | NameCheap, Inc. |
| **Malware family** | IcedID (BokBot) — [S0483](https://attack.mitre.org/software/S0483/) |
| **Threat actor** | Gold Cabin (TA551 / Shathak) |
| **Download API** | `URLDownloadToFileA` |

---

## Attack reconstruction

```text
[Phishing email]
    → document-1982481273.xlsm (malicious macro)
    → URLDownloadToFileA (WININET)
    → GET /ds/3003.gif from 5 staging domains (NameCheap-heavy)
    → 3003.gif (disguised IcedID DLL) loaded/executed
    → Modular banking stealer / follow-on payloads
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1566.001** | Phishing: Spearphishing Attachment | `.xlsm` delivery (T1) |
| **T1204.002** | User Execution: Malicious File | Macro-enabled workbook |
| **T1203** | Exploitation for Client Execution | Office macro execution (T6) |
| **T1105** | Ingress Tool Transfer | `URLDownloadToFileA` → `3003.gif` (T2–T3) |
| **T1036.007** | Masquerading: Double File Extension | `.gif` hides PE/DLL (T2) |
| **T1071.001** | Web Protocols | HTTPS staging URLs |

---

## Mitigation / hunting

1. Block **`/ds/3003.gif`** and the five staging domains; monitor **NameCheap**-registered lookalike domains in email gateways.
2. Disable Office macros by default; alert on **`.xlsm`** from external senders with **`URLDownloadToFileA`** in macro/VBA telemetry.
3. Hunt for **`inetcache`** or temp paths containing **`.gif`** files with **PE** magic bytes.
4. Sigma/YARA: IcedID **`x97m/icedid`** VT label; correlate with **Gold Cabin** / **TA551** campaigns.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/icedid/
- MITRE S0483 (IcedID): https://attack.mitre.org/software/S0483/
- Malpedia IcedID: https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid
- MalwareBazaar: https://bazaar.abuse.ch/
