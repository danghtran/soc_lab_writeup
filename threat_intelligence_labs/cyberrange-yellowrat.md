# CyberDefenders - Yellow RAT (Threat Intel) Write-up

**Challenge:** [Yellow RAT](https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, VirusTotal, RAT, SolarMarker

---

## Summary

Abnormal network traffic and search redirects at GlobalTech Industries led to investigation of a dropped artifact identified by **MD5 hash** on **VirusTotal**. The sample links to the **Yellow Cockatoo RAT** cluster (also tracked as **Jupyter**, **SolarMarker**, **Polazert**). VT and open-source reporting show a disguised DLL name, compile/submission timeline, dropped **`solarmarker.dat`** in AppData, and C2 communication with **`gogohid.com`**.

---

## Scenario

During a regular IT security check at GlobalTech Industries, abnormal network traffic was detected from multiple workstations. Upon initial investigation, it was discovered that certain employees' search queries were being redirected to unfamiliar websites. This discovery raised concerns and prompted a more thorough investigation.

---

## Objectives

- Analyze the provided artifact hash on VirusTotal.
- Identify malware family, filenames, timeline, dropped components, and C2 infrastructure.

---

## Environment

- **Artifact:** MD5 hash of dropped malware (lab package)
- **Tools used:**
  - [VirusTotal](https://www.virustotal.com/) — relations, details, behavior, detections
  - [Red Canary — Yellow Cockatoo](https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/) — dropped file and C2 context

---

## Evidence & Findings

### T1 — Malware family

**Question:** What is the name of the malware family that causes abnormal network traffic?

- **What I checked:** VirusTotal **Relations** graph → linked collections and threat context; OSINT on cluster name.
- **Evidence:** VT collection **"How to detect Yellow Cockatoo Remote Access Trojan"**; behavior consistent with in-memory .NET RAT causing redirect/C2 activity.
- **Reasoning:** Yellow Cockatoo is the named cluster for this RAT activity (aliases: Jupyter, SolarMarker, Polazert).

**Answer:** **Yellow Cockatoo RAT**

---

### T2 — Common disguised filename

**Question:** What is the common filename associated with the malware discovered on our workstations?

- **What I checked:** VirusTotal **Details** → **Signature / File Version Information** → **Original Name**.
- **Evidence:**

  ```text
  Original Name: 111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll
  ```

- **Reasoning:** The sample masquerades as a UUID-style DLL rather than an obvious executable name.

**Answer:** **111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll**

---

### T3 — Compilation timestamp

**Question:** What is the compilation timestamp of the malware that infected our network?

- **What I checked:** VirusTotal **Details** → **Portable Executable Info** → header **Compilation Timestamp**.
- **Evidence:** `2020-09-24 18:26:47 UTC`
- **Reasoning:** PE compile time indicates when the binary was built (lab format omits seconds).

**Answer:** **2020-09-24 18:26**

---

### T4 — First VirusTotal submission

**Question:** When was the malware first submitted to VirusTotal?

- **What I checked:** VirusTotal **Details** → **History** → **First Submission**.
- **Evidence:** `2020-10-15 02:47:37 UTC`
- **Reasoning:** ~3 weeks after compile time (Sep 24 → Oct 15), suggesting dwell time before community visibility.

**Answer:** **2020-10-15 02:47:37** (or **2020-10-15** if date-only)

---

### T5 — Dropped `.dat` file in AppData

**Question:** What is the name of the `.dat` file that the malware dropped in the AppData folder?

- **What I checked:** VirusTotal **Detection** tab — rule matches (`Jupyter_Dropped_file`, `Windows_Trojan_Jupyter`); Red Canary Yellow Cockatoo report.
- **Evidence:** YARA/sigma-style rules reference dropped path string **`solarmarker.dat`** under `%USERPROFILE%\AppData\Roaming\`.
- **Reasoning:** Yellow Cockatoo writes a host ID string to **`solarmarker.dat`** used as `hwid` in C2 check-in ([Red Canary](https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/)).

**Answer:** **solarmarker.dat**

---

### T6 — C2 server

**Question:** What is the C2 server that the malware is communicating with?

- **What I checked:** VirusTotal **Behavior** tab → **Network Communication**; memory pattern URLs; Red Canary C2 URLs.
- **Evidence:**
  - VT: hostname/URL pattern **`gogohid.com`**
  - Reporting: `https://gogohid.com/gate?q=...` and success callback URLs

- **Reasoning:** Primary C2 domain for Yellow Cockatoo / SolarMarker check-in and command retrieval.

**Answer:** **`gogohid.com`** (lab may also accept `http://gogohid.com` or `https://gogohid.com`)

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Malware family** | Yellow Cockatoo RAT (Jupyter / SolarMarker / Polazert) |
| **Disguised DLL** | `111bc461-1ca8-43c6-97ed-911e0e69fdf8.dll` |
| **Dropped file** | `%USERPROFILE%\AppData\Roaming\solarmarker.dat` |
| **C2 domain** | `gogohid.com` |
| **Compile time** | 2020-09-24 18:26:47 UTC |
| **First VT submission** | 2020-10-15 02:47:37 UTC |

---

## Attack Reconstruction

1. Users experience **search/query redirects** — abnormal egress/DNS or proxy activity.
2. Malware drops and runs as a **UUID-named DLL**, executing in memory as a .NET RAT.
3. Writes **`solarmarker.dat`** to AppData as a persistent host identifier.
4. Beacons to **`gogohid.com`**, exfiltrates host info, retrieves commands in a loop.
5. Community first saw the hash on VT **~3 weeks** after compile — possible undetected dwell.

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| **T1219** | Remote Access Software |
| **T1071.001** | Application Layer Protocol: Web Protocols (HTTPS C2) |
| **T1027** | Obfuscated Files or Information (DLL disguise) |

---

## Mitigation / Hardening

- Block **`gogohid.com`** and related URLs at DNS/proxy/firewall.
- Hunt for **`solarmarker.dat`** under `%AppData%\Roaming\` and UUID-pattern `.dll` names.
- Deploy VT/YARA rules: `Windows_Trojan_Jupyter`, `Jupyter_Dropped_file`.
- Monitor for browser/search hijacking and unusual HTTPS to unknown domains from workstations.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/yellow-rat/
- Red Canary — Yellow Cockatoo: https://redcanary.com/blog/threat-intelligence/yellow-cockatoo/
