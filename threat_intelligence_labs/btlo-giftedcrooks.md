# Blue Team Labs Online - Gifted Crooks (63f2e44643) Write-up

**Lab:** Gifted Crooks  
**URL:** https://blueteamlabs.online/home/investigation/gifted-crooks-63f2e44643  

**Date completed:** 20260526  
**Author:** dangtran 
**Tags:** Threat Intelligence, MISP, ICANN

---

## Summary

This investigation focused on exploring a MISP instance and extracting key intelligence from Event ID **10128** related to UAC‑0226 / GIFTEDCROOK activity. Using event metadata (publisher, timestamps, tags), attributes, and objects, I identified the issuing country, campaign type, the volume and categories of indicators, and the initial dropped artifact. I also extracted file‑based IOCs (extensions and script names) and network C2 endpoints (defanged IPs and ports). Finally, I enriched both C2 IPs using ICANN IP lookup to determine their hosting geolocation, and captured the TLP handling label assigned to the event.

---

## Scenario

You have recently joined the Cyber Threat Intelligence (CTI) team at a mid-sized organization. Your manager asks you to get familiar with MISP, the organization's threat intelligence platform. You’ve been given access to a MISP instance containing threat events, tags, and correlations. Your task is to explore the platform and answer key questions that reflect day-to-day intelligence work.

---

## Objectives

- Navigate a MISP instance and locate relevant event details.
- Extract IOCs (file, network, dropped artifacts) and basic event statistics.
- Perform basic IOC enrichment for C2 infrastructure.

---

## Scope & Assumptions

- **Platform:** MISP (lab-provided instance)
- **Event under analysis:** Event ID `10128`
- **Assumptions:**
  - “Country issued the alert” refers to the event’s publishing/issuing authority as indicated by the event context (e.g., CERT/CSIRT name in the event title/description/tags).
  - Defanged IOCs use safe formatting (e.g., `89[.]44[.]9[.]186`) to prevent accidental clicking/execution.

---

## Environment

- **Platform(s):**
  - Blue Team Labs Online
  - MISP (lab instance)
- **Provided artifacts:**
  - MISP event metadata, attributes, tags, objects
- **Tools used:**
  - Web browser (to access MISP)
  - CyberChef (Defang IP recipe)
  - ICANN IP Lookup (enrichment)

---

## High-Level Approach

Open the BTLO lab environment → access MISP → pivot to Event ID `10128` → answer questions by reviewing event metadata (publishing org, publish date, tags/TLP), then enumerating attributes/objects/categories → extract file/network IOCs → defang C2 endpoints → enrich C2 IPs using ICANN IP lookup → record results with supporting evidence notes.

---

## Evidence & Timeline

### Setup - _Access MISP and open Event 10128_

- **What I checked:** Lab instructions and MISP web UI navigation to reach Event ID `10128`.
- **Evidence:** README instructions on the lab desktop and the MISP event view page for ID `10128`.
- **Reasoning:** All answers in this lab are derived from the MISP event’s metadata, attributes, objects, and tags.

---

### T1 - _Issuing country and campaign type_

**Question:** In Event ID 10128, what country issued the alert? What type of campaign is it tied to?

- **What I checked:** Event title/context and associated references indicating the issuing authority and campaign classification.
- **Evidence:** Event context referencing CERT‑UA and UAC activity (e.g., “Цільова Шпигунська Активність UAC”).
- **Reasoning:** CERT‑UA is Ukraine’s CERT, so the issuing country is Ukraine. The described activity is targeted theft/collection against innovation hubs and government/law enforcement, consistent with an espionage campaign classification.

**Answer:** **Ukraine**, **Cyber‑Espionage**

---

### T2 - _Publish date and creator organization_

**Question:** What is the date the event was published? What is the Org (creator organization) of this event?

- **What I checked:** Event metadata fields for publish time and the creator org.
- **Evidence:** Event metadata shows publish date `2025-04-08 08:43:36` and creator org `rosti.bin.re` (first recorded change / creator org).
- **Reasoning:** These fields are authoritative metadata for the event in MISP and are used for provenance and timeline context.

**Answer:** **2025‑04‑08 08:43:36**, **rosti.bin.re**

---

### T3 - _Event size (attributes and objects)_

**Question:** How many Attributes are in this event? How many objects are in this event?

- **What I checked:** The event overview counters for attributes and objects.
- **Evidence:** Attribute count `56`, object count `21`.
- **Reasoning:** Counts indicate the event’s indicator volume and the extent of structured information attached to the event.

**Answer:** **56 attributes**, **21 objects**

---

### T4 - _Unique attribute categories_

**Question:** How many unique categories are in the attributes section?

- **What I checked:** Attribute “Category” values and deduplicated the list.
- **Evidence:** Categories observed: `Artifacts dropped`, `External analysis`, `Network activity`, `File`.
- **Reasoning:** Distinct categories show which investigation dimensions are covered by the event (host artifacts, network, file IOCs, and analysis context).

**Answer:** **4** (`Artifacts dropped`, `External analysis`, `Network activity`, `File`)

---

### T5 - _Unique file extension IOCs_

**Question:** What are the unique file extension IOCs we can extract from this event? Arrange in alphabetical order.

- **What I checked:** File-related attributes and dropped artifacts for extension patterns.
- **Evidence:** Extensions observed: `.ps1`, `.xlsm`, `.zip`.
- **Reasoning:** These extensions represent the primary file types used in the infection chain and tooling (scripts, macro-enabled docs, and archives).

**Answer:** **.ps1**, **.xlsm**, **.zip**

---

### T6 - _Office document count_

**Question:** What is the total number of office documents included in the event attributes?

- **What I checked:** File attributes filtered to office document types (e.g., `.xlsm`).
- **Evidence:** Total office documents recorded in attributes: `9`.
- **Reasoning:** This quantifies the document-based delivery component (macro-enabled documents are common initial access vectors).

**Answer:** **9**

---

### T7 - _Script file names_

**Question:** What are the file names of the scripts included in the event attributes? Arrange in alphabetical order.

- **What I checked:** File attributes for `.ps1` entries and extracted names.
- **Evidence:** `kpbkewf32mm.ps1`, `nnnnrth.ps1`.
- **Reasoning:** Script names are high-signal host-based IOCs that can be used for EDR/SIEM detections.

**Answer:** **kpbkewf32mm.ps1**, **nnnnrth.ps1**

---

### T8 - _Dropped artifact (file name and path)_

**Question:** According to this event, an artifact was dropped at the start of infection. What is the file name and the path?

- **What I checked:** “Artifacts dropped” attributes and associated comments for path.
- **Evidence:** File `status.zip` dropped to `%TMP%\\nmpoyqv5l0ig\\`.
- **Reasoning:** `%TMP%` staging is common for initial payload unpacking; the specific subdirectory and filename are actionable IOCs.

**Answer:** **status.zip**, **%TMP%\\nmpoyqv5l0ig\\**

---

### T9 - _C2 endpoints (defanged IP + port)_

**Question:** According to this event, a C2 was established. What is the first IP and Port used by the adversary? Use the defanged IP recipe by CyberChef.

- **What I checked:** “Network activity” attributes tagged as C2 and ordered by first observed/first listed.
- **Evidence:** First C2 endpoint: `89[.]44[.]9[.]186`, port `3240`.
- **Reasoning:** C2 endpoints are key containment and detection indicators; defanging prevents accidental interaction.

**Answer:** **89[.]44[.]9[.]186**, **3240**

---

### T10 - _Second C2 endpoint (defanged IP + port)_

**Question:** What is the second IP and Port used by the adversary in this campaign? Use the defanged IP recipe by CyberChef.

- **What I checked:** Additional C2-tagged network activity indicators in the event.
- **Evidence:** Second C2 endpoint: `37[.]120[.]239[.]187`, port `6501`.
- **Reasoning:** Secondary infrastructure supports pivoting and blocking/fingerprinting of the campaign’s C2 network.

**Answer:** **37[.]120[.]239[.]187**, **6501**

---

### T11 - _C2 enrichment (ICANN IP Lookup)_

**Question:** Perform IOC enrichment using ICANN IP Lookup for the first C2. In what country is this IP located?

- **What I checked:** ICANN lookup results for `89[.]44[.]9[.]186`.
- **Evidence:** ICANN enrichment indicates country: `France`.
- **Reasoning:** Hosting geolocation helps triage infrastructure and informs blocking/escalation decisions.

**Answer:** **France**

---

### T12 - _C2 enrichment (ICANN IP Lookup)_

**Question:** Perform IOC enrichment using ICANN IP Lookup for the second C2. In what country is this IP located?

- **What I checked:** ICANN lookup results for `37[.]120[.]239[.]187`.
- **Evidence:** ICANN enrichment indicates country: `Netherlands`.
- **Reasoning:** Confirms geographic distribution of campaign infrastructure for reporting and hunting.

**Answer:** **Netherlands**

---

### T13 - _TLP tag / handling_

**Question:** Lastly, what is the TLP tag assigned to this event?

- **What I checked:** Event tags.
- **Evidence:** Tag `tlp:clear`.
- **Reasoning:** TLP defines how broadly the intelligence can be shared.

**Answer:** **tlp:clear**

---

## Indicators of Compromise (IOCs)

- **Network (C2):**
  - `89[.]44[.]9[.]186:3240`
  - `37[.]120[.]239[.]187:6501`
- **Dropped artifact:**
  - `status.zip` in `%TMP%\\nmpoyqv5l0ig\\`
- **Scripts:**
  - `kpbkewf32mm.ps1`
  - `nnnnrth.ps1`
- **File extensions observed:** `.ps1`, `.xlsm`, `.zip`
- **Campaign label:** `Cyber‑Espionage`

---

## Findings

- **Event provenance:** Event `10128` is published on `2025‑04‑08 08:43:36` with creator org `rosti.bin.re` (T2).
- **Campaign classification:** The activity is issued by Ukraine’s CERT context (CERT‑UA) and tied to a `Cyber‑Espionage` campaign (T1).
- **Actionable IOCs:** The event provides host-based (scripts, dropped archive path) and network-based (two C2 endpoints) indicators suitable for detection and blocking (T8–T10).

---

## Attack Reconstruction (What likely happened)

The event indicates an initial infection chain involving office documents (including macro-enabled files), possibly phishing attempts, and supporting scripting, consistent with a staged execution flow. Early in the infection, an archive (`status.zip`) is dropped into a temporary directory (`%TMP%\\nmpoyqv5l0ig\\`), suggesting unpacking/staging of additional payloads or configuration. Following staging, the adversary establishes command-and-control communications using at least two external endpoints (first `89[.]44[.]9[.]186:3240`, then `37[.]120[.]239[.]187:6501`), consistent with a multi-node C2 design typical of targeted espionage operations.

---

## Mitigation / Remediation

- **Containment:** Block the identified C2 endpoints at network egress; alert on outbound connections to the defanged IP:port pairs.
- **Host detections:** Add detections for the dropped artifact path `%TMP%\\nmpoyqv5l0ig\\` and script filenames `kpbkewf32mm.ps1`, `nnnnrth.ps1`.
- **Email/document controls:** Strengthen protections for macro-enabled office documents (e.g., block unsigned macros, restrict `.xlsm` execution paths).
- **Threat intel operations:** Track event updates in MISP and correlate these indicators against internal telemetry for retro-hunting.

---

## Lessons Learned

- MISP event metadata (publisher, publish date, tags) provides critical context for provenance and sharing controls.
- Structuring raw Q&A notes into evidence-backed timeline entries improves repeatability and makes intelligence defensible.

---

## References

- Lab: https://blueteamlabs.online/home/investigation/gifted-crooks-63f2e44643