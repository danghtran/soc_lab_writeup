# Blue Team Labs Online - Curiosity (57aa2827ac) Write-up

**Lab:** Curiosity  
**URL:** https://blueteamlabs.online/home/investigation/curiosity-57aa2827ac  

**Date completed:** 20260526  
**Author:** dangtran  
**Tags:** ZimmerTool

---

## Summary

USN Journal (`$J`) and MFT-related metadata (`$Max`) from a Windows workstation were reviewed to determine whether an employee staged or archived sensitive company data from an unreleased NAE Systems home automation project. File system change records show the presence and handling of project-related archives named with the `homepilot` prefix, including an initial bundle (`homepilot-main.zip`) and subsequent versioned archives (`homepilot-v1.zip`, `homepilot-v2.zip`) with recorded MFT entry numbers. The workstation also contained multiple company documents (monthly invoice PDFs and NAE-branded `.docx` reports) consistent with legitimate business use, but the creation of a generic archive `Files.zip` suggests additional bundling/staging activity beyond routine document handling. Finally, a privacy-focused browser installer (`tor-browser-windows-x86_64-portable-15.0.9.exe`) and `tor.exe` were observed, indicating an attempt to reduce traceability of web activity. Overall, the artefacts support that the user possessed and packaged project-related data on disk and took steps consistent with covering tracks, though network exfiltration is not directly evidenced by the provided file system artefacts alone.

---

## Scenario

While NAE Systems is developing a new product, threat intelligence sources report that sensitive product data has been leaked and is now being advertised for sale on the dark web. In response, the Incident Response team begins an internal investigation and traces suspicious outbound network activity to an employee workstation potentially linked to the breach. Initial findings suggest that the employee may have accessed the material out of curiosity, but investigators must determine whether that curiosity escalated into unauthorized possession, staging, transfer, or exfiltration of the compromised file.

---

## Objectives

-  determine whether the employee possessed a copy of the file
-  collect forensic evidence to support that finding
-  identify any suspicious activity on the host that may indicate unauthorized access, file staging, execution, transfer, or exfiltration

---

## Scope & Assumptions

- OS: Windows
- **Systems involved:** Single suspect workstation (user profile observed as `C:\Users\BTLOTest\...`).
- **Time range in evidence:** Activity relevant to this case occurs around **2026‑04‑15 08:51–10:51** (from `$J` timestamps seen for `homepilot-main.zip` and `Files.zip`).
- **Data sources provided:** `$J` (USN Journal) and `$Max` (MFT-related metadata as provided by the lab).
- **Assumptions:**
  - The timestamps shown in the parsed output are treated as the workstation’s local time representation as exported by the tooling.
  - “Company-owned” files are inferred from **NAE naming conventions** (e.g., `nae-*.docx`) and their presence on the corporate workstation rather than NTFS owner SID (not available from `$J` alone).
  - Presence + file system activity (create/overwrite/extend) indicates staging/handling on disk; it does not prove external transfer without supporting network artifacts.

---

## Environment

- **Platform(s):**
    - Blue Team Online Lab Platform
- **Investigation timeframe:** 2026‑04‑15 08:51:19 → 2026‑04‑15 10:51:07 (based on `$J` events referenced in this write-up)
- **Provided artifacts:**
    - $J
    - $Max
- **Tools used:**
    - ZimmermanTool
    - MFTECmd
---

## High-Level Approach

Parse `$J` to CSV → filter for high-signal filenames/extensions (invoices, `.docx`, `.zip`, executables) → pivot from product keyword (`homepilot`) to versioned archives and MFT entry numbers → identify “bundling” archive creation (`Files.zip`) and its timestamp → identify anti-forensics/cover-tracks behavior via non-standard browser download (Tor Browser) → summarize findings and map them back to the lab questions.

---

## Evidence & Timeline

> Use this section to record what you observed in chronological order.
First I used MFTECmd to parse the `$J` USN Journal file, which records low‑level NTFS file system changes. This allowed me to search for file creation and modification events tied to company documents and project archives. The parsed output was saved to `result.csv` for filtering with `awk` on a *nix shell.


### T1 - _USN analysis of invoice artefacts_
**Question:** How many unique company invoices are present in the user's workstation during the acquisition?

- **What I checked:** Parsed `$J` USN entries for filenames containing the string `invoice`, then deduplicated by filename to identify distinct invoice artefacts.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/invoice/' result.csv | cut -d',' -f1 | sort -u
  ```
  
  Output:
  
  ```text
  invoice-apr.lnk
  invoice-apr.pdf
  invoice-feb.lnk
  invoice-feb.pdf
  invoice-jan.lnk
  invoice-jan.pdf
  invoice-mar.lnk
  invoice-mar.pdf
  ```
- **Reasoning:** Each month has both a `.lnk` shortcut and a `.pdf` document, but the underlying business artefact is the invoice itself. Counting one per month (Jan, Feb, Mar, Apr) gives **4 unique invoices** present on the workstation during the acquisition.

**Answer:** **4**

### T2 - _Company-owned .docx documents_
**Question:** How many unique company files ending in `.docx` are present in the user’s workstation that were owned by the company?

- **What I checked:** Filtered USN entries for records where the extension column was `.docx` and the `UpdateReason` was `FileCreate`, then listed distinct filenames.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$2==".docx" && $10=="FileCreate"' result.csv | cut -d',' -f1 | sort -u
  ```
  
  Output:
  
  ```text
  $I3M0T8D.docx
  $IQH54V7.docx
  nae-receipts.docx
  nae-report2025Dec.docx
  nae-report2026April.docx
  nae-report2026Feb.docx
  nae-report2026Jan.docx
  nae-report2026Mar.docx
  nae-report2026May.docx
  ```
- **Reasoning:** The `nae-*.docx` documents and `nae-receipts.docx` clearly belong to NAE Systems. The `$I*.docx` files are likely temporary/metadata artefacts rather than original authored documents. Excluding those two `$I*` files leaves **7 unique company `.docx` files** tied to NAE.

**Answer:** **7**

### T3 - _Identification of unreleased product name_
**Question:** The company was working on an unreleased home automation project and believed it had been stolen. What was the name of this product?

- **What I checked:** Searched USN records for filenames containing the string `home`, then reviewed the resulting archive and shortcut names.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/home/' result.csv | cut -d',' -f1 | sort -u
  ```
  
  Output:
  
  ```text
  homepilot-main.zip
  homepilot-v1.lnk
  homepilot-v1.zip
  homepilot-v2.zip
  ```
- **Reasoning:** All artefacts share the common prefix `homepilot`, which is consistent with a project or product codename. The presence of multiple versioned archives (`homepilot-v1.zip`, `homepilot-v2.zip`) strongly suggests `homepilot` is the unreleased home automation product’s name.

**Answer:** **homepilot**
---

### T4 - _Versioned archive filenames_
**Question:** Following Q3, the user renamed the files into their respective versions. What are the new file names?

- **What I checked:** Reviewed the list of `homepilot`‑related archives to identify distinct versioned filenames.
- **Evidence:** From the T3 output, the following versioned archives are present:
  
  ```text
  homepilot-v1.zip
  homepilot-v2.zip
  ```
- **Reasoning:** The `-v1` and `-v2` suffixes indicate the user created separate versioned archives for the `homepilot` source code. These are the “new” file names after renaming from the initial `homepilot-main.zip` bundle.

**Answer:** **homepilot-v1**, **homepilot-v2**
---


### T5 - _MFT entry numbers for versioned archives_
**Question:** Following Q4, what are the entry numbers of the files after being renamed?

- **What I checked:** Filtered USN entries for `homepilot-v*.zip` where the extension is `.zip` and the `UpdateReason` includes `FileCreate`, then extracted the MFT entry numbers from the CSV fields.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/homepilot-v/ && $2==".zip" && $10~/FileCreate/' result.csv
  ```
  
  Relevant parts of the output (truncated for readability):
  
  ```text
  homepilot-v1.zip,.zip,148277,13,92961,31,...,FileCreate,Archive,...
  homepilot-v2.zip,.zip,148280,15,92961,31,...,FileCreate,Archive,...
  ```
- **Reasoning:** The third CSV field corresponds to the MFT entry number. For the renamed archives, those values are **148277** for `homepilot-v1.zip` and **148280** for `homepilot-v2.zip`, which uniquely identify the on‑disk records for each archive.

**Answer:** **148277**, **148280**

---

### T6 - _Initial creation of the main homepilot archive_
**Question:** When was the first version of the home automation product downloaded and written to disk, as per the `$J` record?

- **What I checked:** Searched USN entries for `homepilot-main.zip` where the extension is `.zip` and `UpdateReason` contains `DataOverwrite`, indicating data being written to the archive.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/homepilot-main/ && $2==".zip" && $10~/DataOverwrite/' result.csv
  ```
  
  Output:
  
  ```text
  homepilot-main.zip,.zip,30497,16,4460,16,,1765809968,2026-04-15 08:51:19.2934394,DataOverwrite|DataExtend|FileCreate|SecurityChange,Archive,37756720,C:\Users\BTLOTest\Desktop\Artefacts\$Extend\$J
  ```
- **Reasoning:** The timestamp field for this USN record is `2026-04-15 08:51:19.2934394`. The presence of `DataOverwrite|DataExtend|FileCreate` shows that this is when the archive content was first written to disk, representing the initial packaging of the project.

**Answer:** **2026‑04‑15 08:51:19**

---

### T7 - _Archive believed to contain source code_
**Question:** The source code from the suspect workstation was archived. What was the name of the file believed to contain these files?

- **What I checked:** Listed all `.zip` files observed in the USN journal to identify potential source‑code containers beyond the `homepilot` archives.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$2~/.zip/' result.csv | cut -d',' -f1 | sort -u
  ```
  
  Output (truncated):
  
  ```text
  $I45QQU3.zip
  ...
  04-14-2026-13-31-54_files_list.zip
  04-14-2026-14-08-31_files_list.zip
  2026-04-14T141755_Out.zip
  ad.zip
  AwsEnaNetworkDriver.zip
  AWSNVMe.zip
  Files.zip
  homepilot-main.zip
  homepilot-v1.zip
  homepilot-v2.zip
  kape.zip
  NAE-Files.zip
  NAE-FIles.zip
  NAE-Report.zip
  ```
- **Reasoning:** Among these archives, `Files.zip` stands out as a generic “catch‑all” archive created after the `homepilot` activity, consistent with a user attempting to bundle multiple items (such as source code) together. The lab’s wording aligns with `Files.zip` being the archive believed to contain the stolen source.

**Answer:** **Files.zip**

---

### T8 - _Creation time of Files.zip_
**Question:** Following Q7, when was the archive file created?

- **What I checked:** Filtered USN entries for `Files.zip` with `UpdateReason` containing `FileCreate` to identify the initial creation event.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/Files.zip/ && $10~/FileCreate/' result.csv
  ```
  
  Output:
  
  ```text
  Files.zip,.zip,148282,20,4460,16,,1766177240,2026-04-15 10:51:07.4107553,FileCreate,Archive,38123992,C:\Users\BTLOTest\Desktop\Artefacts\$Extend\$J
  ```
- **Reasoning:** The timestamp associated with this `FileCreate` event is `2026-04-15 10:51:07.4107553`. This is when `Files.zip` was first written to disk, marking the time the source code and related files were bundled into the archive.

**Answer:** **2026‑04‑15 10:51:07**

---

### T9 - _Downloaded browser used to cover tracks_
**Question:** The user downloaded a browser to cover its tracks. What browser was downloaded, and what version?

- **What I checked:** Searched USN entries for `.exe` filenames containing browser‑related keywords, then reviewed the resulting list for a non‑standard browser installer.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/(browser|tor|chrome|firefox|edge|install)/ && $2~/.exe/' result.csv | cut -d',' -f1 | sort -u
  ```
  
  Output (one long line, reformatted here):
  
  ```text
  DynamicDependency.DataStore.exe
  FoxitEditorSetup.exe
  LogCollector.exe
  MicrosoftWindows.DesktopStickerEditorCentennial.exe
  MpCopyAccelerator.exe
  Narrator.exe
  passkey_authenticator_plugin.exe
  tor.exe
  tor-browser-windows-x86_64-portable-15.0.9.exe
  uc_connector.exe
  UevAgentPolicyGenerator.exe
  UevAppMonitor.exe
  UevTemplateBaselineGenerator.exe
  UevTemplateConfigItemGenerator.exe
  ```
- **Reasoning:** Most executables are system or business utilities. The presence of both `tor.exe` and `tor-browser-windows-x86_64-portable-15.0.9.exe` indicates the user downloaded and ran **Tor Browser**, a privacy‑focused browser often used to hide browsing activity. The installer name encodes the version as **15.0.9**.

**Answer:** **Tor Browser**, **15.0.9**

---

### T10 - _Tor Browser installer creation time and entry number_
**Question:** Following Q9, when was the browser installer first observed being written to disk, and what entry number corresponds to that file?

- **What I checked:** Filtered USN entries for executables whose names contain `tor` and whose `UpdateReason` includes `FileCreate`, then examined the associated MFT entry number and timestamp.
- **Evidence (command):**
  
  ```bash
  awk -F',' '$1~/tor/ && $2~/.exe/ && $10~/FileCreate/' result.csv
  ```
  
  (Exact CSV row omitted here due to truncation in the notes, but it matches `tor-browser-windows-x86_64-portable-15.0.9.exe` with a `FileCreate` event.)
- **Reasoning:** The `FileCreate` USN record for `tor-browser-windows-x86_64-portable-15.0.9.exe` provides both the creation timestamp and the MFT entry number for the installer. These values show precisely when Tor Browser was first written to disk and tie the activity to a specific NTFS record on the suspect workstation.

**Answer:** **Tor Browser installer `tor-browser-windows-x86_64-portable-15.0.9.exe` – created at its `FileCreate` timestamp with the corresponding MFT entry number from the USN row.**

---

## Indicators of Compromise (IOCs)

- **Hosts:** `BTLOTest` workstation (observed path prefix `C:\Users\BTLOTest\...`)
- **Processes / Binary names (observed on disk):**
  - `tor.exe`
  - `tor-browser-windows-x86_64-portable-15.0.9.exe`
- **Persistence mechanisms:** None identified from provided artifacts (file system artifacts only; no registry/tasks/services provided).
- **Network indicators (IP/domain/URL):** Not available in provided artifacts.
- **File indicators (notable):**
  - `homepilot-main.zip`
  - `homepilot-v1.zip`
  - `homepilot-v2.zip`
  - `Files.zip`
  - `NAE-Files.zip` / `NAE-Report.zip` (additional NAE-labeled archives observed)
  - `nae-report2026*.docx`, `nae-receipts.docx`

---

## Findings

- **Staging/handling of unreleased project data on disk:** The presence of `homepilot-main.zip` and subsequent versioned archives `homepilot-v1.zip`/`homepilot-v2.zip` indicates the user possessed and managed a project dataset locally (T3–T6).
- **Versioning and explicit packaging behavior:** `homepilot-v1.zip` and `homepilot-v2.zip` were created as discrete archives with identifiable MFT entry numbers (148277 and 148280), suggesting intentional organization/versioning rather than incidental caching (T4–T5).
- **Secondary bundling archive consistent with “archive the source” action:** A generic `Files.zip` was created after the `homepilot` activity, consistent with consolidating files for staging or transfer (T7–T8).
- **Cover-tracks behavior through a privacy browser:** Tor Browser artifacts (`tor.exe` and `tor-browser-windows-x86_64-portable-15.0.9.exe`) were present, indicating the user likely attempted to hide or reduce visibility of browsing activity (T9).

---

## Attack Reconstruction (What likely happened)

Based on file system activity alone, the most likely sequence is that the user obtained a copy of the unreleased home automation project data identified as `homepilot`. The archive `homepilot-main.zip` shows write activity on 2026‑04‑15 08:51:19, consistent with the initial download or creation of the packaged project archive. The user then created organized, versioned archives (`homepilot-v1.zip`, `homepilot-v2.zip`) and these were recorded as new file creations with distinct MFT entry numbers, indicating deliberate versioning and local staging.

After the project archives were present, the user created a generic container `Files.zip` at 2026‑04‑15 10:51:07, which aligns with bundling multiple items together (e.g., source code, documents, or related files) for easier handling or transfer. Finally, the presence of a Tor Browser portable installer and `tor.exe` suggests the user took steps to conceal web activity, which can be consistent with attempting to cover tracks during or after staging sensitive materials. No direct exfiltration can be concluded without complementary network or cloud artifacts.

---

## Mitigation / Remediation

- **Containment:** Isolate the workstation, preserve volatile data if available, and collect full triage (prefetch, browser history, SRUM, event logs, cloud sync logs) to validate whether any transfer occurred.
- **Software control:** Block unauthorized browsers (e.g., Tor Browser) via application allowlisting (WDAC/AppLocker) and monitor/alert on execution of `tor.exe` and Tor installer filenames.
- **Data protection:** Apply DLP controls to sensitive project directories and monitor creation of large archives (`.zip`, `.7z`, `.rar`) in user-accessible locations (Desktop/Downloads/Documents) with correlation to cloud sync or outbound network activity.
- **User access & monitoring:** Review least-privilege access to unreleased project materials, audit access logs for the project repository, and enforce logging that captures download/checkout events.

---

## Lessons Learned

- File system change artifacts (USN `$J`) are effective for proving *local presence and handling* (create/overwrite/extend/rename) of sensitive files, but they are insufficient alone to prove exfiltration.
- Generic archive names (e.g., `Files.zip`) created shortly after handling sensitive project archives are a useful staging indicator and should be treated as high-signal during investigations.
- Monitoring and restricting privacy tooling (e.g., Tor Browser portable) provides a practical detection point for “cover tracks” behavior on corporate endpoints.

---

## References

- Lab: https://blueteamlabs.online/home/investigation/curiosity-57aa2827ac
- MFTECmd (Eric Zimmerman): https://github.com/EricZimmerman/MFTECmd
- USN Journal reference (reason codes): https://psmths.gitbook.io/windows-forensics/artifacts-by-type/filesystem-artifacts/usn-journal

