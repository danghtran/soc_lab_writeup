# Blue Team Labs Online - {Lab Name} ({lab-id}) Write-up

**Lab:** {Lab Name}  
**URL:** https://blueteamlabs.online/home/investigation/{lab-slug}-{lab-id}  

**Date completed:** _YYYYMMDD_  
**Author:** _your name_  
**Tags:** _e.g., Windows, IR, USN, MFTECmd_

---

## Summary

_TODO: 5–10 sentences. What happened, what artifacts you analyzed, key evidence, and your conclusion._

---

## Scenario

_Paste the lab scenario from BTLO here._

---

## Objectives

- _TODO: Lab objective 1_
- _TODO: Lab objective 2_
- _TODO: Lab objective 3_

---

## Scope & Assumptions

- **OS:** _e.g., Windows_
- **Systems involved:** _hostname(s), user profile(s), time range_
- **Data sources provided:** _e.g., $J, $MFT, memory dump, logs, pcap_
- **Assumptions:**
  - _TODO_
  - _TODO_

---

## Environment

- **Platform(s):**
  - Blue Team Labs Online
- **Investigation timeframe:** _start → end (from artifact timestamps)_
- **Provided artifacts:**
  - _TODO_
- **Tools used:**
  - _e.g., Get-ZimmermanTools, MFTECmd, Timeline Explorer_

---

## High-Level Approach

_TODO: Brief workflow, e.g., parse artifacts → filter/pivot on high-signal indicators → answer lab questions → summarize findings._

---

## Evidence & Timeline

> Record observations in chronological order. Duplicate the **T#** block below for each lab question.

### Setup - _Artifact parsing_

_Describe how you prepared the data (parser, output file, column mapping)._

```bash
# Example: parse USN Journal
MFTECmd.exe -f "$J" --csv out --csvf result.csv
```

```bash
# Confirm CSV columns before filtering
head -n 1 result.csv | tr ',' '\n' | nl
```

---

### T1 - _Short title_

**Question:** _Paste the lab question here._

- **What I checked:** _TODO_
- **Evidence (command):**

  ```bash
  # TODO: command
  ```

  Output:

  ```text
  # TODO: key output
  ```

- **Reasoning:** _TODO: explain how the evidence answers the question._

**Answer:** _TODO_

---

### T2 - _Short title_

**Question:** _Paste the lab question here._

- **What I checked:** _TODO_
- **Evidence (command):**

  ```bash
  # TODO: command
  ```

  Output:

  ```text
  # TODO: key output
  ```

- **Reasoning:** _TODO_

**Answer:** _TODO_

---

### T3 - _Short title_

**Question:** _Paste the lab question here._

- **What I checked:** _TODO_
- **Evidence (command):**

  ```bash
  # TODO: command
  ```

  Output:

  ```text
  # TODO: key output
  ```

- **Reasoning:** _TODO_

**Answer:** _TODO_

---

## Indicators of Compromise (IOCs)

- **Hosts:** _TODO_
- **Processes / Binary names:** _TODO_
- **Persistence mechanisms:** _TODO_
- **Network indicators (IP/domain/URL):** _TODO_
- **File indicators (paths/hashes):** _TODO_

---

## Findings

- **Finding 1:** _TODO (reference T# section)_
- **Finding 2:** _TODO_
- **Finding 3:** _TODO_

---

## Attack Reconstruction (What likely happened)

_TODO: 1–2 paragraphs. Initial access → execution/staging → transfer/cover tracks → impact. Tie each step to timeline evidence._

---

## Mitigation / Remediation

- **Containment:** _TODO_
- **Eradication:** _TODO_
- **Detection improvements:** _TODO (SIEM rules, hunting queries, controls)_

---

## Lessons Learned

- _TODO_
- _TODO_

---

## References

- Lab: https://blueteamlabs.online/home/investigation/{lab-slug}-{lab-id}
- _TODO: tool docs, MITRE ATT&CK mappings, blog posts_
