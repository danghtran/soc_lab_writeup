# CyberDefenders - Insider (Linux Disk Forensics) Write-up

**Challenge:** [Insider](https://cyberdefenders.org/blueteam-ctf-challenges/insider/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Digital forensics, Linux, insider threat, FTK Imager

---

## Summary

**Karen** (employee at **TAAUSAI**) is suspected of illegal activity on a **Kali Linux** workstation. Analysis of forensic image **`FirstHack.ad1`** (E01, ext4) shows **Mimikatz** downloaded, a hidden file on the Desktop, **binwalk** on a stego image, **flightSim** attack evidence against user **Bob** (`irZLAohL.jpeg`), taunting of **Young** in a bash script, repeated **`su`** to **`postgres`** at 11:26, and last shell cwd **`/root/Documents/myfirsthack/`**. Apache never ran (`access.log` empty, MD5 of empty file).

---

## Scenario

After Karen started working for TAAUSAI, she began doing illegal activities inside the company. TAAUSAI hired you as a SOC analyst to kick off an investigation on this case. You acquired a disk image and found that Karen uses Linux OS on her machine.

---

## Objectives

- Analyze Karen's disk image and answer forensic questions.
- Identify OS, malicious tooling, attack artifacts, and user activity from logs and userland artifacts.

---

## Environment

- **Artifact:** `FirstHack.ad1` (from lab ZIP `c46-FirstHack.zip`) → E01 **`Horcrux.E01`**, ext4 partition
- **Hostname (from logs):** `KarenHacker`
- **Tools:** [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-7-1) — mount AD1, browse/export files, hash export

**Key paths on image:**

```text
/var/log/syslog.2.gz          # OS version strings
/boot/config-4.13.0-kali1-amd64
/var/log/apache2/access.log
/root/Downloads/
/root/.bash_history
/root/Desktop/
/root/Documents/myfirsthack/
/var/log/auth.log
```

---

## Evidence & Findings

### T1 — Linux distribution

**Question:** Which Linux distribution is being used on this machine?

- **What I checked:** `var/log/syslog.2.gz` (decompress/read) for kernel banner; `/boot` for `config-*` filenames.
- **Evidence:**

  ```text
  Linux version 4.13.0-kali1-amd64 (devel@kali.org) ... #1 SMP Debian 4.13.10-1kali2
  ```

  Boot config: `config-4.13.0-kali1-amd64`

- **Reasoning:** Kernel and package branding identify **Kali Linux** (penetration-testing distribution).

**Answer:** **`kali`**

---

### T2 — MD5 of Apache access.log

**Question:** What is the MD5 hash of the Apache access.log file?

- **What I checked:** `var/log/apache2/access.log` — export via FTK Imager → **Export File Hash List** (CSV).
- **Evidence:**

  ```text
  MD5: d41d8cd98f00b204e9800998ecf8427e
  ```

  This is the MD5 of an **empty file** (0 bytes) — Apache never wrote access entries.

- **Reasoning:** Confirms no HTTP access logging occurred on this host (ties to T7).

**Answer:** **`d41d8cd98f00b204e9800998ecf8427e`**

---

### T3 — Credential dumping tool download

**Question:** It is suspected that a credential dumping tool was downloaded. What is the name of the downloaded file?

- **What I checked:** `root/Downloads/` and `root/Desktop/`.
- **Evidence:** **`mimikatz_trunk.zip`** in Downloads; extracted **`mimikatz`** folder on Desktop.
- **Reasoning:** Mimikatz is a well-known Windows credential dumping tool — suspicious on an insider's Linux box (likely for attacks against Windows targets such as Bob).

**Answer:** **`mimikatz_trunk.zip`**

---

### T4 — Super-secret file path

**Question:** A super-secret file was created. What is the absolute path to this file?

- **What I checked:** `root/.bash_history` — search `touch`, `>`, file creation.
- **Evidence:**

  ```bash
  touch snky snky > /root/Desktop/SuperSecretFile.txt
  ```

- **Reasoning:** Command explicitly creates **`SuperSecretFile.txt`** on the Desktop.

**Answer:** **`/root/Desktop/SuperSecretFile.txt`**

---

### T5 — Program using didyouthinkwedmakeiteasy.jpg

**Question:** What program used the file didyouthinkwedmakeiteasy.jpg during its execution?

- **What I checked:** `root/.bash_history` for commands referencing the image.
- **Evidence:**

  ```bash
  binwalk didyouthinkwedmakeiteasy.jpg
  ```

- **Reasoning:** **binwalk** analyzes embedded files / steganography in images — common CTF and forensics step.

**Answer:** **`binwalk`**

---

### T6 — Third checklist goal

**Question:** What is the third goal from the checklist Karen created?

- **What I checked:** Desktop checklist file.
- **Evidence:**

  ```text
  Check List:
  - Gain Bob's Trust
  - Learn how to hack
  - Profit
  ```

- **Reasoning:** Third line is the final goal in Karen's personal attack plan.

**Answer:** **`Profit`**

---

### T7 — Apache run count

**Question:** How many times was Apache run?

- **What I checked:** `var/log/apache2/` — `access.log` and related logs (empty or absent entries).
- **Evidence:** Empty **`access.log`** (MD5 `d41d8cd9...`); no meaningful Apache runtime logged.
- **Reasoning:** No access log data implies Apache did not serve traffic on this system during the captured period.

**Answer:** **`0`**

---

### T8 — Evidence of attack on another machine

**Question:** This machine was used to launch an attack on another. Which file contains the evidence for this?

- **What I checked:** Root directory for unusual artifacts (`.msf4` Metasploit dir, screenshots).
- **Evidence:** **`irZLAohL.jpeg`** in `/root/` — screenshot of **Windows** command prompt on victim **Bob**'s machine, running **`flightSim`** / **`flightSim.exe run`** (simulated malicious network traffic for IDS/firewall testing).
- **Reasoning:** JPEG proves Karen operated attack tooling against another user's host (Bob), not just local Linux activity.

**Answer:** **`irZLAohL.jpeg`**

---

### T9 — Expert Karen was taunting

**Question:** Who was the expert that Karen was taunting through a bash script in Documents?

- **What I checked:** `Documents/myfirsthack/firstscript_fixed` (bash script).
- **Evidence:**

  ```bash
  echo "Heck yeah! I can write bash too Young"
  ```

- **Reasoning:** Direct reference to fellow expert **Young** in taunting message.

**Answer:** **`Young`**

---

### T10 — User executing su at 11:26

**Question:** A user executed the su command to gain root access multiple times at 11:26. Who was the user?

- **What I checked:** `var/log/auth.log` — filter **`su`** at **11:26**.
- **Evidence:**

  ```text
  Mar 20 11:26:22 KarenHacker su[4060]: Successful su for postgres by root
  Mar 20 11:26:22 KarenHacker su[4074]: Successful su for postgres by root
  ...
  ```

- **Reasoning:** Repeated **`su`** sessions target account **`postgres`** (privilege switching / persistence probing).

**Answer:** **`postgres`**

---

### T11 — Current working directory (bash history)

**Question:** Based on the bash history, what is the current working directory?

- **What I checked:** `root/.bash_history` — last **`cd`** command.
- **Evidence:**

  ```bash
  cd ../Documents/myfirsthack/
  ```

  Resolves to **`/root/Documents/myfirsthack/`** from prior path context.

- **Reasoning:** Last directory change before session end defines cwd for subsequent relative commands.

**Answer:** **`/root/Documents/myfirsthack/`**

---

## Attack / Insider Activity Reconstruction

```text
[Karen @ TAAUSAI — Kali workstation]
        |
        +→ Downloads mimikatz_trunk.zip (credential dumping prep)
        +→ Creates /root/Desktop/SuperSecretFile.txt
        +→ binwalk on didyouthinkwedmakeiteasy.jpg (stego/analysis)
        +→ Checklist: Gain Bob's Trust → Learn how to hack → Profit
        |
        v
[Against Bob — Windows victim]
        +→ flightSim.exe run (simulated attack traffic)
        +→ Evidence captured: irZLAohL.jpeg screenshot
        |
        +→ Documents/myfirsthack/ — scripts taunting "Young"
        +→ auth.log: repeated su → postgres @ 11:26
```

---

## Key artifacts

| Artifact | Significance |
|----------|----------------|
| **OS** | Kali Linux 4.13.0-kali1-amd64 |
| **mimikatz_trunk.zip** | Credential dumping tooling |
| **SuperSecretFile.txt** | User-created sensitive file |
| **didyouthinkwedmakeiteasy.jpg** | Analyzed with binwalk |
| **irZLAohL.jpeg** | Proof of attack on Bob's Windows host |
| **firstscript_fixed** | Taunt reference to Young |
| **auth.log** | postgres su activity 11:26:22 |
| **.bash_history** | Last cwd `/root/Documents/myfirsthack/` |

---

## MITRE ATT&CK (insider / abuse)

| Technique | Name | Notes |
|-----------|------|--------|
| **T1078** | Valid Accounts | Insider Karen |
| **T1003** | OS Credential Dumping | Mimikatz download |
| **T1059.004** | Unix Shell | bash history, scripts |
| **T1071** | Application Layer Protocol | flightSim / attack simulation |
| **T1567** | Exfiltration Over Web Service | (potential; not fully in scope) |

---

## Lessons / methodology

1. **Start with OS identity** — `syslog`, `/boot/config-*`, `/etc/os-release` if present.
2. **User intent** — `.bash_history`, Desktop notes, Downloads.
3. **Empty logs are IOCs** — `access.log` MD5 `d41d8cd9...` = zero-byte file.
4. **Cross-platform insider** — Linux disk can hold evidence of **Windows** attacks (screenshots, Mimikatz).
5. **Auth logs** — `auth.log` for `su`/`sudo` privilege abuse.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/insider/
- FTK Imager: https://accessdata.com/product-download/
