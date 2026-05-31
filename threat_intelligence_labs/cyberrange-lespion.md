# CyberDefenders - L'espion (Threat Intel / OSINT) Write-up

**Challenge:** [Lespion](https://cyberdefenders.org/blueteam-ctf-challenges/lespion/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, OSINT, insider threat, GitHub, geolocation

---

## Summary

A client network was compromised from a **single user account** — likely an **insider**. Starting from **`Github.txt`** (profile **`EMarseille99`** / **Emilie Marseille**), OSINT across GitHub, LinkedIn, Instagram, and image analysis tied the insider to **hardcoded credentials**, **xmrig** cryptomining, social accounts, travel/family locations, company office in **Birmingham**, and final sighting on an **EarthCam** at **Notre Dame** in **Indiana**.

---

## Scenario

You have been tasked by a client whose network was compromised and brought offline to investigate the incident and determine the attacker's identity. Incident responders and digital forensic investigators are currently on the scene and have conducted a preliminary investigation. Their findings show that the attack originated from a single user account, probably an insider.

---

## Objectives

- Investigate the incident, identify the insider, and uncover attack actions.
- Use OSINT on provided artifacts (`Github.txt`, `office.jpg`, `Webcam.png`) and open sources.

---

## Environment

- **Artifacts:** `Github.txt`, `office.jpg`, `Webcam.png` (from lab ZIP `c54-Lespion.zip`)
- **Tools used:**
  - [GitHub](https://github.com/) — repos, commits, fork vs. original content
  - [CyberChef](https://gchq.github.io/CyberChef/) — Base64 decode
  - Google / Bing search, reverse image search
  - [Sherlock](https://github.com/sherlock-project/sherlock) — username enumeration (optional)
  - [EarthCam](https://www.earthcam.com/) — webcam geolocation
  - LinkedIn, Instagram — profile correlation

**Starting pivot:** `Github.txt` → `https://github.com/EMarseille99`

---

## Evidence & Findings

### T1 — API key in GitHub repository

**Question:** What API key did the insider add to his GitHub repositories?

- **What I checked:** GitHub profile **`EMarseille99`** → non-forked repo **`Project-Build---Custom-Login-Page`** → **`Login Page.js`** (commit history).
- **Evidence:**

  ```javascript
  // Login Page.js (first line / Update Login Page.js commit)
  API Key = aJFRaLHjMXvYZgLPwiJkroYLGRkNBW
  ```

- **Reasoning:** Only original (non-fork) repo likely contains insider-added secrets; login-page JS commonly holds API keys for web apps.

**Answer:** **`aJFRaLHjMXvYZgLPwiJkroYLGRkNBW`**

---

### T2 — Plaintext password in GitHub repository

**Question:** What plaintext password did the insider add to his GitHub repositories?

- **What I checked:** Same **`Login Page.js`** — hardcoded credentials in **`Create Login Page`** commit.
- **Evidence:**

  ```text
  username: EMarseille99
  password: UGljYXNzb0JhZ3VldHRlOTk=   (Base64)
  ```

  Decode (CyberChef / `echo ... | base64 -d`):

  ```text
  PicassoBaguette99
  ```

- **Reasoning:** Base64 is encoding, not encryption — trivial to recover plaintext.

**Answer:** **`PicassoBaguette99`**

---

### T3 — Cryptocurrency mining tool

**Question:** What cryptocurrency mining tool did the insider use?

- **What I checked:** Forked repositories on **`EMarseille99`** GitHub profile.
- **Evidence:** Forked repo **`xmrig`** — description **"CPU/GPU miner"** (Monero / CryptoNight / Argon2).
- **Reasoning:** **XMRig** is a well-known Monero miner; fork indicates interest/use for unauthorized mining on corporate resources.

**Answer:** **`xmrig`**

---

### T4 — University attended

**Question:** What university did the insider go to?

- **What I checked:** GitHub bio (works at **Software Consultants Inc.**) → Google/LinkedIn for **Emilie Marseille**.
- **Evidence:** LinkedIn education: **Sorbonne** (Paris).
- **Reasoning:** Cross-platform identity correlation (GitHub avatar + employer + name → LinkedIn education).

**Answer:** **`Sorbonne`**

---

### T5 — Gaming website account

**Question:** On which gaming website did the insider have an account?

- **What I checked:** Username search (**`EMarseille99`**) / Sherlock; Instagram posts for cross-links.
- **Evidence:** Instagram post contains a **QR code** linking to a **Steam** profile; Sherlock also hits **Steam Community** for **`EMarseille99`**.
- **Reasoning:** Gaming platform account confirmed via social post QR and username enumeration.

**Answer:** **`steam`**

---

### T6 — Instagram profile link

**Question:** What is the link to the insider Instagram profile?

- **What I checked:** Google search for **`EMarseille99`** / **Emilie Marseille**; compare profile photo to GitHub avatar.
- **Evidence:** Matching avatar and display name on Instagram.

**Answer:** **`https://www.instagram.com/emarseille99/`**

---

### T7 — Holiday destination (country)

**Question:** Which country did the insider visit on her holiday?

- **What I checked:** Instagram travel posts.
- **Evidence:** Post caption references holiday; photo shows **Gardens by the Bay** (Singapore landmark — Supertree Grove).
- **Reasoning:** Distinctive architecture identifies **Singapore** without reverse image search.

**Answer:** **`Singapore`**

---

### T8 — Family residence (city)

**Question:** Which city does the insider family live in?

- **What I checked:** Instagram posts about visiting family/friends.
- **Evidence:** Photo includes **Burj Khalifa** skyline.
- **Reasoning:** Burj Khalifa is in **Dubai**, UAE — family location from travel/family visit posts.

**Answer:** **`Dubai`**

---

### T9 — Company office city (`office.jpg`)

**Question:** You have been provided with a picture of the building in which the company has an office. Which city is the company located in?

- **What I checked:** Visual landmarks in **`office.jpg`** — street signs, theatre names.
- **Evidence:**
  - **ODEON** cinema sign → UK
  - **Hippodrome Theatre** / **Chinese Quarter** signage
  - **Alexandra Theatre** area → **Birmingham**, England
- **Reasoning:** UK cinema chain + Hippodrome/Chinese Quarter narrows to **Birmingham** (vs. other UK cities).

**Answer:** **`birmingham`**

---

### T10 — Webcam state (`Webcam.png`)

**Question:** Our intelligence team spotted the target with this IP camera. Which state is this camera in?

- **What I checked:** **`Webcam.png`** — **EarthCam** watermark; EarthCam advanced search (US → Campus Views).
- **Evidence:** View matches **University of Notre Dame** live EarthCam; campus is in **South Bend, Indiana**.
- **Reasoning:** Lab asks for **state** (US context); Notre Dame → **Indiana**. Bing/image search also resolves this feed.

**Answer:** **`Indiana`**

---

## Insider Profile (reconstructed)

| Field | Value |
|-------|-------|
| **GitHub** | [EMarseille99](https://github.com/EMarseille99) |
| **Name** | Emilie Marseille |
| **Employer (GitHub)** | Software Consultants Inc. |
| **University** | Sorbonne |
| **Instagram** | https://www.instagram.com/emarseille99/ |
| **Gaming** | Steam (`EMarseille99`) |

---

## Attack / Abuse Actions

1. **Secrets in source control** — API key and Base64-encoded password in public GitHub repo.
2. **Cryptomining** — fork/interest in **xmrig** (unauthorized resource abuse on corporate network).
3. **Insider origin** — compromise traced to this single account per IR preliminary findings.

---

## Key IOCs / Intelligence

| Type | Indicator |
|------|-----------|
| **GitHub user** | `EMarseille99` |
| **Repo (secrets)** | `Project-Build---Custom-Login-Page` / `Login Page.js` |
| **API key** | `aJFRaLHjMXvYZgLPwiJkroYLGRkNBW` |
| **Password** | `PicassoBaguette99` (from Base64 `UGljYXNzb0JhZ3VldHRlOTk=`) |
| **Miner** | xmrig |
| **Instagram** | `https://www.instagram.com/emarseille99/` |
| **Company office city** | Birmingham, UK |
| **Last known location (cam)** | Notre Dame, Indiana, USA |

---

## MITRE ATT&CK (insider / abuse)

| Technique | Name |
|-----------|------|
| **T1552.001** | Unsecured Credentials: Credentials in Files (GitHub) |
| **T1496** | Resource Hijacking (cryptomining) |
| **T1078** | Valid Accounts (insider account) |
| **T1589** | Gather Victim Identity Information (attacker OSINT — defensive mirror) |

---

## Mitigation / Hardening

- Scan GitHub/org repos for secrets (API keys, encoded passwords); enforce pre-commit hooks and **GitHub secret scanning**.
- Rotate exposed API key **`aJFRaLHjMXvYZgLPwiJkroYLGRkNBW`** and force password reset for **`EMarseille99`**.
- Block/limit cryptominer binaries and pool traffic; monitor CPU spikes and **xmrig** process hashes.
- Insider-threat program: least privilege, DLP on code repos, egress monitoring.
- OPSEC training — employees should not post QR codes / location tags linking work identity to personal accounts.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/lespion/
- GitHub profile: https://github.com/EMarseille99
- EarthCam (Notre Dame): https://www.earthcam.com/
