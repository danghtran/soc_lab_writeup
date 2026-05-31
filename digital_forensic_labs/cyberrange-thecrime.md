# CyberDefenders - The Crime (Android Forensics) Write-up

**Challenge:** [The Crime](https://cyberdefenders.org/blueteam-ctf-challenges/the-crime/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Android forensics, SQLite, mobile artifact analysis

---

## Summary

A murder investigation centers on the **victim’s Android phone** (filesystem dump). Artifact review shows heavy **Olymp Trade** use (`com.ticno.olymptrade`), **250,000 EGP** debt to **Shady Wahab** (`+201172137258`), departure to **The Nile Ritz-Carlton** on **2023-09-20**, a **Cairo → Las Vegas** flight ticket for **2023-10-01**, and a Discord meet-up at **The Mob Museum** in Las Vegas.

---

## Scenario

We're currently in the midst of a murder investigation, and we've obtained the victim's phone as a key piece of evidence. After conducting interviews with witnesses and those in the victim's inner circle, analyze the information gathered and trace the evidence to piece together the sequence of events leading up to the incident.

---

## Objectives

- Parse Android app, messaging, contacts, location, download, and chat artifacts.
- Reconstruct financial pressure, travel, and social plans before the incident.

---

## Environment

- **Artifact:** Android filesystem dump (ZIP password: `cyberdefenders.org`)
- **Tools used:**
  - [ALEAPP](https://github.com/abrignoni/ALEAPP) — installed apps, SMS, Discord (optional bulk parse)
  - [DB Browser for SQLite](https://sqlitebrowser.org/) — `mmssms.db`, `calllog.db`, `gmm_storage.db`, Discord KV stores
  - `sqlite3` CLI — targeted queries
  - `Get-FileHash` / `sha256sum` — APK hash verification (alternate for T1)

**Typical dump layout (paths relative to extract root):**

```text
data/app/                          # installed APKs
data/com.google.android.gms/databases/
user_de/0/com.android.providers.telephony/databases/
data/com.android.providers.contacts/databases/
data/data/com.google.android.apps.maps/databases/
media/0/Download/
data/data/com.discord/files/
```

---

## Evidence & Findings

### T1 — SHA256 of primary trading application

**Question:** Can you identify the SHA256 of the trading application the victim primarily used on his phone?

- **What I checked:** Google Play Services **`gass.db`** (`data/com.google.android.gms/databases/`) — stores app integrity / package metadata including hashes; also confirm via **`data/app/`** for `com.ticno.olymptrade`.
- **Evidence:**

  ```text
  Package: com.ticno.olymptrade
  SHA256:  4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c
  ```

  Alternate verification: hash `base.apk` under `data/app/com.ticno.olymptrade-*/` or ALEAPP **Installed Apps** report.

- **Reasoning:** Witnesses cited trading addiction; **`com.ticno.olymptrade`** is **Olymp Trade** — the only trading app in the user app set alongside Discord.

**Answer:** **`4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c`**

---

### T2 — Amount owed

**Question:** How much does the victim owe this person?

- **What I checked:** SMS database **`mmssms.db`** — `user_de/0/com.android.providers.telephony/databases/mmssms.db`.
- **Evidence:** Threat / collection SMS from **`+201172137258`** demanding repayment of **250000** (EGP).
- **Reasoning:** Matches best-friend testimony about avoided calls and unrepayable debt.

**Answer:** **`250000`**

---

### T3 — Creditor name

**Question:** What is the name of the person to whom the victim owes money?

- **What I checked:** **`calllog.db`** — `data/com.android.providers.contacts/databases/calllog.db` — correlate creditor number from SMS.
- **Evidence:**

  ```sql
  SELECT name, normalized_number
  FROM calls
  WHERE normalized_number = '+201172137258';
  ```

  ```text
  Shady Wahab | +201172137258
  ```

- **Reasoning:** Call log links the Egyptian MSISDN to a saved/display name.

**Answer:** **`Shady Wahab`**

---

### T4 — Location on departure (2023-09-20)

**Question:** On September 20, 2023, he departed from his residence without informing anyone. Where was the victim located at that moment?

- **What I checked:** Google Maps **`gmm_storage.db`** — `data/data/com.google.android.apps.maps/databases/gmm_storage.db` — timeline / place history around **2023-09-20**.
- **Evidence:** Records for **2023-09-20** (and adjacent **2023-09-21**) reference **The Nile Ritz-Carlton, Cairo**.

  *Alternate artifact:* `system_ce/0/snapshots/` task snapshot may show the same hotel UI on back-navigation capture.

- **Reasoning:** Family stated he left home that day without notice; Maps history places him at the Ritz-Carlton on the Nile in **Cairo**.

**Answer:** **`The Nile Ritz-Carlton`**

---

### T5 — Intended travel destination

**Question:** The victim reserved the hotel for 10 days and had a flight scheduled thereafter. Where did the victim intend to travel?

- **What I checked:** **`media/0/Download/`** for saved travel documents.
- **Evidence:** File **`Plane Ticket.png`** — flight **Cairo → Las Vegas**, date **2023-10-01** (10 days after hotel check-in aligns with lobby statement).
- **Reasoning:** Ticket stored locally in Downloads is the victim’s planned post-hotel destination.

**Answer:** **`Las Vegas`**

---

### T6 — Discord meeting location

**Question:** Where was the victim supposed to meet a friend (per Discord)?

- **What I checked:** Discord local storage — `data/data/com.discord/files/kv-storage/@account.<id>/a-wal` (message cache).
- **Evidence:** Message content (timestamp **2023-09-20**):

  ```text
  What a wonderful news! We'll meet at **The Mob Museum**, I'll await your call when you arrive.
  Enjoy you flight bro ❤️
  ```

- **Reasoning:** **The Mob Museum** (National Museum of Organized Crime and Law Enforcement) is a Las Vegas landmark — consistent with the Vegas flight ticket and Discord plan.

**Answer:** **`The Mob Museum`**

---

## Timeline (reconstructed)

| Date / period | Event |
|---------------|--------|
| Pre-incident | Heavy **Olymp Trade** use; debt **250,000 EGP** to **Shady Wahab** |
| **2023-09-20** | Leaves home; Maps / snapshot → **The Nile Ritz-Carlton**, Cairo |
| **2023-09-20** | Discord: meet at **The Mob Museum** after flight |
| Hotel stay | ~**10 days** (lobby testimony) |
| **2023-10-01** | Planned flight **Cairo → Las Vegas** (`Plane Ticket.png`) |
| Las Vegas | Intended meet-up: **The Mob Museum** |

---

## Key artifacts & IOCs

| Artifact | Path / value |
|----------|----------------|
| **Trading app** | `com.ticno.olymptrade` (Olymp Trade) |
| **APK SHA256** | `4f168a772350f283a1c49e78c1548d7c2c6c05106d8b9feb825fdc3466e9df3c` |
| **Creditor** | Shady Wahab, `+201172137258` |
| **Debt** | 250000 EGP |
| **Hotel (Cairo)** | The Nile Ritz-Carlton |
| **Flight ticket** | `media/0/Download/Plane Ticket.png` → Las Vegas |
| **Meet-up** | The Mob Museum, Las Vegas |
| **Discord user (friend)** | `rob1ns0n.` / `0xR0b1n50N` (from KV JSON) |

---

## MITRE ATT&CK (context)

This lab is investigative forensics, not malware triage. Relevant **victim-side** framing:

| Technique | Name | Notes |
|-----------|------|--------|
| **T1589** | Gather Victim Identity Information | Threat actors; here, investigators reconstruct victim actions |
| **T1071** | Application Layer Protocol | Discord coordination |
| **Financial abuse** | — | Debt collection / trading losses as motive context |

---

## Lessons / methodology

1. **Map artifact → question** — SMS (`mmssms.db`), calls (`calllog.db`), Maps (`gmm_storage.db`), Downloads, Discord KV.
2. **Cross-correlate** — phone number in SMS → name in call log; Cairo hotel → Vegas ticket → Vegas Discord venue.
3. **Validate hashes** — GMS `gass.db`, ALEAPP, or direct `base.apk` SHA256 should match.
4. **Watch path typos** on dumps: `providers` (plural), `apps.maps` (not `app.map`).

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/the-crime/
- ALEAPP: https://github.com/abrignoni/ALEAPP
