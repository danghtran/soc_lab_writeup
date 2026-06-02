# CyberDefenders - DanaBot (PCAP / Threat Intel) Write-up

**Challenge:** [DanaBot](https://cyberdefenders.org/blueteam-ctf-challenges/danabot/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, Wireshark, DanaBot, infostealer

---

## Summary

SOC detected a compromised host and stolen company data. PCAP analysis shows DNS to **`portfolio.serveirc.com`** resolving to **`62.173.142.148`**, HTTP delivery of obfuscated JS dropper **`allegato_708.js`** (via **`GET /login.php`**), execution by **`wscript.exe`**, then download of second-stage **`resources.dll`** (MD5 **`e758e07113016aca55d9eda2b0ffeebe`**) — consistent with **DanaBot** banking/infostealer behavior.

---

## Scenario

The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen.

---

## Objectives

- Use the network capture (PCAP) and threat intelligence to investigate the incident.
- Determine how the breach occurred: attacker infrastructure, initial payload, execution, and second-stage malware.

---

## Environment

- **Artifact:** DanaBot PCAP (lab package, e.g. `205-DanaBot.pcap`)
- **Tools:** Wireshark, WHOIS/reputation lookup, `sha256sum` / `md5sum` (or CyberChef)

**Useful filters:**

```text
dns
ip.src == 62.173.142.148
http.response.code == 200
http.request.uri contains "login.php"
```

---

## Evidence & Findings (Wireshark)

### T1 — Attacker IP (initial access)

**Question:** Which IP address was used by the attacker during the initial access?

- **What I checked:** DNS responses for suspicious hostnames (`dns` filter).
- **Evidence:** Packet **2** — DNS answer for **`portfolio.serveirc.com`** → **`62.173.142.148`**. WHOIS/reputation checks flag the host as malicious external infrastructure.

  ![Wireshark — DNS response for portfolio.serveirc.com](images/wireshark_dns_response.png)

- **Reasoning:** First contact with attacker-controlled domain resolves to this IP; subsequent HTTP downloads originate from **`62.173.142.148`**.

**Answer:** **`62.173.142.148`**

---

### T2 — Initial access malicious file name

**Question:** What is the name of the malicious file used for initial access?

- **What I checked:** `ip.src == 62.173.142.148` — HTTP flows with **200 OK**; **Follow HTTP Stream** (stream 0).
- **Evidence:** **`GET /login.php`** response includes:

  ```http
  Content-Disposition: attachment; filename=allegato_708.js
  Content-Type: application/octet-stream
  ```

  Body is heavily obfuscated JavaScript (dropper), not a login page.

- **Reasoning:** Filename in **Content-Disposition** is the delivered malware name despite the **`/login.php`** URI.

**Answer:** **`allegato_708.js`**

---

### T3 — SHA-256 of initial malicious file

**Question:** What is the SHA-256 hash of the malicious file used for initial access?

- **What I checked:** **File → Export Objects → HTTP** — export object from packet **11** (saved as **`login.php`** in object list; content = **`allegato_708.js`** payload). Hash with `sha256sum` or VT/ANY.RUN.
- **Evidence:**

  ```bash
  sha256sum login.php
  # 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268
  ```

- **Reasoning:** Wireshark names the HTTP object after the URI path; the file content matches **`allegato_708.js`** from T2.

**Answer:** **`847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`**

---

### T4 — Process used to execute malicious file

**Question:** Which process was used to execute the malicious file?

- **What I checked:** Sandbox reports (VT/ANY.RUN) for the JS hash; process creation in PCAP-related analysis.
- **Evidence:** **Windows Script Host** — **`wscript.exe`** executes the `.js` dropper (obfuscated script in exported payload).

  ![Wireshark / sandbox — WScript executes malicious JS](images/wireshark_mal_js.png)

- **Reasoning:** `.js` malware on Windows is typically launched via **`wscript.exe`** or **`cscript.exe`**; lab/sandbox confirms **`wscript.exe`**.

**Answer:** **`wscript.exe`** (also seen as **`WScript.exe`**)

---

### T5 — Second malicious file extension

**Question:** What is the file extension of the second malicious file utilized by the attacker?

- **What I checked:** `http.response.code == 200` — **Follow HTTP Stream** at packet **9952**.
- **Evidence:** **`GET`** request / response for **`resources.dll`** (second-stage payload after JS deobfuscation downloads from attacker infrastructure, e.g. **`soundata.top`** in related campaigns).
- **Reasoning:** DanaBot JS dropper fetches a DLL loaded with **`rundll32.exe`** — extension **`.dll`**.

**Answer:** **`.dll`**

---

### T6 — MD5 of second malicious file

**Question:** What is the MD5 hash of the second malicious file?

- **What I checked:** **File → Export Objects → HTTP** — export **`resources.dll`**; compute MD5.
- **Evidence:**

  ```bash
  md5sum resources.dll
  # e758e07113016aca55d9eda2b0ffeebe
  ```

- **Reasoning:** Hash uniquely identifies the second-stage DanaBot module for blocking and hunting.

**Answer:** **`e758e07113016aca55d9eda2b0ffeebe`**

---

## Attack Reconstruction

```text
[Victim] DNS query → portfolio.serveirc.com
        |
        v
62.173.142.148 — HTTP GET /login.php
        |
        v
Deliver: allegato_708.js (obfuscated JS dropper)
        |
        v
wscript.exe executes JS
        |
        v
HTTP download: resources.dll (.dll)
        |
        v
rundll32.exe loads DLL → DanaBot infostealer / credential theft
```

1. User/victim resolves typosquat-style domain **`portfolio.serveirc.com`**.
2. Attacker IP **`62.173.142.148`** serves **`allegato_708.js`** disguised as **`login.php`**.
3. **`wscript.exe`** runs the script.
4. Second stage **`resources.dll`** downloaded and executed (typically via **`rundll32.exe`**).
5. Sensitive data exfiltration (DanaBot banking/info-stealer behavior).

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Attacker IP** | `62.173.142.148` |
| **Domain** | `portfolio.serveirc.com` |
| **Initial URI** | `/login.php` |
| **JS dropper** | `allegato_708.js` |
| **JS SHA-256** | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` |
| **Executor** | `wscript.exe` |
| **Second stage** | `resources.dll` |
| **DLL MD5** | `e758e07113016aca55d9eda2b0ffeebe` |
| **Malware family** | DanaBot |

---

## MITRE ATT&CK

| Technique | Name |
|-----------|------|
| **T1189** | Drive-by Compromise |
| **T1071.001** | Application Layer Protocol: Web (HTTP delivery) |
| **T1059.007** | Command and Scripting Interpreter: JavaScript |
| **T1105** | Ingress Tool Transfer (`resources.dll`) |
| **T1218.011** | Signed Binary Proxy Execution: Rundll32 (typical DLL load) |
| **T1555** | Credentials from Password Stores (DanaBot objective) |

---

## Mitigation / Hardening

- Block **`62.173.142.148`** and **`portfolio.serveirc.com`** at DNS/firewall/proxy.
- Hunt for **`allegato_708.js`**, hash **`847b4ad9...`**, and **`resources.dll`** / MD5 **`e758e071...`**.
- Restrict **`wscript.exe`** / **`cscript.exe`** where not required (AppLocker/WDAC).
- Monitor **`rundll32.exe`** loading DLLs from `%TEMP%` or unusual HTTP-download paths.
- User training on phishing and malicious attachment/download lures (Italian filename **`allegato_`** = “attachment”).

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/danabot/
- ANY.RUN report (JS hash): https://any.run/report/847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268/
