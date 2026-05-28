# Skills by Lab

Skills practiced in each investigation write-up in this repository.

---

## Curiosity (BTLO) — Digital forensics / host investigation

**Write-up:** [`digital_forensic_labs/btlo-curiosity.md`](digital_forensic_labs/btlo-curiosity.md)

**Focus:** Determine whether an employee possessed, staged, or archived sensitive product data on a Windows workstation.

| Skill area | What you practice |
|------------|-------------------|
| **NTFS forensics** | Parse and query the USN Journal (`$J`) for file create/overwrite/extend events |
| **MFT correlation** | Use MFT entry numbers from USN output to identify versioned archives |
| **Timeline analysis** | Reconstruct file activity chronology (onboarding archives → staging → cover tracks) |
| **Data filtering** | `awk`/CLI deduplication on CSV exports (`FileCreate`, extensions, filename patterns) |
| **Insider-threat indicators** | Identify staging (`Files.zip`), project codenames (`homepilot`), versioning behavior |
| **IOC development** | Document archives, scripts, and suspicious executables (e.g., Tor Browser portable) |
| **Tooling** | Eric Zimmerman tooling (`Get-ZimmermanTools`, **MFTECmd**) |

---

## Gifted Crooks (BTLO) — Threat intelligence

**Write-up:** [`threat_intelligence_labs/btlo-giftedcrooks.md`](threat_intelligence_labs/btlo-giftedcrooks.md)

**Focus:** Navigate MISP and extract intelligence from Event **10128** (UAC-0226 / GIFTEDCROOK).

| Skill area | What you practice |
|------------|-------------------|
| **MISP operations** | Event metadata, attributes, objects, categories, and tags |
| **Campaign classification** | Map alert context to campaign type (e.g., cyber-espionage) and issuing authority |
| **IOC extraction** | File extensions, script names, dropped artifacts, network C2 (IP:port) |
| **Safe sharing** | Defang IPs/URLs (CyberChef) before documenting or sharing |
| **IOC enrichment** | ICANN IP Lookup for C2 geolocation |
| **Handling labels** | TLP tags (`tlp:clear`) and sharing constraints |
| **Reporting** | Structured CTI answers tied to event provenance (publisher, publish date, org) |

---

## Introduction to Phishing (TryHackMe) — SOC triage

**Write-up:** [`soc_triage_labs/thm-phishing.md`](soc_triage_labs/thm-phishing.md)

**Focus:** Triage four phishing-related alerts and complete incident reports in Splunk.

| Skill area | What you practice |
|------------|-------------------|
| **SIEM search** | Splunk queries across `email` and `firewall` datasources |
| **Alert triage** | True positive vs false positive decision-making |
| **Phishing analysis** | Urgency lures, typosquatting (`m1crosoft`), suspicious TLDs (`amazon.biz`), URL shorteners |
| **Log correlation** | Tie email recipients to `SourceIP` and outbound URL clicks |
| **Control validation** | Interpret `action=blocked` vs `action=allowed` firewall outcomes |
| **Incident reporting** | Document affected entities, escalation rationale, remediation (awareness, password reset) |
| **Risk prioritization** | Blocked click (contain) vs allowed click (credential reset, audit) |

---

## WebStrike (CyberDefenders) — SOC triage / network forensics (PCAP)

**Write-up:** [`soc_triage_labs/cyberrange-webstrike.md`](soc_triage_labs/cyberrange-webstrike.md)

**Focus:** Investigate a web server compromise using a PCAP (file upload bypass → web shell → reverse shell → exfil attempt).

| Skill area | What you practice |
|------------|-------------------|
| **PCAP triage** | Identify suspicious HTTP methods/paths and pivot to attacker conversations |
| **Wireshark workflow** | Follow HTTP streams, extract headers, and read multipart/form-data uploads |
| **Web attack analysis** | Understand upload validation bypass via double extensions (e.g., `.jpg.php`) |
| **Web shell detection** | Identify PHP web shell payloads and post-upload access paths |
| **C2 / reverse shell identification** | Extract attacker IP/port from shell command (netcat reverse shell) |
| **Data access/exfil indicators** | Detect sensitive file targeting (e.g., `/etc/passwd`) and POST-based exfil attempts |
| **IOC documentation** | Record attacker IP, user-agents, malicious filename, upload directory, and ports |
