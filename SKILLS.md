# Skills Index

Compact index of labs and skill tags that I learned after each lab.

---

## Skill tags (taxonomy)

Reuse these across labs. Expand only when something is genuinely new.

| Tag | Meaning |
|-----|---------|
| `ntfs-usn` | USN Journal (`$J`) parsing and filtering |
| `mft` | MFT entry / filesystem metadata correlation |
| `host-timeline` | File activity chronology on Windows |
| `cli-awk` | CSV/log filtering with awk/grep |
| `insider-threat` | Staging, versioning, local data theft indicators |
| `misp` | MISP events, attributes, objects, tags |
| `cti-enrichment` | Defanging, IP/geo lookup, TLP |
| `campaign-analysis` | Threat actor / campaign classification |
| `splunk` | SIEM search and correlation |
| `alert-triage` | True vs false positive decisions |
| `phishing` | Email lures, typosquat, URL shorteners |
| `firewall-logs` | Blocked vs allowed egress |
| `incident-report` | Structured SOC case documentation |
| `pcap` | Packet capture triage |
| `wireshark` | HTTP streams, protocol analysis |
| `web-shell` | Upload bypass, PHP shells, web paths |
| `c2-network` | C2 URLs, reverse shells, ports |
| `virustotal` | VT history, relations, behavior |
| `sandbox` | ANY.RUN / dynamic analysis |
| `malware-config` | Stealer config, encryption keys (e.g. RC4) |
| `mitre-map` | Map behavior to ATT&CK IDs |
| `evasion` | Self-delete, cleanup commands |
| `ioc` | Extract and document indicators |
| `mfecmd` | Eric Zimmerman MFTECmd |
| `tor-privacy` | Privacy tools as cover-tracks signal |

**Tools** (optional extra column): `MFTECmd`, `Splunk`, `Wireshark`, `VirusTotal`, `ANY.RUN`, `CyberChef`

---

## Labs

| Lab | Write-up | Tags | MITRE (highlight) |
|-----|----------|------|-------------------|
| **Curiosity** | [btlo-curiosity.md](digital_forensic_labs/btlo-curiosity.md) | `ntfs-usn`, `mft`, `host-timeline`, `cli-awk`, `insider-threat`, `ioc`, `mfecmd`, `tor-privacy` | Collection, Exfiltration |
| **Gifted Crooks** | [btlo-giftedcrooks.md](threat_intelligence_labs/btlo-giftedcrooks.md) | `misp`, `cti-enrichment`, `campaign-analysis`, `ioc` | T1071 (C2 in intel) |
| **Introduction to Phishing** | [thm-phishing.md](soc_triage_labs/thm-phishing.md) | `splunk`, `alert-triage`, `phishing`, `firewall-logs`, `incident-report` | T1566 |
| **WebStrike** | [cyberrange-webstrike.md](soc_triage_labs/cyberrange-webstrike.md) | `pcap`, `wireshark`, `web-shell`, `c2-network`, `ioc` | T1190, T1505, T1071 |
| **Oski** | [cyberrange-oski.md](threat_intelligence_labs/cyberrange-oski.md) | `virustotal`, `sandbox`, `malware-config`, `mitre-map`, `c2-network`, `evasion`, `ioc` | T1555, T1071 |

---

## By tag (quick lookup)

| Tag | Labs |
|-----|------|
| `splunk` | Introduction to Phishing |
| `misp` | Gifted Crooks |
| `virustotal` | Oski |
| `wireshark` | WebStrike |
| `ntfs-usn` | Curiosity |
| `phishing` | Introduction to Phishing, Oski (delivery) |
| `c2-network` | Gifted Crooks, WebStrike, Oski |
| `ioc` | All |
