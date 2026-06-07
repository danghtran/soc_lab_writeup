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
| `llmnr-nbns` | LLMNR / NBT-NS poisoning, mistyped name queries |
| `ntlm-smb` | SMB2 session setup, NTLMSSP auth and relay |
| `memory-forensics` | RAM dump analysis, process/network artifacts |
| `volatility` | Volatility 3 plugins (pstree, cmdline, netscan, filescan) |
| `osint` | Open-source profiling, social/geo correlation, image search |
| `android-forensics` | Android FS dump, app/SMS/location/chat artifacts |
| `sqlite` | Android SQLite DBs (mmssms, calllog, Maps, Discord KV) |
| `supply-chain` | Trojanized vendor builds, signed-update compromise |
| `linux-forensics` | Linux disk image, bash history, auth/syslog |
| `browser-extension` | Chrome extension manifest, content scripts, exfil |
| `ics-ot` | PLC/CIP/SCADA, Dragos industrial telemetry |

**Tools** (optional extra column): `MFTECmd`, `Splunk`, `Wireshark`, `VirusTotal`, `ANY.RUN`, `CyberChef`, `Volatility 3`, `Sherlock`, `ALEAPP`, `DB Browser for SQLite`, `MalwareBazaar`, `ThreatFox`, `FTK Imager`, `Dragos`

---

## Labs

| Lab | Write-up | Tags | MITRE (highlight) |
|-----|----------|------|-------------------|
| **Curiosity** | [btlo-curiosity.md](digital_forensic_labs/btlo-curiosity.md) | `ntfs-usn`, `mft`, `host-timeline`, `cli-awk`, `insider-threat`, `ioc`, `mfecmd`, `tor-privacy` | Collection, Exfiltration |
| **Gifted Crooks** | [btlo-giftedcrooks.md](threat_intelligence_labs/btlo-giftedcrooks.md) | `misp`, `cti-enrichment`, `campaign-analysis`, `ioc` | T1071 (C2 in intel) |
| **Introduction to Phishing** | [thm-phishing.md](soc_triage_labs/thm-phishing.md) | `splunk`, `alert-triage`, `phishing`, `firewall-logs`, `incident-report` | T1566 |
| **WebStrike** | [cyberrange-webstrike.md](soc_triage_labs/cyberrange-webstrike.md) | `pcap`, `wireshark`, `web-shell`, `c2-network`, `ioc` | T1190, T1505, T1071 |
| **Oski** | [cyberrange-oski.md](threat_intelligence_labs/cyberrange-oski.md) | `virustotal`, `sandbox`, `malware-config`, `mitre-map`, `c2-network`, `evasion`, `ioc` | T1555, T1071 |
| **Poisoned Credentials** | [cyberrange-poisonedcredential.md](digital_forensic_labs/cyberrange-poisonedcredential.md) | `pcap`, `wireshark`, `llmnr-nbns`, `ntlm-smb`, `mitre-map`, `ioc` | T1557.001, T1021.002 |
| **Yellow RAT** | [cyberrange-yellowrat.md](threat_intelligence_labs/cyberrange-yellowrat.md) | `virustotal`, `c2-network`, `ioc`, `mitre-map`, `campaign-analysis` | T1219, T1071 |
| **Amadey APT-C-36** | [cyberrange-apt-c36.md](digital_forensic_labs/cyberrange-apt-c36.md) | `memory-forensics`, `volatility`, `c2-network`, `mitre-map`, `ioc`, `evasion` | T1036, T1071, T1218, T1053 |
| **L'espion** | [cyberrange-lespion.md](threat_intelligence_labs/cyberrange-lespion.md) | `osint`, `insider-threat`, `cti-enrichment`, `ioc`, `mitre-map` | T1552, T1496, T1078 |
| **The Crime** | [cyberrange-thecrime.md](digital_forensic_labs/cyberrange-thecrime.md) | `android-forensics`, `sqlite`, `host-timeline`, `ioc` | — |
| **PsExec Hunt** | [cyberrange-psexechunt.md](digital_forensic_labs/cyberrange-psexechunt.md) | `pcap`, `wireshark`, `ntlm-smb`, `mitre-map`, `ioc`, `alert-triage` | T1021.002, T1569.002, T1570 |
| **Red Stealer** | [cyberrange-redstealer.md](threat_intelligence_labs/cyberrange-redstealer.md) | `virustotal`, `cti-enrichment`, `mitre-map`, `c2-network`, `ioc` | T1005, T1071, T1134, T1555 |
| **3CX Supply Chain** | [cyberrange-3cxsupplychain.md](threat_intelligence_labs/cyberrange-3cxsupplychain.md) | `virustotal`, `supply-chain`, `mitre-map`, `evasion`, `malware-config`, `campaign-analysis`, `ioc` | T1195, T1574, T1497 |
| **DanaBot** | [cyberrange-danabot.md](digital_forensic_labs/cyberrange-danabot.md) | `pcap`, `wireshark`, `c2-network`, `mitre-map`, `ioc`, `cti-enrichment` | T1189, T1059, T1105, T1218 |
| **Insider** | [cyberrange-insider.md](digital_forensic_labs/cyberrange-insider.md) | `linux-forensics`, `insider-threat`, `host-timeline`, `mitre-map`, `ioc` | T1003, T1078, T1059 |
| **Ramnit** | [cyberrange-ramnit.md](digital_forensic_labs/cyberrange-ramnit.md) | `memory-forensics`, `volatility`, `virustotal`, `cti-enrichment`, `c2-network`, `mitre-map`, `ioc`, `evasion` | T1036, T1071, T1555 |
| **GrabThePhisher** | [cyberrange-grabthephisher.md](threat_intelligence_labs/cyberrange-grabthephisher.md) | `phishing`, `web-shell`, `c2-network`, `cti-enrichment`, `mitre-map`, `ioc` | T1566, T1041, T1056 |
| **FakeGPT** | [cyberrange-fakegpt.md](malware_analysis/cyberrange-fakegpt.md) | `browser-extension`, `malware-config`, `evasion`, `c2-network`, `mitre-map`, `ioc`, `phishing` | T1176, T1056, T1539, T1497 |
| **Dragos 1UP (BOTS)** | [splunkboss-drago.md](soc_triage_labs/splunkboss-drago.md) | `splunk`, `ics-ot`, `alert-triage`, `c2-network`, `mitre-map`, `ioc`, `incident-report` | T0855, T1210, T1219 |
| **Lockdown** | [cyberrange-lockdown.md](digital_forensic_labs/cyberrange-lockdown.md) | `pcap`, `wireshark`, `web-shell`, `ntlm-smb`, `memory-forensics`, `volatility`, `virustotal`, `c2-network`, `mitre-map`, `ioc`, `evasion` | T1190, T1505.003, T1547.001 |

---

## By tag (quick lookup)

| Tag | Labs |
|-----|------|
| `splunk` | Introduction to Phishing, Dragos 1UP (BOTS) |
| `ics-ot` | Dragos 1UP (BOTS) |
| `alert-triage` | Introduction to Phishing, PsExec Hunt, Dragos 1UP (BOTS) |
| `incident-report` | Introduction to Phishing, Dragos 1UP (BOTS) |
| `misp` | Gifted Crooks |
| `virustotal` | Oski, Yellow RAT, Red Stealer, 3CX Supply Chain, Ramnit, Lockdown |
| `supply-chain` | 3CX Supply Chain |
| `campaign-analysis` | Gifted Crooks, Yellow RAT, 3CX Supply Chain |
| `wireshark` | WebStrike, Poisoned Credentials, PsExec Hunt, DanaBot, Lockdown |
| `pcap` | WebStrike, Poisoned Credentials, PsExec Hunt, DanaBot, Lockdown |
| `cti-enrichment` | Gifted Crooks, L'espion, Red Stealer, DanaBot, Ramnit, GrabThePhisher |
| `llmnr-nbns` | Poisoned Credentials |
| `ntlm-smb` | Poisoned Credentials, PsExec Hunt, Lockdown |
| `ntfs-usn` | Curiosity |
| `phishing` | Introduction to Phishing, Oski (delivery), GrabThePhisher, FakeGPT |
| `browser-extension` | FakeGPT |
| `malware-config` | Oski, 3CX Supply Chain, FakeGPT |
| `evasion` | Oski, Amadey APT-C-36, 3CX Supply Chain, Ramnit, FakeGPT, Lockdown |
| `web-shell` | WebStrike, GrabThePhisher, Lockdown |
| `c2-network` | Gifted Crooks, WebStrike, Oski, Yellow RAT, Amadey APT-C-36, Red Stealer, DanaBot, Ramnit, GrabThePhisher, FakeGPT, Dragos 1UP (BOTS), Lockdown |
| `memory-forensics` | Amadey APT-C-36, Ramnit, Lockdown |
| `volatility` | Amadey APT-C-36, Ramnit, Lockdown |
| `osint` | L'espion |
| `insider-threat` | Curiosity, L'espion, Insider |
| `linux-forensics` | Insider |
| `host-timeline` | Curiosity, The Crime, Insider |
| `android-forensics` | The Crime |
| `sqlite` | The Crime |
| `ioc` | All |
