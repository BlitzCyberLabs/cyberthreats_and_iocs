# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting
## Official Question Bank, Hints & Final Answers Key

---

## 📋 Table of Contents
1. [Part 1: Quick Walkthrough - How to Perform the Lab](#part-1-quick-walkthrough---how-to-perform-the-lab)
2. [Part 2: Questions, Hints & Final Answers](#part-2-questions-hints--final-answers)
   - [Section 1: Web Log Fundamentals](#section-1-web-log-fundamentals)
   - [Section 2: SQL Injection Forensics](#section-2-sql-injection-forensics)
   - [Section 3: Cross-Site Scripting (XSS) Forensics](#section-3-cross-site-scripting-xss-forensics)
   - [Section 4: Authentication Brute Force Forensics](#section-4-authentication-brute-force-forensics)
   - [Section 5: Capstone Threat Actor Incident Investigation](#section-5-capstone-threat-actor-incident-investigation)
3. [Part 3: Master Flags Summary](#part-3-master-flags-summary)

---

## Part 1: Quick Walkthrough - How to Perform the Lab

### 1. SQL Injection Attack & Detection
1. In the **Target Application**, navigate to **"🔍 Catalog & Search"**.
2. Enter the union-based SQL injection query into the search box:
   ```sql
   ' UNION SELECT 1,username,password,email,role FROM users--
   ```
3. The catalog dumps the hidden user accounts table, displaying admin credentials and Flag #1:
   **`BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}`**
4. Switch to the **SOC SIEM Console** and search for `status:500` or `uri:*union*`.
5. Click **"Inspect"** on the generated log row to view the raw URL-encoded single quote (`%27`), the decoded SQL keywords, and the IoC detection details.

---

### 2. Cross-Site Scripting (XSS) Attack & Detection
1. In the **Target Application**, go to **"🔍 Catalog & Search"** (Reflected XSS) or **"💬 Feedback Board"** (Stored XSS).
2. Enter the script payload:
   ```html
   <script>alert('XSS')</script>
   ```
3. Submit the search or feedback comment.
4. A sandbox pop-up triggers, displaying simulated cookie exposure and Flag #2:
   **`BLITZ{x55_cl13nt_3x3c_7b39d104fa}`**
5. In the **SOC SIEM Console**, filter by `category:xss` or `rule:RULE-SEC-003` to observe URL-encoded brackets (`%3C` and `%3E`), and check log `log-017` to find the attacker's external C2 domain (`http://evil-c2.attacker.com/steal`).

---

### 3. Authentication Brute Force Attack & Detection
1. In the **Target Application**, navigate to the **"🔐 Login Portal"**.
2. Click the **"Hydra Burst"** button (or use the **"⚡ Attack Simulator"**).
3. The simulator issues 24 consecutive invalid login attempts (returning `401 Unauthorized`), followed by the correct password:
   * **Cracked Password:** `dragon123` (returns `302 Found` and unlocks Flag #3: **`BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}`**).
4. In the **SOC SIEM Console**, observe the spike in the red **401 Unauthorized** bar on the timeline histogram and trace the transition from multiple 401s to a single 302.

---

### 4. Incident Correlation
1. Filter the SIEM by `ioc:true` to display all security events.
2. Correlate timestamps and identify the threat actor IP (`198.51.100.72`) targeting the administrative endpoint `/admin/export?table=users_credentials`.
3. Complete the incident triage to obtain master Flag #4:
   **`BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}`**

---

## Part 2: Questions, Hints & Final Answers

### Section 1: Web Log Fundamentals

#### Question 1
Which standard 3-digit HTTP response status code indicates an authentication failure (Unauthorized access) when credentials are invalid or missing?
* **💡 Hint:** Think of the client error code in the 4xx range returned by web servers when login credentials fail.
* **🎯 Final Answer:** `401`

#### Question 2
In the standard NCSA/Apache Combined Log Format, which field comes immediately after the HTTP request line (e.g. `"GET /catalog/search HTTP/1.1"`)?
* **💡 Hint:** It is the 3-digit numerical code indicating whether the request succeeded (200), failed authentication (401), or errored (500).
* **🎯 Final Answer:** `status code` *(also accept: `status`, `HTTP status`, `status_code`)*

---

### Section 2: SQL Injection Forensics

#### Question 3
What is the two-character hexadecimal URL percent encoding for a single quotation mark (`'`), commonly seen in access logs when attackers break SQL query strings?
* **💡 Hint:** In the ASCII table, single quote (') is character 39 in decimal, which equals hex 27. It is prefixed with a percent sign in URLs.
* **🎯 Final Answer:** `%27`

#### Question 4
Exploit the SQL Injection vulnerability in the Target Application catalog search using a `UNION SELECT` query. What secret challenge flag is retrieved from the leaked administrator database record?
* **💡 Hint:** In the Target Application, enter `' UNION SELECT 1,username,password,email,role FROM users--` into the catalog search bar.
* **🎯 Final Answer:** `BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}`

#### Question 5
In the SOC SIEM logs, search for automated vulnerability scanning activity. What was the source IP address that executed the automated `sqlmap` scan against `/catalog/search`?
* **💡 Hint:** In the SIEM console search bar, type `sqlmap` or `rule:RULE-SEC-005` and look at the Client IP column.
* **🎯 Final Answer:** `198.51.100.44`

---

### Section 3: Cross-Site Scripting (XSS) Forensics

#### Question 6
What URL percent-encoded string represents the opening angle bracket (`<`) frequently observed in raw access logs during HTML and script tag injection attacks?
* **💡 Hint:** In ASCII, the less-than symbol (<) has decimal value 60, which corresponds to hex 3C.
* **🎯 Final Answer:** `%3C` *(also accept: `%3c`)*

#### Question 7
Trigger the Reflected XSS vulnerability in the Target Application search bar with a script alert payload. What challenge flag is displayed in the client-side execution sandbox modal?
* **💡 Hint:** In the Target Application catalog search bar, enter `<script>alert('XSS')</script>` and press Search.
* **🎯 Final Answer:** `BLITZ{x55_cl13nt_3x3c_7b39d104fa}`

#### Question 8
In the SOC SIEM logs, inspect the stored XSS attack targeting the guestbook endpoint (`/board/feedback`). What malicious external C2 domain endpoint was the attacker attempting to exfiltrate session cookies to?
* **💡 Hint:** Inspect log `log-017` in the SIEM console and examine the decoded `src` attribute inside the injected script tag.
* **🎯 Final Answer:** `http://evil-c2.attacker.com/steal` *(also accept: `evil-c2.attacker.com/steal`, `http://evil-c2.attacker.com`, `evil-c2.attacker.com`)*

---

### Section 4: Authentication Brute Force Forensics

#### Question 9
What HTTP response status code anomaly in the SIEM timeline histogram serves as the primary behavioral indicator of an ongoing login brute-force attack?
* **💡 Hint:** Look at the 3-digit status code that spikes sharply on the histogram during high-frequency password guessing.
* **🎯 Final Answer:** `401` *(also accept: `401 Unauthorized`)*

#### Question 10
Execute the brute force attack against user `admin` on the Target Application login portal. What is the cracked legitimate password that yields an HTTP 302 redirect?
* **💡 Hint:** Click "Hydra Burst" on the login page or run the Attack Simulator. Check the attempt that authenticates with status 302.
* **🎯 Final Answer:** `dragon123`

#### Question 11
What challenge flag is unlocked upon successfully authenticating as `admin` on the Target Application login portal?
* **💡 Hint:** Log into the Target Application using username `admin` and password `dragon123` (or inject SQLi bypass `' OR '1'='1`) and read the success message.
* **🎯 Final Answer:** `BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}`

#### Question 12
In the SOC SIEM baseline logs, an attacker conducted an automated brute force attack against the account `sarah_admin`. What was the attacker's source IP address?
* **💡 Hint:** In the SIEM search bar, search for `sarah_admin`. Find the IP that issued 34 consecutive 401 attempts before a single 302 redirect.
* **🎯 Final Answer:** `203.0.113.89`

---

### Section 5: Capstone Threat Actor Incident Investigation

#### Question 13
Identify the external threat actor IP address responsible for the multi-stage attack involving XSS injection and administrative data export?
* **💡 Hint:** Filter the SIEM by `category:xss` or inspect logs `log-015` through `log-018` to identify the common source IP address.
* **🎯 Final Answer:** `198.51.100.72`

#### Question 14
What sensitive database table name was targeted in the attacker's unauthorized `GET /admin/export` request?
* **💡 Hint:** Inspect log `log-018` in the SIEM console and examine the `table` parameter in the decoded query string.
* **🎯 Final Answer:** `users_credentials`

#### Question 15
Enter the master Incident Correlation Flag awarded for reconstructing the attacker's full kill chain:
* **💡 Hint:** Master triage flag representing the complete incident correlation.
* **🎯 Final Answer:** `BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}`

---

## Part 3: Master Flags Summary

| Vulnerability Vector | Trigger Location | Final Flag |
|---|---|---|
| **SQL Injection** | Catalog Search `UNION SELECT` | `BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}` |
| **Cross-Site Scripting** | Catalog Search / Feedback Script Injection | `BLITZ{x55_cl13nt_3x3c_7b39d104fa}` |
| **Login Compromise** | Login Portal (`admin` / `dragon123`) | `BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}` |
| **Incident Correlation** | Full Multi-Stage Attack Triage | `BLITZ{1nc1d3nt_c0rr3l4t10n_89c2e01b}` |
