# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting
## Official Question Bank, Hints & Final Answers Key (8 Questions)

---

## 📋 Table of Contents
1. [Part 1: Quick Walkthrough - How to Perform the Lab](#part-1-quick-walkthrough---how-to-perform-the-lab)
2. [Part 2: Official Questions, Hints & Final Answers](#part-2-official-questions-hints--final-answers)
   - [Question 1: SQL Injection Execution](#question-1-sql-injection-execution)
   - [Question 2: SQL Injection Web Log Forensics](#question-2-sql-injection-web-log-forensics)
   - [Question 3: Directory Traversal Execution](#question-3-directory-traversal-execution)
   - [Question 4: Directory Traversal Web Log Forensics](#question-4-directory-traversal-web-log-forensics)
   - [Question 5: Cross-Site Scripting Execution](#question-5-cross-site-scripting-execution)
   - [Question 6: Cross-Site Scripting Web Log Forensics](#question-6-cross-site-scripting-web-log-forensics)
   - [Question 7: Threat Actor IP Identification](#question-7-threat-actor-ip-identification)
   - [Question 8: Security Remediation & Defense](#question-8-security-remediation--defense)
3. [Part 3: Master Flags Summary](#part-3-master-flags-summary)

---

## Part 1: Quick Walkthrough - How to Perform the Lab

### 1. Attack 1: SQL Injection (SQLi)
1. Open the **Target Application** tab and navigate to **"🏢 Asset Directory"**.
2. Test for error-based vulnerability by entering a single quote: `'`. Notice the application returns an unhandled `HTTP 500 Internal Server Error` revealing PostgreSQL syntax details.
3. Perform data exfiltration using a UNION query:
   ```sql
   ' UNION SELECT 1,username,password_hash,email,role FROM users--
   ```
4. The leaked database table displays the admin secret key and Flag #1:
   **`BLITZ{5ql1_3xf1ltr4t10n_k9x27p4}`**
5. Switch to the **SOC SIEM Console**, filter by `status:500` or `category:sqli`, and click **"Inspect"** to analyze the logged query parameters and URL encoding `%27`.

---

### 2. Attack 2: Directory Traversal (Path Traversal / LFI)
1. In the **Target Application**, navigate to **"📁 Document Center"**.
2. The application fetches files via `/api/documents?file=...`.
3. Test escaping the document root to access the internal system secrets file:
   ```text
   ../../../../system/secrets.env
   ```
4. The server returns the configuration file exposing Flag #2:
   **`BLITZ{p4th_tr4v3rs4l_f1l3_r34d_8a3d1}`**
5. Also test accessing `/etc/passwd`:
   ```text
   ../../../../etc/passwd
   ```
6. Switch to the **SOC SIEM Console**, filter by `category:path_traversal` or `rule:RULE-SEC-006`, and inspect the raw dot-dot-slash (`../`) path traversal sequences.

---

### 3. Attack 3: Cross-Site Scripting (XSS)
1. In the **Target Application**, go to **"Asset Directory"** (Reflected XSS) or **"Support"** (Stored XSS).
2. Submit an executable script payload:
   ```html
   <script>alert('XSS')</script>
   ```
3. The browser security sandbox executes the script and reveals Flag #3:
   **`BLITZ{x55_d0m_3x3cut10n_9c417e2}`**
4. In the **SOC SIEM Console**, filter by `category:xss` and inspect the raw URL percent encoding `%3C` for the opening script tag bracket.

---

## Part 2: Official Questions, Hints & Final Answers

### Question 1: SQL Injection Execution
Perform a SQL injection attack in the Asset Directory search bar using a UNION-based query to exfiltrate the hidden `users` table. What is the administrative secret flag retrieved from the database?
* **💡 Hint:** In the Asset Directory search bar, enter `' UNION SELECT 1,username,password_hash,email,role FROM users--` and inspect the leaked administrator record.
* **🎯 Final Answer:** `BLITZ{5ql1_3xf1ltr4t10n_k9x27p4}`

---

### Question 2: SQL Injection Web Log Forensics
When testing input fields for unhandled SQL injection, an unescaped single quote character (`'`) caused the backend database to throw a syntax exception. What HTTP response status code was returned by the server and recorded in the SIEM access logs?
* **💡 Hint:** Filter the SIEM console for server error status codes in the 5xx range or inspect the log entry generated after submitting an isolated quote `'`.
* **🎯 Final Answer:** `500` *(also accept: `500 Internal Server Error`)*

---

### Question 3: Directory Traversal Execution
Exploit the Document Center endpoint (`/api/documents`) using Directory Traversal path escape sequences to read the protected server configuration file (`/system/secrets.env`). What secret flag is exposed inside?
* **💡 Hint:** Enter `../../../../system/secrets.env` into the Document Center file input to traverse up from the storage root.
* **🎯 Final Answer:** `BLITZ{p4th_tr4v3rs4l_f1l3_r34d_8a3d1}`

---

### Question 4: Directory Traversal Web Log Forensics
Inspect the raw URI parameters recorded in the SIEM for your directory traversal request. What standard two-character dot sequence followed by a forward slash is repeated to escape the web document root?
* **💡 Hint:** In Unix/Linux file system paths, what notation represents traversing to the parent directory?
* **🎯 Final Answer:** `../` *(also accept: `..%2f`, `..%2F`)*

---

### Question 5: Cross-Site Scripting Execution
Inject an XSS payload into the application (via the search bar or support ticket form) that executes JavaScript in the browser context. What challenge flag is displayed upon successful script execution?
* **💡 Hint:** Enter `<script>alert('XSS')</script>` into the search bar or support ticket description and inspect the sandbox execution pop-up.
* **🎯 Final Answer:** `BLITZ{x55_d0m_3x3cut10n_9c417e2}`

---

### Question 6: Cross-Site Scripting Web Log Forensics
In the raw web access logs, web browsers automatically URL-encode special characters. What is the two-character hexadecimal URL percent-encoding for the opening tag bracket (`<`) in the logged XSS request URI?
* **💡 Hint:** Look at the raw request URI in the SIEM log inspector for the `<script>` tag. In ASCII, character 60 converts to hex 3C.
* **🎯 Final Answer:** `%3C` *(also accept: `%3c`)*

---

### Question 7: Threat Actor IP Identification
Analyze the historical baseline telemetry in the SIEM console. What external source IP address conducted directory traversal reconnaissance by probing the Unix user file `/etc/passwd`?
* **💡 Hint:** In the SIEM console, search for `passwd` or `rule:RULE-SEC-006` and check the Client IP column.
* **🎯 Final Answer:** `198.51.100.88`

---

### Question 8: Security Remediation & Defense
What secure coding defense mechanism should be implemented in application source code to completely prevent SQL injection vulnerabilities by separating SQL query structure from user-supplied input data?
* **💡 Hint:** It involves pre-compiling the query and binding input variables separately.
* **🎯 Final Answer:** `parameterized queries` *(also accept: `prepared statements`, `parameterization`)*

---

## Part 3: Master Flags Summary

| Attack Vector | Trigger Location | Final Flag |
|---|---|---|
| **SQL Injection** | Asset Directory Search (`UNION SELECT`) | `BLITZ{5ql1_3xf1ltr4t10n_k9x27p4}` |
| **Directory Traversal** | Document Center (`/system/secrets.env`) | `BLITZ{p4th_tr4v3rs4l_f1l3_r34d_8a3d1}` |
| **Cross-Site Scripting** | Search / Support Ticket (`<script>`) | `BLITZ{x55_d0m_3x3cut10n_9c417e2}` |
