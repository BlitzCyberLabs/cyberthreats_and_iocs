# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting

[![GitHub Pages](https://img.shields.io/badge/Hosted%20on-GitHub%20Pages-10b981?style=for-the-badge&logo=github)](https://pages.github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Zero Backend](https://img.shields.io/badge/Architecture-100%25%20Client--Side-purple?style=for-the-badge)](#architecture)
[![Cyber Defense Range](https://img.shields.io/badge/Track-SOC%20Tier%201%20Analyst-cyan?style=for-the-badge)](#curriculum)

An interactive, browser-based **Cyber Defense Training Lab** designed to teach cybersecurity students, junior SOC analysts, and incident responders how to research, exploit, and detect **Indicators of Compromise (IoCs)** in web server access logs for:
1. **SQL Injection (Login Bypass)**
2. **Cross-Site Scripting (Reflected XSS in Search Bar)**
3. **Authentication Brute Force (Login Page)**

---

## 🌟 What's Included

* **🌐 Realistic Corporate Web Application (`portal.aegis-corp.com`)**:
  * **White / Light Theme** corporate design for Aegis Enterprise Operations.
  * **Search Bar**: Vulnerable to reflected Cross-Site Scripting (`GET /api/search?q=`).
  * **Single Sign-On (SSO) Login**: Vulnerable to SQL injection authentication bypass (`POST /auth/login`).
  * **Admin Home Page**: Confidential system control vault accessible upon successful login bypass, revealing the administrative challenge flag.
* **🛡️ Dark-Theme SOC SIEM Application Log Monitor**:
  * **Real-time Log Telemetry Stream**: Captures every real request line, HTTP method, client IP, status code, query parameters, and POST request body.
  * **HTTP Status Code Histogram**: Real-time visual timeline showing bursts of `401 Unauthorized` and `500 Internal Server Error`.
  * **Threat Breakdown & Attack Classification**: Real-time donut chart categorizing IoCs across SQLi, XSS, and Brute Force.
  * **Lucene Search & Quick Filters**: Search by `status:401`, `uri:*login*`, `ip:203.0.113.89`, `rule:RULE-SEC-004`, or free text.
  * **Deep Forensic Log Inspector**: Side-by-side comparison of raw Apache Combined format logs, decoded URL parameters, POST request bodies, and SIEM detection engine alerts.
* **📝 Question Bank (8 Questions)**:
  * [LAB_QUESTIONS_AND_ANSWERS.doc](LAB_QUESTIONS_AND_ANSWERS.doc) (Word Document format with Question, Hint, and Final Answer)
  * [LAB_QUESTIONS_AND_ANSWERS.md](LAB_QUESTIONS_AND_ANSWERS.md) (Markdown format)
* **🚩 Non-Predictable Flags**: Formatted strictly as `BLITZ{...}`.
* **🌐 100% GitHub Pages Compatible**: Pure client-side HTML5/ES6 JavaScript. Zero server, Python, or database setup required.

---

## 🚩 Master Flags & Forensic IoC Summary

| Attack Vector | Target Endpoint | Forensic Indicator of Compromise (IoC) | Challenge Flag / Key Detail |
|---|---|---|---|
| **SQL Injection (Login Bypass)** | `POST /auth/login` | Tautology `' OR '1'='1` or comment delimiter `admin' --` in POST body; returns HTTP 302 | `BLITZ{5ql1_byp455_4dm1n_h0m3_7d91a}` |
| **Cross-Site Scripting (Reflected)** | `GET /api/search?q=` | Unsanitized script tags encoded as `%3Cscript%3E` in access URI | `BLITZ{x55_r3fl3ct3d_s34rch_9b42e}` |
| **Brute Force (Login)** | `POST /auth/login` | Surge of HTTP 401s followed by anomalous HTTP 302 from single IP | Attacker IP: `203.0.113.89`<br>Password: `Summer2026!` |

---

## 🚀 How to Host Live on GitHub (GitHub Pages)

### Step 1: Initialize Git and Push to GitHub

```bash
# 1. Initialize git repository
git init

# 2. Stage all files
git add .

# 3. Commit files
git commit -m "feat: complete interactive SOC web attack forensics lab"

# 4. Set branch to main
git branch -M main

# 5. Link your GitHub repository
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git

# 6. Push to GitHub
git push -u origin main
```

### Step 2: Enable GitHub Pages

1. In your GitHub repository, open **Settings** > **Pages** (under *Code and automation*).
2. Under **Build and deployment**:
   * **Source**: Choose **GitHub Actions** (uses the included `.github/workflows/deploy.yml`).
   * *Alternatively*, choose **Deploy from a branch**, select branch `main`, folder `/ (root)`, and click **Save**.
3. Within 60 seconds, your lab will be live at:
   ```
   https://YOUR_USERNAME.github.io/YOUR_REPOSITORY/
   ```

---

## 💻 How to Run Locally

You can test or run the lab locally at any time:

```bash
# Python
python -m http.server 8000

# Or Node.js
npx serve .
```
Then open `http://localhost:8000` in any web browser.

---

## 🔎 SIEM Search Query Quick Reference

| Search Query | Description |
|---|---|
| `status:401` | Filter for failed authentication attempts (brute force surge) |
| `status:302` | Filter for successful authentication redirects |
| `status:500` | Filter for unhandled database syntax error crashes |
| `uri:*login*` | Wildcard search for login authentication requests |
| `ip:203.0.113.89` | Isolate logs from the brute force threat actor IP |
| `method:POST` | View all POST data submissions with request bodies |
| `rule:RULE-SEC-004` | Filter by Brute Force SIEM detection rule ID |
| `category:sqli` | Quick filter for SQL injection telemetry |
| `category:xss` | Quick filter for Cross-Site Scripting telemetry |
| `category:brute_force` | Filter for authentication brute force events |
| `ioc:true` | Display only logs triggering security detection rules |

---

## 📁 Repository Structure

```text
soc lab/
├── index.html                 # Main Single Page Application hub
├── README.md                  # Project overview and setup instructions
├── LAB_QUESTIONS_AND_ANSWERS.md # Full student lab guide, question bank & answers (Markdown)
├── LAB_QUESTIONS_AND_ANSWERS.doc# Word document version of questions & answers
├── css/
│   └── styles.css             # Cyber UI styling and animations
├── data/
│   └── baseline-logs.json     # Pre-loaded realistic historical access logs (portal.aegis-corp.com)
├── js/
│   ├── app.js                 # App coordinator and tab switcher
│   ├── store.js               # Reactive state & localStorage persistence
│   ├── target-app.js          # White-theme corporate web app (portal.aegis-corp.com)
│   ├── soc-siem.js            # Dark-theme SOC SIEM monitor, charts, search, and inspector
│   ├── log-engine.js          # Log ingestion, synthetic traffic generator, exporters
│   ├── detections.js          # Real-time SIEM detection rule engine (SQLi, XSS, Brute Force)
│   └── utils.js               # Web Audio synthesizer, URL decoders, toast notifications
└── .github/
    └── workflows/
        └── deploy.yml         # GitHub Actions automated GitHub Pages deployment
```

---

## 📜 License

This project is licensed under the **MIT License**.
