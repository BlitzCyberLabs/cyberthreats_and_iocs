# 🛡️ SOC Analyst 101: Web Attack Forensics & IoC Hunting Lab

[![GitHub Pages](https://img.shields.io/badge/Hosted%20on-GitHub%20Pages-10b981?style=for-the-badge&logo=github)](https://pages.github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Zero Backend](https://img.shields.io/badge/Architecture-100%25%20Client--Side-purple?style=for-the-badge)](#architecture)
[![Cyber Defense Range](https://img.shields.io/badge/Track-SOC%20Tier%201%20Analyst-cyan?style=for-the-badge)](#curriculum)

An interactive, browser-based **Cyber Defense Training Lab** designed to teach cybersecurity students, junior SOC analysts, and incident responders how to hunt, analyze, and detect **Indicators of Compromise (IoCs)** in web server access logs.

---

## 🌟 Highlights

- **🎯 Interactive Victim Application (`CyberVault`)**: Perform actual SQL Injection (SQLi), Cross-Site Scripting (XSS), and Authentication Brute Force attacks in a safe, controlled browser sandbox.
- **⚡ Automated Attack Simulator**: Launch 1-click automated penetration testing bursts (Hydra Brute Force, Sqlmap Scanning, Polyglot XSS, Benign Traffic Floods) with live console telemetry!
- **🛡️ SOC SIEM Log Console (`CyberWatch`)**: Search, filter, and inspect realistic Apache Combined and JSON logs using Lucene-like queries (`status:401`, `uri:*union*`, `ip:198.51.100.44`, `rule:RULE-SEC-001`, free text).
- **📊 Real-time Forensics Visualizations**: Interactive HTTP Status code distribution histograms (Chart.js) and threat vector classification charts.
- **🔍 Deep-Dive Forensic Inspector**: Inspect raw logs, URL-decoded query parameters, HTTP headers, IoC severity ratings, and mitigation steps.
- **📚 Guided Curriculum**: 5 structured learning tasks with interactive flags, hints, point scoring, and a Certificate of Proficiency badge.
- **🌐 100% GitHub Pages Ready**: Built purely with client-side modern Web technologies (HTML5, Vanilla ES6 JavaScript, Tailwind CSS). **Zero server backend, zero Docker setup required, zero hosting cost!**

---

## 🚀 How to Host Live on GitHub (GitHub Pages)

You can host this entire interactive lab live on GitHub for free in under 2 minutes:

### Step 1: Initialize Git and Push to GitHub

Open a terminal inside this folder (`soc lab`):

```bash
# 1. Initialize git repository
git init

# 2. Stage all files
git add .

# 3. Commit files
git commit -m "Initial commit: SOC Web Attack Forensics & IoC Lab"

# 4. Rename branch to main
git branch -M main

# 5. Link your GitHub repository (replace with your repo URL)
git remote add origin https://github.com/YOUR_USERNAME/soc-web-ioc-lab.git

# 6. Push to GitHub
git push -u origin main
```

### Step 2: Enable GitHub Pages

1. Navigate to your repository on GitHub.
2. Go to **Settings** > **Pages** (in the left sidebar under *Code and automation*).
3. Under **Build and deployment**:
   - **Source**: Select **GitHub Actions** (The included `.github/workflows/deploy.yml` will automatically build and publish).
   - *Alternatively*, select **Deploy from a branch**, choose `main` as the branch, `/ (root)` as the folder, and click **Save**.
4. Within 60 seconds, your lab will be live at:
   ```
   https://YOUR_USERNAME.github.io/soc-web-ioc-lab/
   ```

---

## 💻 How to Run Locally

Because this project is built entirely client-side, you can run it locally with any lightweight static server:

### Option A: Python Built-in Server (Recommended)
```bash
python -m http.server 8000
```
Then open your browser to `http://localhost:8000`.

### Option B: Node.js `npx serve`
```bash
npx serve .
```

### Option C: VS Code Live Server
Right-click `index.html` and select **"Open with Live Server"**.

---

## 🗺️ Lab Tasks Overview

| Task # | Title | Focus & Core IoCs | Points |
|---|---|---|---|
| **Task 1** | **Introduction to Web Logs & IoCs** | Anatomy of Apache Combined Format, HTTP status codes (`200`, `302`, `401`, `403`, `500`), Pyramid of Pain. | 100 PTS |
| **Task 2** | **Detecting SQL Injection (SQLi) IoCs** | Tautology (`' OR 1=1`), UNION SELECT exfiltration, URL encodings (`%27`, `%20`, `%22`, `%2D%2D`), error probes. | 150 PTS |
| **Task 3** | **Detecting Cross-Site Scripting (XSS) IoCs** | Reflected vs. Stored XSS, `<script>` tags, `%3Cscript%3E`, `onerror=`, `onload=`, cookie exfiltration C2 endpoints. | 150 PTS |
| **Task 4** | **Detecting Authentication Brute Force** | High frequency 401 Unauthorized bursts, dictionary attacks, identifying the 401 -> 302 credential compromise transition. | 150 PTS |
| **Task 5** | **Capstone Incident Investigation** | End-to-end multi-stage intrusion triage: correlate recon, brute force, admin compromise, and data theft. | 150 PTS |

---

## 🔎 SIEM Search Query Guide

The embedded SOC SIEM console supports flexible searching:

| Search Query | Description |
|---|---|
| `status:401` | Filter for authentication failures |
| `status:500` | Filter for internal server error crashes (often caused by broken SQL syntax) |
| `uri:*union*` | Wildcard search for UNION SELECT statements in the request path |
| `ip:198.51.100.44` | Filter logs originating from an external threat actor IP |
| `method:POST` | View all POST data submissions (login attempts, feedback submissions) |
| `rule:RULE-SEC-001` | Filter by specific detection rule ID (SQLi UNION exfiltration) |
| `category:sqli` | Quick filter for all SQL injection telemetry |
| `category:xss` | Quick filter for all Cross-Site Scripting telemetry |
| `category:brute_force` | Filter for brute force login attempts |
| `ioc:true` | Display only logs that triggered security detection rules |
| `sqlmap` | Free-text search for automated scanner user agents or payload strings |

---

## 📁 Repository Structure

```
soc-web-ioc-lab/
├── index.html                 # Main Single Page Application hub
├── css/
│   └── styles.css             # Cyber UI styling, animations, terminal styling
├── js/
│   ├── app.js                 # App coordinator, routing, navigation, progress UI
│   ├── store.js               # Reactive state (logs, user progress, flags, localStorage)
│   ├── lab-content.js         # Guided tasks, questions, hints, flag validation
│   ├── target-app.js          # Interactive vulnerable victim app & attack simulator
│   ├── soc-siem.js            # SIEM dashboard logic, search engine, charts, drawer
│   ├── log-engine.js          # Log ingestion, synthetic traffic generator, exporters
│   ├── detections.js          # Real-time SIEM detection rule engine (SQLi, XSS, Brute Force)
│   └── utils.js               # Synthesizer sound effects, URL decoders, toast notifications
├── data/
│   └── baseline-logs.json     # Pre-loaded realistic historical access logs
├── .github/
│   └── workflows/
│       └── deploy.yml         # GitHub Actions automated Pages deployment
├── README.md                  # Comprehensive Documentation & Setup Guide
└── LICENSE                    # MIT Open Source License
```

---

## 💡 Instructor & Walkthrough Guide (Spoiler Warning)

<details>
<summary><strong>Click to expand Solutions & Answers</strong></summary>

### Task 1
- **Q1.1**: What standard 3-digit HTTP response status code indicates an authentication failure (Unauthorized)?
  - **Answer**: `401`
- **Q1.2**: In standard Apache Combined logs, which field comes directly after the request line `[METHOD /path PROTOCOL]`?
  - **Answer**: `status code`

### Task 2
- **Q2.1**: What URL-encoded string represents a single quotation mark (`'`) in web server access logs?
  - **Answer**: `%27`
- **Q2.2**: Perform a UNION SELECT injection in the Target Application catalog search. What secret flag is stored in the database administrator's record?
  - **Answer**: `SOC{sqli_un10n_3xf1ltr4t10n_succ3ss}`
- **Q2.3**: In the SOC Dashboard, filter or search for SQLi attacks. What source IP address launched the automated sqlmap scan in the baseline logs?
  - **Answer**: `198.51.100.44`

### Task 3
- **Q3.1**: What URL-encoded representation corresponds to the opening bracket character (`<`) frequently found in XSS log signatures?
  - **Answer**: `%3C`
- **Q3.2**: Trigger the Reflected XSS vulnerability in the Target App search bar with an alert payload. What flag is rewarded upon successful execution?
  - **Answer**: `SOC{xss_cl13nt_s1d3_p4yl04d_f0und}`
- **Q3.3**: Inspect the SOC Dashboard baseline logs for Stored XSS submissions in the guestbook. What malicious external C2 domain endpoint was the attacker attempting to load scripts from?
  - **Answer**: `http://evil-c2.attacker.com/steal`

### Task 4
- **Q4.1**: What HTTP response status code anomaly is the primary behavioral signature of a login brute force attack?
  - **Answer**: `401`
- **Q4.2**: Execute the Brute Force Attack Simulator against the Target App's login portal for user 'admin'. What is the cracked legitimate password discovered?
  - **Answer**: `dragon123`
- **Q4.3**: In the SOC Dashboard baseline logs, an attacker brute-forced the account 'sarah_admin' after multiple failures. What was the attacker's IP address?
  - **Answer**: `203.0.113.89`

### Task 5
- **Q5.1**: What was the IP address of the primary adversary who conducted the combined XSS injection and administrative data export?
  - **Answer**: `198.51.100.72`
- **Q5.2**: What specific sensitive database table was targeted in the attacker's GET /admin/export request?
  - **Answer**: `users_credentials`
- **Q5.3**: Enter the master Capstone Incident Responder Flag to finish the room!
  - **Answer**: `SOC{s0c_w3b_10c_m4st3r_hunt3r_2026}`

</details>

---

## 📜 License

This project is licensed under the **MIT License** - feel free to use, modify, and distribute for educational and training purposes.
