# 🛡️ SOC Analyst Lab: Web Attack Forensics & IoC Hunting

[![GitHub Pages](https://img.shields.io/badge/Hosted%20on-GitHub%20Pages-10b981?style=for-the-badge&logo=github)](https://pages.github.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Zero Backend](https://img.shields.io/badge/Architecture-100%25%20Client--Side-purple?style=for-the-badge)](#architecture)
[![Cyber Defense Range](https://img.shields.io/badge/Track-SOC%20Tier%201%20Analyst-cyan?style=for-the-badge)](#curriculum)

An interactive, browser-based **Cyber Defense Training Lab** designed to teach cybersecurity students, junior SOC analysts, and incident responders how to hunt, analyze, and detect **Indicators of Compromise (IoCs)** for:
1. **SQL Injection (SQLi)**
2. **Cross-Site Scripting (XSS)**
3. **Authentication Brute Force**

---

## 🌟 What's Included

* **🎯 Target Application (`CyberVault Systems`)**: An interactive victim web application with a vulnerable search catalog, authentication portal, and guestbook, plus a 1-click **Attack Simulator Console** (Hydra brute force burst, sqlmap scanning, polyglot XSS).
* **🛡️ SOC SIEM Console (`CyberWatch`)**: Real-time log telemetry stream, HTTP status code activity histogram, threat breakdown charts, Lucene-like search engine, and a deep-dive forensic log inspection drawer.
* **📝 Separate Questions & Answers Documents**:
  * [LAB_QUESTIONS_AND_ANSWERS.md](LAB_QUESTIONS_AND_ANSWERS.md) (Markdown format)
  * [LAB_QUESTIONS_AND_ANSWERS.doc](LAB_QUESTIONS_AND_ANSWERS.doc) (Word Document format)
* **🚩 Non-Predictable Flags**: Formatted as `BLITZ{...}`.
* **🌐 100% GitHub Pages Compatible**: Pure client-side HTML5/JavaScript. Zero backend or database setup required.

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
| `status:401` | Filter for failed authentication attempts |
| `status:500` | Filter for internal database server crashes |
| `uri:*union*` | Wildcard search for UNION SELECT statements |
| `ip:198.51.100.44` | Isolate logs from a specific threat actor IP |
| `method:POST` | View all POST data submissions |
| `rule:RULE-SEC-001` | Filter by specific SIEM detection rule ID |
| `category:sqli` | Quick filter for SQL injection telemetry |
| `category:xss` | Quick filter for Cross-Site Scripting telemetry |
| `category:brute_force` | Filter for brute force login attempts |
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
│   └── baseline-logs.json     # Pre-loaded realistic historical access logs
├── js/
│   ├── app.js                 # App coordinator and tab switcher
│   ├── store.js               # Reactive state & localStorage persistence
│   ├── target-app.js          # Interactive vulnerable victim app & attack simulator
│   ├── soc-siem.js            # SIEM dashboard logic, search engine, charts, drawer
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
