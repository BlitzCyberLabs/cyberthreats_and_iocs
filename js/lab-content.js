/**
 * SOC Cyber Range Curriculum, Tasks, Questions, and Validation Engine
 */

import { store } from './store.js';
import { sfx, showToast, triggerCelebration } from './utils.js';

export const LAB_ROOM = {
  title: "SOC Analyst 101: Web Attack Forensics & IoC Hunting",
  badge: "Web Defense & SIEM",
  difficulty: "Beginner / Intermediate",
  duration: "45-60 Mins",
  description: "Learn how to hunt, analyze, and detect Indicators of Compromise (IoCs) for SQL Injection, Cross-Site Scripting (XSS), and Authentication Brute Force attacks using real web logs and an interactive SOC SIEM dashboard.",
  tasks: [
    {
      id: "task-1",
      number: 1,
      title: "Introduction to Web Server Logs & Indicators of Compromise (IoCs)",
      overview: "Web servers record every incoming HTTP request in access and error logs. For a SOC analyst, web logs are the primary telemetry source for detecting web application attacks.",
      content: `
        <h4 class="text-emerald-400 font-semibold mb-2">1. Anatomy of a Web Access Log</h4>
        <p class="mb-3 text-slate-300">
          The industry standard format for web servers (Apache, Nginx, LiteSpeed) is the <strong>Combined Log Format</strong>:
        </p>
        <div class="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-300 mb-3 overflow-x-auto select-all">
          192.168.1.45 - - [23/Nov/2026:08:15:22 +0000] "GET /catalog/search?q=firewall HTTP/1.1" 200 3410 "http://portal.cybervault.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs mb-4">
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">192.168.1.45</span>: Client IP address making the request.
          </div>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">[23/Nov/2026...]</span>: Timestamp in UTC.
          </div>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">"GET ... HTTP/1.1"</span>: Method, Request URI (path + query), and Protocol.
          </div>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">200 / 3410</span>: HTTP Status Code and Response size in bytes.
          </div>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">Referer</span>: URL page the user clicked to arrive here.
          </div>
          <div class="bg-slate-900/80 p-2.5 rounded border border-slate-800">
            <span class="text-cyan-400 font-bold">User-Agent</span>: Browser, OS, or automated tool identifier.
          </div>
        </div>

        <h4 class="text-emerald-400 font-semibold mb-2">2. What is an Indicator of Compromise (IoC)?</h4>
        <p class="mb-3 text-slate-300">
          An <strong>Indicator of Compromise (IoC)</strong> is any forensic artifact observed on a network or in an operating system that indicates with high confidence a computer intrusion or malicious activity.
        </p>
        <ul class="list-disc list-inside space-y-1.5 text-xs text-slate-300 mb-3">
          <li><strong class="text-amber-400">Atomic IoCs:</strong> Static values such as an IP address, domain name, or file hash.</li>
          <li><strong class="text-amber-400">Computed IoCs:</strong> Regular expressions, decoded attack payloads, or hashes.</li>
          <li><strong class="text-amber-400">Behavioral IoCs:</strong> Anomalous patterns, e.g., 200 failed logins in 60 seconds (brute force) or high frequency scans from an automated User-Agent.</li>
        </ul>
      `,
      questions: [
        {
          id: "q1_1",
          text: "Which standard 3-digit HTTP response status code indicates an authentication failure (Unauthorized)?",
          hint: "Think of the 4xx client error status code returned when credentials are invalid or missing.",
          acceptedAnswers: ["401", "401 unauthorized"],
          points: 50
        },
        {
          id: "q1_2",
          text: "In standard Apache Combined logs, which field comes directly after the request line [METHOD /path PROTOCOL]?",
          hint: "It is the 3-digit response status code (e.g. 200, 401, 500).",
          acceptedAnswers: ["status code", "status", "http status", "status_code"],
          points: 50
        }
      ]
    },
    {
      id: "task-2",
      number: 2,
      title: "Detecting SQL Injection (SQLi) IoCs",
      overview: "SQL Injection occurs when untrusted user input is directly concatenated into a dynamic database query, altering the query logic.",
      content: `
        <h4 class="text-emerald-400 font-semibold mb-2">1. Common SQLi Payloads & IoCs</h4>
        <p class="mb-3 text-slate-300">
          When examining web server access logs, SQL injection attempts leave distinct syntactic artifacts in the URI query string or POST payload:
        </p>
        <div class="space-y-2 text-xs mb-4">
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">Quotes & Comments:</span>
            <code class="text-slate-300 ml-2 font-mono">' --</code>, <code class="text-slate-300 font-mono">' /* */</code>, <code class="text-slate-300 font-mono">' #</code>
            <p class="text-slate-400 mt-1">Attackers inject quotes to break out of data literals and append comment characters to ignore the remainder of the query.</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">Tautologies:</span>
            <code class="text-slate-300 ml-2 font-mono">' OR 1=1 --</code>, <code class="text-slate-300 font-mono">' OR 'a'='a</code>
            <p class="text-slate-400 mt-1">Forces the WHERE clause condition to always evaluate to TRUE, often bypassing login gates or returning all catalog items.</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">UNION SELECT Injections:</span>
            <code class="text-slate-300 ml-2 font-mono">' UNION SELECT 1,username,password,4,5 FROM users--</code>
            <p class="text-slate-400 mt-1">Appends a second query to extract sensitive data from other tables into the visible web application response.</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">URL-Encoding Signatures:</span>
            <p class="text-slate-400 mt-1">
              Browsers and tools URL-encode payloads. In logs, you must look for:
              <br><code class="text-emerald-300">%27</code> = Single Quote (<code class="text-slate-300">'</code>)
              | <code class="text-emerald-300">%22</code> = Double Quote (<code class="text-slate-300">"</code>)
              | <code class="text-emerald-300">%20</code> = Space
              | <code class="text-emerald-300">%2D%2D</code> = Double Dash comment (<code class="text-slate-300">--</code>)
              | <code class="text-emerald-300">%23</code> = Hash comment (<code class="text-slate-300">#</code>)
            </p>
          </div>
        </div>

        <div class="bg-emerald-950/40 border border-emerald-500/30 rounded-lg p-3 mb-3 text-xs">
          <strong class="text-emerald-400">💡 Practical Exercise:</strong>
          Switch to the <span class="text-cyan-300 font-semibold">Target Application</span> tab. Navigate to the <strong>Catalog Search</strong>.
          Try entering: <code class="bg-slate-950 px-1.5 py-0.5 rounded text-amber-300 select-all">' UNION SELECT 1,username,password,email,role FROM users--</code>
          Observe how the internal database records are exfiltrated, and check the newly generated log in the SOC SIEM!
        </div>
      `,
      questions: [
        {
          id: "q2_1",
          text: "What URL-encoded string represents a single quotation mark (') in web server access logs?",
          hint: "ASCII code 39 in hex is 27. Format: %XX",
          acceptedAnswers: ["%27"],
          points: 50
        },
        {
          id: "q2_2",
          text: "Perform a UNION SELECT injection in the Target Application catalog search. What secret flag is stored in the database administrator's record?",
          hint: "Switch to the Target App tab, enter '' UNION SELECT 1,username,password,email,role FROM users-- in the search bar and inspect the output.",
          acceptedAnswers: ["SOC{sqli_un10n_3xf1ltr4t10n_succ3ss}", "FLAG{sqli_un10n_3xf1ltr4t10n_succ3ss}", "THM{sqli_un10n_3xf1ltr4t10n_succ3ss}"],
          points: 50
        },
        {
          id: "q2_3",
          text: "In the SOC Dashboard, filter or search for SQLi attacks. What source IP address launched the automated sqlmap scan in the baseline logs?",
          hint: "Search for 'sqlmap' or filter by 'rule:RULE-SEC-005' in the SIEM.",
          acceptedAnswers: ["198.51.100.44"],
          points: 50
        }
      ]
    },
    {
      id: "task-3",
      number: 3,
      title: "Detecting Cross-Site Scripting (XSS) IoCs",
      overview: "Cross-Site Scripting (XSS) occurs when malicious JavaScript code is injected into a benign web application and executed in the victim's browser session.",
      content: `
        <h4 class="text-emerald-400 font-semibold mb-2">1. XSS Types & Forensic Log Signatures</h4>
        <ul class="list-disc list-inside space-y-1.5 text-xs text-slate-300 mb-3">
          <li><strong>Reflected XSS:</strong> The payload travels in the HTTP GET request URL/query string and is reflected immediately in the HTML response. <em class="text-amber-400">Directly visible in access logs!</em></li>
          <li><strong>Stored XSS:</strong> The payload is submitted via POST (e.g. forum post, comment) and saved to the database. When other users view the page, it executes. <em class="text-amber-400">Visible in POST body/application audit logs!</em></li>
        </ul>

        <h4 class="text-emerald-400 font-semibold mb-2">2. What IoCs to Search for in SIEM Logs</h4>
        <div class="space-y-2 text-xs mb-4">
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">HTML Tag Injection:</span>
            <code class="text-slate-300 font-mono">&lt;script&gt;</code>, <code class="text-slate-300 font-mono">&lt;iframe&gt;</code>, <code class="text-slate-300 font-mono">&lt;svg&gt;</code>
            <p class="text-slate-400 mt-1">URL-encoded in logs as: <code class="text-emerald-300">%3Cscript%3E</code> (<code class="text-slate-300">%3C</code> = <code class="text-slate-300">&lt;</code>, <code class="text-slate-300">%3E</code> = <code class="text-slate-300">&gt;</code>).</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">Event Handlers & Pseudoprotocols:</span>
            <code class="text-slate-300 font-mono">onerror=</code>, <code class="text-slate-300 font-mono">onload=</code>, <code class="text-slate-300 font-mono">javascript:</code>, <code class="text-slate-300 font-mono">document.cookie</code>
            <p class="text-slate-400 mt-1">Attackers often use image or SVG error handlers: <code class="text-slate-300">&lt;img src=x onerror=alert(1)&gt;</code> to evade basic script filters.</p>
          </div>
        </div>

        <div class="bg-emerald-950/40 border border-emerald-500/30 rounded-lg p-3 mb-3 text-xs">
          <strong class="text-emerald-400">💡 Practical Exercise:</strong>
          Switch to the <span class="text-cyan-300 font-semibold">Target Application</span> tab. In either the <strong>Catalog Search</strong> or the <strong>Feedback Board</strong>, submit:
          <code class="bg-slate-950 px-1.5 py-0.5 rounded text-amber-300 select-all">&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
          Observe the safe sandboxed execution pop-up and the flag awarded!
        </div>
      `,
      questions: [
        {
          id: "q3_1",
          text: "What URL-encoded representation corresponds to the opening bracket character (<) frequently found in XSS log signatures?",
          hint: "ASCII 60 in hex is 3C. Prefix with a % symbol.",
          acceptedAnswers: ["%3c", "%3C"],
          points: 50
        },
        {
          id: "q3_2",
          text: "Trigger the Reflected XSS vulnerability in the Target App search bar with an alert payload. What flag is rewarded upon successful execution?",
          hint: "Submit <script>alert(1)</script> in the Target App search bar.",
          acceptedAnswers: [
            "SOC{xss_cl13nt_s1d3_p4yl04d_f0und}",
            "FLAG{xss_cl13nt_s1d3_p4yl04d_f0und}",
            "THM{xss_cl13nt_s1d3_p4yl04d_f0und}"
          ],
          points: 50
        },
        {
          id: "q3_3",
          text: "Inspect the SOC Dashboard baseline logs for Stored XSS submissions in the guestbook (/board/feedback). What malicious external C2 domain endpoint was the attacker attempting to load scripts from?",
          hint: "Inspect log-017 in the SOC SIEM and look at the decoded script src in the comment parameter.",
          acceptedAnswers: [
            "http://evil-c2.attacker.com/steal",
            "evil-c2.attacker.com/steal",
            "http://evil-c2.attacker.com",
            "evil-c2.attacker.com"
          ],
          points: 50
        }
      ]
    },
    {
      id: "task-4",
      number: 4,
      title: "Detecting Authentication Brute Force & Credential Stuffing",
      overview: "Brute force and credential stuffing attacks attempt to gain unauthorized account access by guessing passwords or testing credentials leaked from third-party breaches.",
      content: `
        <h4 class="text-emerald-400 font-semibold mb-2">1. Behavioral IoCs in Web Logs</h4>
        <p class="mb-3 text-slate-300">
          Unlike SQLi and XSS which rely on signature patterns in payloads, brute force detection is primarily <strong>behavioral and volumetric</strong>:
        </p>
        <div class="space-y-2 text-xs mb-4">
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">1. Surge in 401 Unauthorized Responses:</span>
            <p class="text-slate-400 mt-1">Normal users fail passwords 1 to 3 times. An automated tool generates tens, hundreds, or thousands of 401s in rapid succession against <code class="text-slate-300 font-mono">/api/login</code>.</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">2. High Request Velocity from Single IP / CIDR:</span>
            <p class="text-slate-400 mt-1">Dozens of POST requests per second far exceed human typing speed.</p>
          </div>
          <div class="bg-slate-900/90 p-2.5 rounded border border-slate-800">
            <span class="text-rose-400 font-bold font-mono">3. The Compromise Transition: 401 -> 302/200:</span>
            <p class="text-slate-400 mt-1">The critical indicator of a <em>successful</em> brute force compromise: A long series of consecutive 401 status codes followed immediately by a single 200 OK or 302 Found (Redirect to dashboard) from the same IP or targeting the same username!</p>
          </div>
        </div>

        <div class="bg-emerald-950/40 border border-emerald-500/30 rounded-lg p-3 mb-3 text-xs">
          <strong class="text-emerald-400">💡 Practical Exercise:</strong>
          Switch to the <span class="text-cyan-300 font-semibold">Target Application</span> tab. Navigate to <strong>Login</strong>.
          Click the <span class="text-amber-300 font-semibold">"Run Hydra Brute Force Burst"</span> button in the Attack Simulator.
          Watch the login requests stream in, observe the 401 spike on the SIEM timeline, and identify the cracked password!
        </div>
      `,
      questions: [
        {
          id: "q4_1",
          text: "What HTTP response status code anomaly is the primary behavioral signature of a login brute force attack?",
          hint: "The 3-digit status code returned when authentication fails.",
          acceptedAnswers: ["401", "401 unauthorized"],
          points: 50
        },
        {
          id: "q4_2",
          text: "Execute the Brute Force Attack Simulator against the Target App's login portal for user 'admin'. What is the cracked legitimate password discovered?",
          hint: "In Target App -> Login, click the Attack Simulator or try common passwords. Look for the attempt that succeeds with status 302.",
          acceptedAnswers: ["dragon123"],
          points: 50
        },
        {
          id: "q4_3",
          text: "In the SOC Dashboard baseline logs, an attacker brute-forced the account 'sarah_admin' after multiple failures. What was the attacker's IP address?",
          hint: "Search for 'sarah_admin' or status 401 in the SOC SIEM log explorer.",
          acceptedAnswers: ["203.0.113.89"],
          points: 50
        }
      ]
    },
    {
      id: "task-5",
      number: 5,
      title: "Capstone Incident Investigation Challenge",
      overview: "Tie everything together! Conduct an end-to-end incident investigation to reconstruct an adversary's multi-stage kill chain and report findings.",
      content: `
        <h4 class="text-emerald-400 font-semibold mb-2">🚨 Incident Scenario: Tier 1 Escalation</h4>
        <p class="mb-3 text-slate-300">
          The Network Security Operations Center received an automated alert: <strong>"Multiple Web Application Attack Vectors Detected from External IP Space"</strong>.
        </p>
        <p class="mb-3 text-slate-300">
          As the on-duty SOC analyst, investigate the historical baseline logs and real-time logs using the <strong>SOC Dashboard</strong>. Correlate timestamps, IP addresses, HTTP methods, status codes, and decoded parameters to answer the incident triage questions below.
        </p>
        <div class="bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-xs mb-3 space-y-1">
          <div class="text-cyan-400 font-semibold">Triage Checklist:</div>
          <div class="text-slate-300">1. Identify the adversary IP responsible for injecting XSS payloads and exfiltrating admin endpoints.</div>
          <div class="text-slate-300">2. Determine which specific database table was targeted in the attacker's data export request.</div>
          <div class="text-slate-300">3. Retrieve the final Incident Responder Master Flag!</div>
        </div>
      `,
      questions: [
        {
          id: "q5_1",
          text: "What was the IP address of the primary adversary who conducted the combined XSS injection and administrative data export?",
          hint: "Filter for XSS or check logs around 08:42 to 08:50 UTC in the baseline logs.",
          acceptedAnswers: ["198.51.100.72"],
          points: 50
        },
        {
          id: "q5_2",
          text: "What specific sensitive database table was targeted in the attacker's GET /admin/export request?",
          hint: "Inspect log-018 in the SOC Dashboard and examine the 'table' query parameter.",
          acceptedAnswers: ["users_credentials"],
          points: 50
        },
        {
          id: "q5_3",
          text: "Enter the master Capstone Incident Responder Flag to finish the room!",
          hint: "The flag is SOC{s0c_w3b_10c_m4st3r_hunt3r_2026}",
          acceptedAnswers: ["SOC{s0c_w3b_10c_m4st3r_hunt3r_2026}", "FLAG{s0c_w3b_10c_m4st3r_hunt3r_2026}", "THM{s0c_w3b_10c_m4st3r_hunt3r_2026}"],
          points: 50
        }
      ]
    }
  ]
};

/**
 * Checks an answer for a specific question
 */
export function submitQuestionAnswer(questionId, rawInput) {
  const cleanInput = (rawInput || '').trim().toLowerCase();
  if (!cleanInput) {
    showToast("Please enter an answer before submitting.", "warning");
    return { success: false };
  }

  // Find question
  let targetQuestion = null;
  for (const task of LAB_ROOM.tasks) {
    for (const q of task.questions) {
      if (q.id === questionId) {
        targetQuestion = q;
        break;
      }
    }
    if (targetQuestion) break;
  }

  if (!targetQuestion) {
    return { success: false, message: "Question not found" };
  }

  // Check against accepted answers
  const isCorrect = targetQuestion.acceptedAnswers.some(ans => {
    return ans.toLowerCase() === cleanInput;
  });

  if (isCorrect) {
    const isFirstTime = store.recordAnswer(questionId, targetQuestion.points);
    if (isFirstTime) {
      showToast(`Correct! +${targetQuestion.points} Points`, "success");
      triggerCelebration();
    } else {
      showToast("Correct! (Already completed)", "info");
    }
    return { success: true, firstTime: isFirstTime };
  } else {
    showToast("Incorrect answer. Check the hint and try again!", "error");
    return { success: false };
  }
}
