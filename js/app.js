/**
 * Main Application Orchestrator for SOC Lab
 */

import { store } from './store.js';
import { logEngine } from './log-engine.js';
import { targetApp } from './target-app.js';
import { socSiem } from './soc-siem.js';
import { LAB_ROOM, submitQuestionAnswer } from './lab-content.js';
import { sfx, showToast, escapeHtml } from './utils.js';

class App {
  constructor() {
    this.audioMuted = false;
  }

  async init() {
    // 1. Initialize Log Engine
    await logEngine.init();

    // 2. Initialize Target App
    targetApp.init('target-app-container');

    // 3. Initialize SOC SIEM
    socSiem.init('siem-container');

    // 4. Render Lab Curriculum Tasks
    this.renderLabTasks();

    // 5. Render Cheatsheet
    this.renderCheatSheet();

    // 6. Bind Global Navigation & UI
    this.bindNavigation();
    this.updateHeaderProgress();

    // 7. Subscribe to Progress Updates
    store.on('progressUpdated', () => {
      this.updateHeaderProgress();
      this.renderLabTasks(); // re-render completion ticks
      this.renderProgressView();
    });

    store.on('tabChange', (tab) => {
      this.switchTabUI(tab);
    });

    console.log("SOC Training Lab initialized successfully.");
  }

  bindNavigation() {
    // Tab buttons
    const navBtns = document.querySelectorAll('.main-nav-btn');
    navBtns.forEach(btn => {
      btn.onclick = () => {
        const tab = btn.getAttribute('data-tab');
        sfx.playClick();
        store.setTab(tab);
      };
    });

    // Sound toggle
    const audioBtn = document.getElementById('btn-toggle-sound');
    if (audioBtn) {
      audioBtn.onclick = () => {
        this.audioMuted = !this.audioMuted;
        sfx.enabled = !this.audioMuted;
        audioBtn.innerHTML = this.audioMuted ? `
          <svg class="w-4 h-4 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2"/></svg>
        ` : `
          <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z"/></svg>
        `;
        showToast(this.audioMuted ? "Sound muted" : "Sound enabled", "info");
      };
    }
  }

  switchTabUI(tab) {
    // Hide all tab views
    document.querySelectorAll('.tab-view-container').forEach(el => el.classList.add('hidden'));

    // Show active tab
    const activeEl = document.getElementById(`view-${tab}`);
    if (activeEl) activeEl.classList.remove('hidden');

    // Update nav bar active state
    document.querySelectorAll('.main-nav-btn').forEach(btn => {
      const bTab = btn.getAttribute('data-tab');
      if (bTab === tab) {
        btn.className = "main-nav-btn px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 text-white shadow-lg shadow-emerald-900/40 transition-all flex items-center gap-2";
      } else {
        btn.className = "main-nav-btn px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-all flex items-center gap-2";
      }
    });

    if (tab === 'progress') {
      this.renderProgressView();
    }
  }

  updateHeaderProgress() {
    const totalQuestions = LAB_ROOM.tasks.reduce((acc, t) => acc + t.questions.length, 0);
    const completedCount = Object.keys(store.completedQuestions).length;
    const pct = Math.round((completedCount / totalQuestions) * 100);

    const scoreEl = document.getElementById('header-score-text');
    const pctEl = document.getElementById('header-progress-pct');
    const barEl = document.getElementById('header-progress-bar');

    if (scoreEl) scoreEl.textContent = `${store.totalScore} / ${store.maxScore} PTS`;
    if (pctEl) pctEl.textContent = `${pct}% Complete`;
    if (barEl) barEl.style.width = `${pct}%`;
  }

  renderLabTasks() {
    const container = document.getElementById('lab-tasks-container');
    if (!container) return;

    container.innerHTML = LAB_ROOM.tasks.map(task => {
      const taskDone = task.questions.every(q => store.completedQuestions[q.id]);
      return `
        <div class="bg-slate-900/90 border ${taskDone ? 'border-emerald-600/50' : 'border-slate-800'} rounded-2xl p-6 shadow-xl space-y-5 transition-all">
          <!-- Task Header -->
          <div class="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-mono font-bold px-2 py-0.5 rounded ${taskDone ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'}">
                  TASK ${task.number}
                </span>
                ${taskDone ? `
                  <span class="text-xs font-mono text-emerald-400 flex items-center gap-1 font-bold">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
                    Completed
                  </span>
                ` : ''}
              </div>
              <h3 class="text-lg font-bold text-white">${escapeHtml(task.title)}</h3>
              <p class="text-xs text-slate-400 mt-1">${escapeHtml(task.overview)}</p>
            </div>
          </div>

          <!-- Task Explanatory Content -->
          <div class="text-slate-300 text-sm leading-relaxed">
            ${task.content}
          </div>

          <!-- Task Questions -->
          <div class="space-y-4 pt-4 border-t border-slate-800">
            <h4 class="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              Challenge Questions & Flags (${task.questions.length})
            </h4>

            <div class="space-y-3">
              ${task.questions.map(q => this.renderQuestionBox(q)).join('')}
            </div>
          </div>
        </div>
      `;
    }).join('');

    this.bindQuestionSubmissions();
  }

  renderQuestionBox(q) {
    const isAnswered = !!store.completedQuestions[q.id];

    return `
      <div class="bg-slate-950 border ${isAnswered ? 'border-emerald-700/60 bg-emerald-950/10' : 'border-slate-800'} rounded-xl p-4 space-y-3" id="q-box-${q.id}">
        <div class="flex items-start justify-between gap-3 text-xs">
          <p class="text-slate-200 font-medium leading-normal flex-1">
            <span class="text-cyan-400 font-mono font-bold mr-1">#</span> ${escapeHtml(q.text)}
          </p>
          <span class="font-mono text-[11px] px-2 py-0.5 rounded shrink-0 ${isAnswered ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-slate-900 text-slate-400 border border-slate-800'}">
            +${q.points} PTS
          </span>
        </div>

        ${isAnswered ? `
          <div class="flex items-center gap-2 bg-emerald-950/50 border border-emerald-700/50 text-emerald-300 px-3 py-2 rounded-lg text-xs font-mono">
            <svg class="w-4 h-4 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
            <span>Correct! Answer accepted.</span>
          </div>
        ` : `
          <form class="question-form flex flex-col sm:flex-row gap-2" data-qid="${q.id}">
            <div class="relative flex-1">
              <input 
                type="text" 
                class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono placeholder-slate-500 focus:outline-none focus:border-emerald-500" 
                placeholder="Submit flag or answer (e.g. SOC{...} or 401)"
                required
              />
            </div>
            <div class="flex items-center gap-2">
              <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs transition-all flex items-center justify-center gap-1 font-mono">
                Submit
              </button>
              ${q.hint ? `
                <button type="button" class="btn-toggle-hint text-slate-400 hover:text-amber-300 p-2 rounded-lg hover:bg-slate-900 border border-slate-800 text-xs transition-all" title="View Hint" data-hint="${escapeHtml(q.hint)}">
                  💡 Hint
                </button>
              ` : ''}
            </div>
          </form>
          <div class="hint-container hidden text-xs font-mono bg-amber-950/30 border border-amber-600/40 text-amber-300 p-2.5 rounded-lg"></div>
        `}
      </div>
    `;
  }

  bindQuestionSubmissions() {
    // Forms
    const forms = document.querySelectorAll('.question-form');
    forms.forEach(form => {
      form.onsubmit = (e) => {
        e.preventDefault();
        const qid = form.getAttribute('data-qid');
        const input = form.querySelector('input');
        const answer = input ? input.value : '';
        submitQuestionAnswer(qid, answer);
      };
    });

    // Hints
    const hintBtns = document.querySelectorAll('.btn-toggle-hint');
    hintBtns.forEach(btn => {
      btn.onclick = () => {
        const hintText = btn.getAttribute('data-hint');
        const parent = btn.closest('.bg-slate-950');
        const hintBox = parent.querySelector('.hint-container');
        if (hintBox) {
          if (hintBox.classList.contains('hidden')) {
            hintBox.textContent = `💡 Hint: ${hintText}`;
            hintBox.classList.remove('hidden');
          } else {
            hintBox.classList.add('hidden');
          }
        }
      };
    });
  }

  renderCheatSheet() {
    const container = document.getElementById('cheatsheet-container');
    if (!container) return;

    container.innerHTML = `
      <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl">
          <div class="flex items-center gap-3 mb-4">
            <div class="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/></svg>
            </div>
            <div>
              <h2 class="text-lg font-bold text-white">SOC Analyst Web IoC Reference & Cheat Sheet</h2>
              <p class="text-xs text-slate-400">Essential signatures, URL encodings, detection regexes, and status code quick reference.</p>
            </div>
          </div>

          <!-- Section 1: URL Encodings -->
          <div class="space-y-4 mb-6">
            <h3 class="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider">
              1. Critical URL / Percent Encodings
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-2.5 font-mono text-xs">
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%27</span> = Single Quote (')</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%22</span> = Double Quote (")</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%3C</span> = Less Than (&lt;)</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%3E</span> = Greater Than (&gt;)</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%20</span> = Space ( )</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%2D%2D</span> = SQL Comment (--)</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%23</span> = Hash Comment (#)</div>
              <div class="bg-slate-950 p-2.5 rounded border border-slate-800"><span class="text-cyan-400">%2527</span> = Double Encoded '</div>
            </div>
          </div>

          <!-- Section 2: Attack Signatures & Regex -->
          <div class="space-y-4 mb-6">
            <h3 class="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider">
              2. Detection Regex Patterns & SIEM Logic
            </h3>
            <div class="space-y-3 text-xs font-mono">
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                <span class="text-rose-400 font-bold">SQL Injection (UNION / Data Exfiltration):</span>
                <div class="text-slate-300 bg-slate-900 p-2 rounded select-all break-all">(?i)\bUNION\s+(ALL\s+)?SELECT\b|information_schema|0x[0-9a-f]{2,}</div>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                <span class="text-rose-400 font-bold">Cross-Site Scripting (HTML & Handlers):</span>
                <div class="text-slate-300 bg-slate-900 p-2 rounded select-all break-all">(?i)&lt;script\b|\bon\w+\s*=|<(iframe|svg|img)\b.*?(onload|onerror)</div>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                <span class="text-rose-400 font-bold">Brute Force Volumetric Threshold:</span>
                <div class="text-slate-300 bg-slate-900 p-2 rounded">count(status == 401 AND uri == "/api/login") by client_ip > 5 in 60s</div>
              </div>
            </div>
          </div>

          <!-- Section 3: Status Codes Summary -->
          <div class="space-y-4">
            <h3 class="text-xs font-mono uppercase text-emerald-400 font-bold tracking-wider">
              3. HTTP Response Status Code Forensic Meanings
            </h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span class="text-emerald-400 font-bold font-mono">200 OK:</span>
                <p class="text-slate-400 mt-1">Normal response, but can also represent successful data exfiltration in SQLi queries or successful reflected XSS HTML execution.</p>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span class="text-cyan-400 font-bold font-mono">302 Found (Redirect):</span>
                <p class="text-slate-400 mt-1">Often used after login success to redirect to /dashboard. A single 302 after a wave of 401s confirms a cracked password!</p>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span class="text-rose-400 font-bold font-mono">401 Unauthorized:</span>
                <p class="text-slate-400 mt-1">Authentication failure. The primary atomic telemetry metric for brute force and dictionary login attempts.</p>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span class="text-purple-400 font-bold font-mono">500 Internal Server Error:</span>
                <p class="text-slate-400 mt-1">Database syntax crash! Often triggered when SQL injection breaks quotes or column count mismatches in UNION queries.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  renderProgressView() {
    const container = document.getElementById('progress-container');
    if (!container) return;

    const totalQuestions = LAB_ROOM.tasks.reduce((acc, t) => acc + t.questions.length, 0);
    const completedCount = Object.keys(store.completedQuestions).length;
    const isRoomFinished = completedCount === totalQuestions;

    container.innerHTML = `
      <div class="max-w-3xl mx-auto space-y-6">
        <div class="bg-slate-900 border border-slate-800 p-6 rounded-2xl shadow-xl space-y-6">
          <div class="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 class="text-xl font-bold text-white">Your Training Progress & Certification</h2>
              <p class="text-xs text-slate-400 mt-1">Track completed tasks and unlock your SOC Analyst completion badge.</p>
            </div>
            <button id="btn-reset-all-progress" class="text-xs font-mono text-rose-400 hover:text-rose-300 underline">
              Reset Progress
            </button>
          </div>

          <!-- Score Card -->
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 text-center">
              <span class="text-xs text-slate-500 font-mono">TOTAL SCORE</span>
              <div class="text-3xl font-bold text-emerald-400 mt-1">${store.totalScore}</div>
              <span class="text-[10px] text-slate-400">out of ${store.maxScore} PTS</span>
            </div>
            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 text-center">
              <span class="text-xs text-slate-500 font-mono">QUESTIONS SOLVED</span>
              <div class="text-3xl font-bold text-cyan-400 mt-1">${completedCount} / ${totalQuestions}</div>
              <span class="text-[10px] text-slate-400">${Math.round((completedCount / totalQuestions) * 100)}% Complete</span>
            </div>
            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 text-center">
              <span class="text-xs text-slate-500 font-mono">ANALYST RANK</span>
              <div class="text-3xl font-bold text-purple-400 mt-1">
                ${isRoomFinished ? 'Tier 1 Lead' : completedCount >= 5 ? 'Junior Analyst' : 'Trainee'}
              </div>
              <span class="text-[10px] text-slate-400">Web Telemetry Specialist</span>
            </div>
          </div>

          <!-- Digital Badge Certificate -->
          <div class="bg-gradient-to-br from-slate-950 via-slate-900 to-emerald-950/40 p-6 rounded-2xl border-2 ${isRoomFinished ? 'border-emerald-500 shadow-2xl shadow-emerald-900/30' : 'border-slate-800'} text-center space-y-4">
            <div class="w-16 h-16 mx-auto rounded-full ${isRoomFinished ? 'bg-emerald-500 text-slate-950' : 'bg-slate-800 text-slate-500'} flex items-center justify-center font-bold text-2xl shadow-lg">
              🛡️
            </div>
            <div>
              <span class="text-xs font-mono uppercase tracking-widest text-emerald-400 font-bold">
                Certificate of Proficiency
              </span>
              <h3 class="text-xl font-bold text-white mt-1">Web Attack Forensics & IoC Hunting</h3>
              <p class="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                Demonstrated practical ability to hunt, correlate, and triage Indicators of Compromise for SQL Injection, Cross-Site Scripting, and Login Brute Force in enterprise web application logs.
              </p>
            </div>
            <div class="inline-block px-4 py-1.5 rounded-full text-xs font-mono font-bold ${isRoomFinished ? 'bg-emerald-950 text-emerald-300 border border-emerald-700' : 'bg-slate-950 text-slate-500 border border-slate-800'}">
              ${isRoomFinished ? '✓ VERIFIED BADGE UNLOCKED' : '🔒 Complete All Tasks to Unlock Badge'}
            </div>
          </div>
        </div>
      </div>
    `;

    const resetBtn = document.getElementById('btn-reset-all-progress');
    if (resetBtn) {
      resetBtn.onclick = () => {
        if (confirm("Reset all question progress and scores?")) {
          store.resetProgress();
          showToast("Progress has been reset.", "info");
        }
      };
    }
  }
}

// Instantiate and attach to window
export const app = new App();
window.addEventListener('DOMContentLoaded', () => {
  app.init();
});
