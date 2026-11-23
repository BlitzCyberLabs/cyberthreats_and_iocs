/**
 * Aegis Enterprise Portal (White / Light Theme Web Application)
 * Realistic corporate portal with Search Bar, Login Page, and Admin Home Page.
 * Performs SQL Injection (Login Bypass), XSS (Search Bar), and Brute Force (Login).
 * Emits real-time HTTP web application logs to the SOC SIEM Monitor.
 */

import { logEngine } from './log-engine.js';
import { sfx, showToast, escapeHtml } from './utils.js';

class TargetApp {
  constructor() {
    this.container = null;
    this.currentView = 'home'; // 'home' | 'login' | 'admin'
    this.clientIp = '203.0.113.195';
    this.hostDomain = 'portal.aegis-corp.com';
    this.currentUser = null; // null or { username: 'sec_admin', role: 'Global Administrator' }
  }

  init(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;
    this.render();
  }

  setView(view) {
    // If trying to access admin without authentication, redirect to login
    if (view === 'admin' && !this.currentUser) {
      showToast("Access Denied: Please authenticate to access the Admin Home Page.", "warning");
      this.currentView = 'login';
    } else {
      this.currentView = view;
    }
    this.render();
  }

  render() {
    if (!this.container) return;

    this.container.innerHTML = `
      <!-- White / Light Theme Web Application Container -->
      <div class="bg-white text-slate-800 rounded-xl border border-slate-200 shadow-xl overflow-hidden font-sans">
        
        <!-- Corporate White Header -->
        <header class="bg-white border-b border-slate-200 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold text-lg shadow-sm">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <h1 class="text-base font-bold text-slate-900 tracking-tight">Aegis Enterprise Cloud Portal</h1>
                <span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">Online v3.4</span>
              </div>
              <p class="text-xs text-slate-500 font-mono">Host: https://${this.hostDomain}</p>
            </div>
          </div>

          <!-- Top Navigation Links -->
          <nav class="flex items-center gap-2 text-xs font-medium">
            <button id="nav-home" class="px-3.5 py-1.5 rounded-md transition-all ${this.currentView === 'home' ? 'bg-slate-100 text-blue-700 font-semibold' : 'text-slate-600 hover:text-slate-900'}">
              🏠 Home & Search
            </button>
            
            ${this.currentUser ? `
              <button id="nav-admin" class="px-3.5 py-1.5 rounded-md transition-all ${this.currentView === 'admin' ? 'bg-emerald-600 text-white font-semibold shadow-sm' : 'bg-emerald-50 text-emerald-700 font-semibold border border-emerald-200 hover:bg-emerald-100'}">
                🛡️ Admin Home Page
              </button>
              <button id="nav-logout" class="px-3 py-1.5 rounded-md text-red-600 hover:bg-red-50 border border-red-200 transition-all">
                Sign Out
              </button>
            ` : `
              <button id="nav-login" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold transition-all shadow-sm flex items-center gap-1.5">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"/></svg>
                <span>Sign In</span>
              </button>
            `}
          </nav>
        </header>

        <!-- Main Body Content -->
        <main class="bg-slate-50 p-6 md:p-8 min-h-[520px]">
          ${this.renderViewContent()}
        </main>

        <!-- Corporate White Footer -->
        <footer class="bg-white border-t border-slate-200 px-6 py-3 flex flex-wrap items-center justify-between text-xs text-slate-500 font-sans">
          <div>&copy; 2026 Aegis Global Operations Inc. • Authorized Personnel Only</div>
          <div class="flex items-center gap-2 font-mono text-[11px]">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Real-time Telemetry Forwarder Active (${this.clientIp})</span>
          </div>
        </footer>
      </div>
    `;

    this.bindEvents();
  }

  renderViewContent() {
    switch (this.currentView) {
      case 'home': return this.renderHomeSearchView();
      case 'login': return this.renderLoginView();
      case 'admin': return this.renderAdminHomeView();
      default: return '';
    }
  }

  // --- 1. HOME & SEARCH BAR VIEW (Cross-Site Scripting & Search) ---
  renderHomeSearchView() {
    return `
      <div class="max-w-4xl mx-auto space-y-6">
        <!-- Hero Search Section -->
        <div class="bg-white p-7 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <div class="space-y-1">
            <h2 class="text-lg font-bold text-slate-900">Enterprise Resource & Asset Search</h2>
            <p class="text-xs text-slate-500">Query internal corporate documentation, network servers, and team directories.</p>
          </div>

          <form id="webapp-search-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="webapp-search-input" 
                placeholder="Search resources, hostnames, articles, or employees..." 
                class="w-full bg-white border border-slate-300 rounded-lg px-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm font-mono"
              />
            </div>
            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-lg text-xs transition-all shadow-sm flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              <span>Search</span>
            </button>
          </form>

          <div class="flex items-center justify-between text-[11px] text-slate-400 font-mono pt-1">
            <span>Endpoint: GET /api/search?q=</span>
            <span>Example queries: firewall, database, backup</span>
          </div>
        </div>

        <!-- Search Results Area -->
        <div id="webapp-search-results">
          ${this.getStandardDirectoryHTML()}
        </div>
      </div>
    `;
  }

  getStandardDirectoryHTML() {
    return `
      <div class="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div class="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between text-xs font-semibold text-slate-700">
          <span>Indexed Infrastructure Records</span>
          <span class="text-slate-400 font-normal font-mono">4 assets indexed</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left font-sans text-xs">
            <thead class="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium">
              <tr>
                <th class="p-3">Asset ID</th>
                <th class="p-3">Resource Name</th>
                <th class="p-3">IP / Subnet</th>
                <th class="p-3">Department</th>
                <th class="p-3">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 text-slate-700 font-mono">
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-101</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Edge Perimeter Firewall</td>
                <td class="p-3 text-slate-600">10.0.1.1</td>
                <td class="p-3 font-sans">Network Infrastructure</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-102</td>
                <td class="p-3 font-medium text-slate-900 font-sans">PostgreSQL Database Primary</td>
                <td class="p-3 text-slate-600">10.0.4.12</td>
                <td class="p-3 font-sans">Data Management</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-103</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Syslog / SIEM Event Collector</td>
                <td class="p-3 text-slate-600">10.0.8.50</td>
                <td class="p-3 font-sans">Security SOC</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-104</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Corporate Identity SSO Gateway</td>
                <td class="p-3 text-slate-600">10.0.2.10</td>
                <td class="p-3 font-sans">Identity Operations</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 2. LOGIN PAGE (SQLi Auth Bypass & Brute Force) ---
  renderLoginView() {
    return `
      <div class="max-w-md mx-auto my-6 space-y-6">
        <div class="bg-white p-7 rounded-xl border border-slate-200 shadow-sm space-y-5">
          <div class="text-center space-y-1">
            <div class="inline-flex items-center justify-center w-11 h-11 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 mb-2">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h2 class="text-base font-bold text-slate-900">Corporate Single Sign-On (SSO)</h2>
            <p class="text-xs text-slate-500">Sign in with your corporate ID to access the Admin Home Page.</p>
          </div>

          <form id="webapp-login-form" class="space-y-4">
            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Corporate ID / Username</label>
              <input 
                type="text" 
                id="webapp-login-user" 
                placeholder="e.g. admin" 
                class="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-mono focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
                required
              />
            </div>

            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Password</label>
              <input 
                type="password" 
                id="webapp-login-pass" 
                placeholder="Enter password or SQLi bypass" 
                class="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-mono focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
                required
              />
            </div>

            <div id="webapp-login-feedback" class="hidden text-xs p-3 rounded-lg font-mono"></div>

            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg text-xs transition-all shadow-sm">
              Sign In
            </button>
          </form>

          <div class="pt-3 border-t border-slate-200 text-center">
            <span class="text-[11px] text-slate-400 font-mono">Monitored Endpoint: POST /auth/login</span>
          </div>
        </div>
      </div>
    `;
  }

  // --- 3. ADMIN HOME PAGE (Reveals SQLi Flag) ---
  renderAdminHomeView() {
    return `
      <div class="max-w-5xl mx-auto space-y-6">
        <!-- Admin Welcome Banner -->
        <div class="bg-gradient-to-r from-blue-700 to-indigo-800 text-white p-7 rounded-xl shadow-md space-y-2">
          <div class="flex items-center justify-between">
            <span class="px-2.5 py-0.5 rounded text-[11px] font-mono bg-blue-900/60 border border-blue-400/40 font-bold uppercase tracking-wider">
              CONFIDENTIAL • ROOT ACCESS
            </span>
            <span class="text-xs font-mono text-blue-200">Session ID: ADM-94029-SEC</span>
          </div>
          <h2 class="text-2xl font-bold tracking-tight">Admin Home Page & System Control Center</h2>
          <p class="text-xs text-blue-100 max-w-2xl leading-relaxed">
            Welcome, System Administrator (<strong>${escapeHtml(this.currentUser?.username || 'sec_admin')}</strong>). You have gained root access to the internal enterprise operations management system.
          </p>
        </div>

        <!-- THE SECRET FLAG CARD (Awarded upon entering Admin Home Page) -->
        <div class="bg-white border-2 border-emerald-500 rounded-xl p-6 shadow-md space-y-3">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-full bg-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            </div>
            <div>
              <span class="text-xs font-mono text-emerald-700 font-bold uppercase tracking-wider block">Administrative Secret Vault</span>
              <h3 class="text-base font-bold text-slate-900">SQL Injection Login Bypass Challenge Flag</h3>
            </div>
          </div>
          
          <div class="bg-slate-900 rounded-lg p-4 font-mono text-sm border border-slate-800 flex items-center justify-between">
            <div>
              <span class="text-slate-400 text-xs block mb-1">Administrative Secret Flag:</span>
              <span class="text-emerald-400 font-bold select-all text-base">BLITZ{5ql1_byp455_4dm1n_h0m3_7d91a}</span>
            </div>
            <span class="text-xs text-emerald-400 font-sans font-semibold bg-emerald-950 px-3 py-1 rounded border border-emerald-800">
              Bypass Verified
            </span>
          </div>

          <p class="text-xs text-slate-500">
            This secret flag confirms successful authentication bypass into the Admin Home Page. The corresponding HTTP request has been recorded in the SOC SIEM logs.
          </p>
        </div>

        <!-- Administrative System Overview -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-1">
            <span class="text-xs font-semibold text-slate-500 uppercase">Database Cluster</span>
            <div class="text-xl font-bold text-slate-900">PostgreSQL 16.2</div>
            <div class="text-xs text-emerald-600 font-medium">● Normal Replication</div>
          </div>
          <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-1">
            <span class="text-xs font-semibold text-slate-500 uppercase">Authentication Mode</span>
            <div class="text-xl font-bold text-slate-900">SQL Dynamic Query</div>
            <div class="text-xs text-amber-600 font-medium">⚠️ Unparameterized</div>
          </div>
          <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-1">
            <span class="text-xs font-semibold text-slate-500 uppercase">SIEM Auditing</span>
            <div class="text-xl font-bold text-slate-900">Forwarding Active</div>
            <div class="text-xs text-blue-600 font-medium">● portal.aegis-corp.com</div>
          </div>
        </div>
      </div>
    `;
  }

  // --- BIND EVENT HANDLERS ---
  bindEvents() {
    const navHome = document.getElementById('nav-home');
    const navLogin = document.getElementById('nav-login');
    const navAdmin = document.getElementById('nav-admin');
    const navLogout = document.getElementById('nav-logout');

    if (navHome) navHome.onclick = () => this.setView('home');
    if (navLogin) navLogin.onclick = () => this.setView('login');
    if (navAdmin) navAdmin.onclick = () => this.setView('admin');
    if (navLogout) {
      navLogout.onclick = () => {
        this.currentUser = null;
        showToast("Signed out successfully.", "info");
        this.setView('home');
      };
    }

    if (this.currentView === 'home') this.bindSearchEvents();
    if (this.currentView === 'login') this.bindLoginEvents();
  }

  // --- SEARCH BAR EVENTS (Cross-Site Scripting) ---
  bindSearchEvents() {
    const form = document.getElementById('webapp-search-form');
    const input = document.getElementById('webapp-search-input');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const query = (input.value || '').trim();
        if (!query) return;

        const lower = query.toLowerCase();
        let status = 200;

        // Check for isolated single quote syntax test
        if (query.includes("'") && !lower.includes('union') && !lower.includes('or')) {
          status = 500;
        }

        // Ingest real HTTP GET log into SIEM
        logEngine.ingest({
          client_ip: this.clientIp,
          method: 'GET',
          uri: '/api/search',
          query_params: { q: query },
          status: status,
          referer: `https://${this.hostDomain}/`,
          user_agent: navigator.userAgent
        });

        this.processSearchQuery(query, status);
      };
    }
  }

  processSearchQuery(query, status) {
    const resultsArea = document.getElementById('webapp-search-results');
    if (!resultsArea) return;

    const lower = query.toLowerCase();

    // 1. Reflected Cross-Site Scripting (XSS in Search Bar)
    if (lower.includes('<script>') || lower.includes('onerror=') || lower.includes('<svg') || lower.includes('onload=')) {
      this.triggerXssAlert(query);
      resultsArea.innerHTML = `
        <div class="bg-amber-50 border border-amber-300 p-5 rounded-xl text-amber-900 space-y-2">
          <div class="font-bold flex items-center gap-2 text-sm text-amber-800">
            ⚠️ Reflected DOM Injection:
          </div>
          <div class="font-mono text-xs bg-white p-3 rounded border border-amber-200 break-all text-amber-800">
            Query string: ${escapeHtml(query)}
          </div>
          <p class="text-xs text-amber-700">The unsanitized query was reflected directly in the HTML response without HTML entity encoding.</p>
        </div>
      `;
      return;
    }

    // 2. SQL Syntax Error
    if (status === 500) {
      sfx.playError();
      showToast("HTTP 500 Internal Server Error (Database Exception)", "error");
      resultsArea.innerHTML = `
        <div class="bg-red-50 border border-red-300 p-5 rounded-xl text-red-900 font-mono text-xs space-y-2">
          <div class="font-bold text-red-700 text-sm">500 Internal Server Error: Database Syntax Exception</div>
          <div class="bg-white p-3 rounded border border-red-200 text-slate-800 select-all leading-relaxed">
            org.postgresql.util.PSQLException: ERROR: syntax error at or near "'"<br>
            LINE 1: SELECT * FROM assets WHERE name ILIKE '%${escapeHtml(query)}%'
          </div>
          <p class="text-slate-500 text-[11px] font-sans">Database error trace logged directly to SOC SIEM monitor.</p>
        </div>
      `;
      return;
    }

    // Default search table
    resultsArea.innerHTML = this.getStandardDirectoryHTML();
  }

  // --- LOGIN EVENTS (SQL Injection Auth Bypass & Brute Force) ---
  bindLoginEvents() {
    const form = document.getElementById('webapp-login-form');
    const uInput = document.getElementById('webapp-login-user');
    const pInput = document.getElementById('webapp-login-pass');
    const fbBox = document.getElementById('webapp-login-feedback');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const username = (uInput.value || '').trim();
        const password = (pInput.value || '').trim();

        // Check SQL Injection Login Bypass (support in username or password: ' OR '1'='1, admin' --, ' OR 1=1 --, etc.)
        const combined = `${username} ${password}`.toLowerCase();
        const hasQuote = username.includes("'") || password.includes("'") || username.includes('"') || password.includes('"');
        const hasSqliOp = combined.includes('or') || combined.includes('--') || combined.includes('#') || combined.includes('/*');
        const isSqliBypass = hasQuote && hasSqliOp;
        const isValidCreds = username.toLowerCase() === 'admin' && password === 'dragon123';
        const isSarahCreds = username.toLowerCase() === 'sarah_admin' && password === 'Summer2026!';

        const isSuccess = isSqliBypass || isValidCreds || isSarahCreds;
        const status = isSuccess ? 302 : 401;

        // Ingest real HTTP POST log with actual request body into SIEM
        logEngine.ingest({
          client_ip: this.clientIp,
          method: 'POST',
          uri: '/auth/login',
          body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
          status: status,
          referer: `https://${this.hostDomain}/login`,
          user_agent: navigator.userAgent
        });

        if (isSuccess) {
          sfx.playSuccess();
          this.currentUser = {
            username: username && !username.includes("'") && !username.includes('"') ? username : 'sec_admin',
            role: 'Global Administrator'
          };
          showToast("Authentication Successful! Redirecting to Admin Home Page...", "success");
          
          // Redirect to Admin Home Page where the flag is waiting!
          setTimeout(() => {
            this.setView('admin');
          }, 600);
        } else {
          sfx.playError();
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-red-50 text-red-800 border border-red-300 block";
          fbBox.innerHTML = `<strong>✕ 401 Unauthorized:</strong> Invalid username or password. Attempt logged to audit trail.`;
        }
      };
    }
  }

  triggerXssAlert(payload) {
    sfx.playAlert();
    const modal = document.createElement('div');
    modal.className = "fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm";
    modal.innerHTML = `
      <div class="bg-white border-2 border-amber-500 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 font-mono text-xs">
        <div class="flex items-center gap-3 text-amber-600">
          <svg class="w-6 h-6 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <span class="font-bold text-sm text-slate-900 font-sans">Browser Security Context: Script Executed</span>
        </div>
        <div class="bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-700">
          <span class="text-slate-500 block mb-1">Executed Payload:</span>
          <div class="text-amber-700 break-all font-bold">${escapeHtml(payload)}</div>
        </div>
        <div class="bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-700">
          <span class="text-slate-500 block mb-1">Exposed Session Cookie:</span>
          <div class="text-blue-700 break-all">session=adm_839f10a74b; path=/; HttpOnly=False</div>
        </div>
        <div class="bg-emerald-50 p-3 rounded-lg border border-emerald-300 text-emerald-900">
          <span class="font-bold block mb-1">Challenge Flag:</span>
          <div class="text-emerald-700 font-bold select-all">BLITZ{x55_r3fl3ct3d_s34rch_9b42e}</div>
        </div>
        <button type="button" class="close-xss-btn w-full bg-slate-900 hover:bg-slate-800 text-white font-bold py-2 rounded-lg transition-all font-sans text-xs">
          Dismiss & View Telemetry in SOC SIEM
        </button>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('.close-xss-btn').onclick = () => modal.remove();
  }
}

export const targetApp = new TargetApp();
