/**
 * Aegis Enterprise Portal (White / Light Theme Web Application)
 * Realistic corporate portal with Search Bar, Document Center, and Login Page.
 * Emits real-time HTTP web application logs to the SOC SIEM Monitor.
 */

import { logEngine } from './log-engine.js';
import { sfx, showToast, escapeHtml } from './utils.js';

class TargetApp {
  constructor() {
    this.container = null;
    this.currentView = 'search'; // 'search' | 'documents' | 'login'
    this.clientIp = '203.0.113.195';
    this.hostDomain = 'portal.aegis-corp.com';
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
                <h1 class="text-base font-bold text-slate-900 tracking-tight">Aegis Enterprise Portal</h1>
                <span class="text-[11px] font-medium px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">Production v3.4</span>
              </div>
              <p class="text-xs text-slate-500 font-mono">Host: https://${this.hostDomain}</p>
            </div>
          </div>

          <!-- Section Switcher Tabs -->
          <nav class="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs font-medium">
            <button id="webapp-nav-search" class="px-3.5 py-1.5 rounded-md transition-all ${this.currentView === 'search' ? 'bg-white text-blue-700 font-semibold shadow-sm' : 'text-slate-600 hover:text-slate-900'}">
              🔍 Asset & Employee Search
            </button>
            <button id="webapp-nav-docs" class="px-3.5 py-1.5 rounded-md transition-all ${this.currentView === 'documents' ? 'bg-white text-blue-700 font-semibold shadow-sm' : 'text-slate-600 hover:text-slate-900'}">
              📁 Document Center
            </button>
            <button id="webapp-nav-login" class="px-3.5 py-1.5 rounded-md transition-all ${this.currentView === 'login' ? 'bg-blue-600 text-white font-semibold shadow-sm' : 'text-slate-600 hover:text-slate-900'}">
              🔐 Employee Login
            </button>
          </nav>
        </header>

        <!-- Main Body Area -->
        <main class="bg-slate-50 p-6 md:p-8 min-h-[520px]">
          ${this.renderViewContent()}
        </main>

        <!-- Corporate White Footer -->
        <footer class="bg-white border-t border-slate-200 px-6 py-3 flex flex-wrap items-center justify-between text-xs text-slate-500">
          <div>&copy; 2026 Aegis Global Operations Inc. • Authorized Access Only</div>
          <div class="flex items-center gap-2 font-mono text-[11px]">
            <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Audited by CyberDefense SOC (${this.clientIp})</span>
          </div>
        </footer>
      </div>
    `;

    this.bindEvents();
  }

  renderViewContent() {
    switch (this.currentView) {
      case 'search': return this.renderSearchView();
      case 'documents': return this.renderDocumentsView();
      case 'login': return this.renderLoginView();
      default: return '';
    }
  }

  // --- 1. SEARCH BAR VIEW (SQLi & Reflected XSS) ---
  renderSearchView() {
    return `
      <div class="max-w-4xl mx-auto space-y-6">
        <!-- Search Card -->
        <div class="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <div class="space-y-1">
            <h2 class="text-base font-bold text-slate-900">Corporate Directory & Asset Query</h2>
            <p class="text-xs text-slate-500">Search for employees, corporate workstations, VPN routers, or database instances.</p>
          </div>

          <form id="webapp-search-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="webapp-search-input" 
                placeholder="Search by asset tag, hostname, appliance type, or employee name..." 
                class="w-full bg-white border border-slate-300 rounded-lg px-4 py-2.5 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm font-mono"
              />
            </div>
            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-5 py-2.5 rounded-lg text-xs transition-all shadow-sm flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              Search
            </button>
          </form>

          <div class="text-[11px] text-slate-500 font-mono">
            Endpoint: <code class="bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded">GET /api/search?q=</code>
          </div>
        </div>

        <!-- Dynamic Results Container -->
        <div id="webapp-search-results">
          ${this.getStandardAssetTable()}
        </div>
      </div>
    `;
  }

  getStandardAssetTable() {
    return `
      <div class="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
        <div class="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between text-xs font-semibold text-slate-700">
          <span>Active Infrastructure Records</span>
          <span class="text-slate-400 font-normal font-mono">4 assets indexed</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left font-sans text-xs">
            <thead class="bg-slate-50 text-slate-600 border-b border-slate-200 font-medium">
              <tr>
                <th class="p-3">Asset ID</th>
                <th class="p-3">Asset Name</th>
                <th class="p-3">Internal IP</th>
                <th class="p-3">Department</th>
                <th class="p-3">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100 text-slate-700 font-mono">
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-101</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Edge Perimeter Firewall</td>
                <td class="p-3 text-slate-600">10.0.1.1</td>
                <td class="p-3 font-sans">Network Ops</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-102</td>
                <td class="p-3 font-medium text-slate-900 font-sans">PostgreSQL Database Primary</td>
                <td class="p-3 text-slate-600">10.0.4.12</td>
                <td class="p-3 font-sans">Database Eng</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-103</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Central Syslog Collector Node</td>
                <td class="p-3 text-slate-600">10.0.8.50</td>
                <td class="p-3 font-sans">Security SOC</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
              <tr class="hover:bg-slate-50">
                <td class="p-3 font-bold text-blue-600">AST-104</td>
                <td class="p-3 font-medium text-slate-900 font-sans">Corporate Identity SSO Gateway</td>
                <td class="p-3 text-slate-600">10.0.2.10</td>
                <td class="p-3 font-sans">Identity Access</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-700 border border-emerald-200 font-sans font-semibold">Active</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 2. DOCUMENT CENTER (Directory Traversal) ---
  renderDocumentsView() {
    return `
      <div class="max-w-4xl mx-auto space-y-6">
        <div class="bg-white p-6 rounded-xl border border-slate-200 shadow-sm space-y-4">
          <div class="space-y-1">
            <h2 class="text-base font-bold text-slate-900">Secure Document & Compliance Repository</h2>
            <p class="text-xs text-slate-500">Access and view corporate policies, compliance audits, and architectural reports.</p>
          </div>

          <form id="webapp-doc-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="webapp-doc-input" 
                value="annual_compliance_2026.pdf" 
                placeholder="Enter filename to load (e.g. annual_compliance_2026.pdf)" 
                class="w-full bg-white border border-slate-300 rounded-lg px-4 py-2 text-xs text-slate-900 font-mono focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
              />
            </div>
            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-4 py-2 rounded-lg text-xs transition-all shadow-sm flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>Load File</span>
            </button>
          </form>

          <div class="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-2 border-t border-slate-100">
            <span>Endpoint: <code class="bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded">GET /api/documents?file=</code></span>
            <span>Available: annual_compliance_2026.pdf, it_security_charter.docx</span>
          </div>
        </div>

        <!-- Document Preview Window -->
        <div id="webapp-doc-preview" class="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3">
          ${this.getStandardDocumentPreview('annual_compliance_2026.pdf')}
        </div>
      </div>
    `;
  }

  getStandardDocumentPreview(filename) {
    return `
      <div class="flex items-center justify-between border-b border-slate-200 pb-2.5">
        <span class="text-xs text-slate-600">File Preview: <strong class="text-slate-900 font-mono">${escapeHtml(filename)}</strong></span>
        <span class="text-xs font-semibold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">HTTP 200 OK</span>
      </div>
      <div class="bg-slate-50 p-4 rounded-lg border border-slate-200 text-slate-700 text-xs leading-relaxed">
        <h3 class="font-bold text-slate-900 text-sm mb-2">Aegis Corporate IT Security & Compliance Charter 2026</h3>
        <p class="mb-2">This document verifies that Aegis Global Operations adheres to enterprise access control standards and automated logging policies. All inbound HTTP requests to internal endpoints are retained in the SIEM for forensic auditing.</p>
        <p class="text-slate-500 font-mono text-[11px]">Storage Root: /var/www/portal/storage/documents/</p>
      </div>
    `;
  }

  // --- 3. LOGIN VIEW (SQLi Auth Bypass & 401 Logs) ---
  renderLoginView() {
    return `
      <div class="max-w-md mx-auto my-6 space-y-6">
        <div class="bg-white p-7 rounded-xl border border-slate-200 shadow-sm space-y-5">
          <div class="text-center space-y-1">
            <div class="inline-flex items-center justify-center w-11 h-11 rounded-lg bg-blue-50 text-blue-600 border border-blue-200 mb-2">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h2 class="text-base font-bold text-slate-900">Corporate Single Sign-On (SSO)</h2>
            <p class="text-xs text-slate-500">Sign in with your corporate ID to access protected internal resources.</p>
          </div>

          <form id="webapp-login-form" class="space-y-4">
            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Corporate ID / Username</label>
              <input 
                type="text" 
                id="webapp-login-user" 
                placeholder="e.g. sec_admin" 
                class="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-mono focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
                required
              />
            </div>

            <div>
              <label class="block text-xs font-semibold text-slate-700 mb-1">Password</label>
              <input 
                type="password" 
                id="webapp-login-pass" 
                placeholder="Enter password" 
                class="w-full bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-900 font-mono focus:outline-none focus:border-blue-600 focus:ring-1 focus:ring-blue-600 shadow-sm"
                required
              />
            </div>

            <div id="webapp-login-feedback" class="hidden text-xs p-3 rounded-lg font-mono"></div>

            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg text-xs transition-all shadow-sm">
              Sign In to Employee Portal
            </button>
          </form>

          <div class="pt-3 border-t border-slate-200 text-center">
            <span class="text-[11px] text-slate-400 font-mono">Monitored Endpoint: POST /auth/login</span>
          </div>
        </div>
      </div>
    `;
  }

  // --- BIND EVENTS ---
  bindEvents() {
    const navSearch = document.getElementById('webapp-nav-search');
    const navDocs = document.getElementById('webapp-nav-docs');
    const navLogin = document.getElementById('webapp-nav-login');

    if (navSearch) navSearch.onclick = () => this.setView('search');
    if (navDocs) navDocs.onclick = () => this.setView('documents');
    if (navLogin) navLogin.onclick = () => this.setView('login');

    if (this.currentView === 'search') this.bindSearchEvents();
    if (this.currentView === 'documents') this.bindDocumentsEvents();
    if (this.currentView === 'login') this.bindLoginEvents();
  }

  // --- SEARCH BAR EVENTS (SQLi & Reflected XSS) ---
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

        // Check if single quote causes database syntax error (HTTP 500)
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
          referer: `https://${this.hostDomain}/search`,
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

    // 1. Reflected XSS
    if (lower.includes('<script>') || lower.includes('onerror=') || lower.includes('<svg') || lower.includes('onload=')) {
      this.triggerXssAlert(query);
      resultsArea.innerHTML = `
        <div class="bg-amber-50 border border-amber-300 p-4 rounded-xl text-amber-900 space-y-2">
          <div class="font-bold flex items-center gap-2 text-sm text-amber-800">
            ⚠️ Reflection in Document Object Model:
          </div>
          <div class="font-mono text-xs bg-white p-3 rounded border border-amber-200 break-all text-amber-800">
            Query string: ${escapeHtml(query)}
          </div>
          <p class="text-xs text-amber-700">The application reflected the input into the client DOM without HTML entity encoding.</p>
        </div>
      `;
      return;
    }

    // 2. SQLi Database Error (HTTP 500)
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

    // 3. SQLi UNION SELECT Data Exfiltration
    if (lower.includes('union') && lower.includes('select')) {
      sfx.playSuccess();
      showToast("SQL Injection Succeeded! Data exfiltrated.", "success");
      resultsArea.innerHTML = `
        <div class="bg-white border-2 border-emerald-500 rounded-xl p-5 shadow-sm space-y-4">
          <div class="flex items-center justify-between border-b border-slate-200 pb-3">
            <div>
              <span class="text-xs font-mono text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">UNION Query Succeeded</span>
              <h3 class="text-base font-bold text-slate-900 mt-1">Exfiltrated Database Table: <code class="text-blue-600">users</code></h3>
            </div>
            <span class="text-xs text-slate-500 font-mono">3 records leaked</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-50 text-slate-600 border-b border-slate-200">
                <tr>
                  <th class="p-2.5">ID</th>
                  <th class="p-2.5">Username</th>
                  <th class="p-2.5">Password Hash / Secret Key</th>
                  <th class="p-2.5">Email</th>
                  <th class="p-2.5">Role</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100 text-slate-700">
                <tr class="bg-emerald-50 text-emerald-900">
                  <td class="p-2.5 font-bold">1</td>
                  <td class="p-2.5 font-bold">sec_admin</td>
                  <td class="p-2.5 font-bold text-emerald-700">BLITZ{5ql1_3xf1ltr4t10n_k9x27p4}</td>
                  <td class="p-2.5">admin@aegis-corp.com</td>
                  <td class="p-2.5 font-bold">Global Administrator</td>
                </tr>
                <tr>
                  <td class="p-2.5">2</td>
                  <td class="p-2.5">svc_backup</td>
                  <td class="p-2.5">$2y$12$N9qo8uLOickgx2...</td>
                  <td class="p-2.5">backup@aegis-corp.com</td>
                  <td class="p-2.5">Service Account</td>
                </tr>
                <tr>
                  <td class="p-2.5">3</td>
                  <td class="p-2.5">audit_officer</td>
                  <td class="p-2.5">$2y$12$mKx31PzQ991v...</td>
                  <td class="p-2.5">compliance@aegis-corp.com</td>
                  <td class="p-2.5">Security Auditor</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="text-[11px] text-slate-500 font-mono">
            Recorded in access log of https://${this.hostDomain}.
          </div>
        </div>
      `;
      return;
    }

    // Default table
    resultsArea.innerHTML = this.getStandardAssetTable();
  }

  // --- DOCUMENT CENTER EVENTS (Directory Traversal) ---
  bindDocumentsEvents() {
    const form = document.getElementById('webapp-doc-form');
    const input = document.getElementById('webapp-doc-input');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const filepath = (input.value || '').trim();
        if (!filepath) return;

        const isTraversal = filepath.includes('../') || filepath.includes('..\\') || filepath.includes('%2e%2e');
        const status = 200;

        // Ingest real HTTP GET log into SIEM
        logEngine.ingest({
          client_ip: this.clientIp,
          method: 'GET',
          uri: '/api/documents',
          query_params: { file: filepath },
          status: status,
          referer: `https://${this.hostDomain}/documents`,
          user_agent: navigator.userAgent
        });

        this.processDocumentFetch(filepath);
      };
    }
  }

  processDocumentFetch(filepath) {
    const previewArea = document.getElementById('webapp-doc-preview');
    if (!previewArea) return;

    const lower = filepath.toLowerCase();

    // 1. Directory Traversal targeting /etc/passwd
    if (lower.includes('etc/passwd') || lower.includes('etc%2fpasswd')) {
      sfx.playAlert();
      showToast("Directory Traversal: /etc/passwd exposed!", "warning");
      previewArea.innerHTML = `
        <div class="flex items-center justify-between border-b border-slate-200 pb-2.5">
          <span class="text-amber-700 font-bold text-xs">⚠️ Directory Traversal Success: /etc/passwd</span>
          <span class="text-emerald-700 text-xs font-semibold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">HTTP 200 OK</span>
        </div>
        <pre class="bg-slate-900 text-amber-300 p-4 rounded-lg font-mono text-xs overflow-x-auto select-all">
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
aegis_app:x:1001:1001:Aegis Service:/var/www/portal:/bin/bash
sec_admin:x:1002:1002:Security Lead:/home/sec_admin:/bin/bash
postgres:x:104:110:PostgreSQL admin,,,:/var/lib/postgresql:/bin/bash
        </pre>
      `;
      return;
    }

    // 2. Directory Traversal targeting internal secrets
    if (lower.includes('secrets.env') || lower.includes('config.env') || lower.includes('.env')) {
      sfx.playSuccess();
      showToast("Directory Traversal: Internal secrets file accessed!", "success");
      previewArea.innerHTML = `
        <div class="flex items-center justify-between border-b border-slate-200 pb-2.5">
          <span class="text-emerald-700 font-bold text-xs">✓ Sensitive File Read: /system/secrets.env</span>
          <span class="text-emerald-700 text-xs font-semibold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">HTTP 200 OK</span>
        </div>
        <pre class="bg-slate-900 text-emerald-300 p-4 rounded-lg font-mono text-xs overflow-x-auto select-all leading-relaxed">
# Aegis Internal System Secrets & Configuration
NODE_ENV=production
DATABASE_URL=postgres://pgadmin:SuperSecret2026@10.0.4.12:5432/aegis_db
JWT_SECRET_SIGNER=0x79a1f4b209e8d1c9
FLAG_SYSTEM_SECRET=BLITZ{p4th_tr4v3rs4l_f1l3_r34d_8a3d1}
ALLOWED_ORIGIN=https://portal.aegis-corp.com
        </pre>
      `;
      return;
    }

    // Default regular document
    previewArea.innerHTML = this.getStandardDocumentPreview(filepath);
  }

  // --- LOGIN EVENTS ---
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

        const isSqliBypass = password.includes("'") && (password.toLowerCase().includes('or') || password.includes('--'));
        const isValid = username.toLowerCase() === 'sec_admin' && password === 'Summer2026!';
        const status = (isSqliBypass || isValid) ? 302 : 401;

        // Ingest real HTTP POST log with actual request body
        logEngine.ingest({
          client_ip: this.clientIp,
          method: 'POST',
          uri: '/auth/login',
          body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
          status: status,
          referer: `https://${this.hostDomain}/login`,
          user_agent: navigator.userAgent
        });

        if (isSqliBypass || isValid) {
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-emerald-50 text-emerald-800 border border-emerald-300 block";
          fbBox.innerHTML = `<strong>✓ Authentication Successful (HTTP 302)!</strong> Session established for user '${escapeHtml(username)}'.`;
          sfx.playSuccess();
        } else {
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-red-50 text-red-800 border border-red-300 block";
          fbBox.innerHTML = `<strong>✕ 401 Unauthorized:</strong> Invalid credentials for '${escapeHtml(username)}'. Attempt logged to audit trail.`;
          sfx.playError();
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
          <span class="font-bold text-sm text-slate-900 font-sans">Browser Security Context: JavaScript Executed</span>
        </div>
        <div class="bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-700">
          <span class="text-slate-500 block mb-1">Executed Payload:</span>
          <div class="text-amber-700 break-all font-bold">${escapeHtml(payload)}</div>
        </div>
        <div class="bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-700">
          <span class="text-slate-500 block mb-1">Exposed Session Token:</span>
          <div class="text-blue-700 break-all">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</div>
        </div>
        <div class="bg-emerald-50 p-3 rounded-lg border border-emerald-300 text-emerald-900">
          <span class="font-bold block mb-1">Challenge Flag:</span>
          <div class="text-emerald-700 font-bold select-all">BLITZ{x55_d0m_3x3cut10n_9c417e2}</div>
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
