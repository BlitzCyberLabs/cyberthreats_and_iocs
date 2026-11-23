/**
 * Aegis Corporate Enterprise Portal
 * Real-world looking enterprise asset management & document repository.
 * Contains authentic attack surfaces for SQL Injection, Directory Traversal, and Cross-Site Scripting.
 * Generates accurate real-time HTTP telemetry into the SOC SIEM console.
 */

import { logEngine } from './log-engine.js';
import { sfx, showToast, escapeHtml } from './utils.js';

class TargetApp {
  constructor() {
    this.container = null;
    this.currentView = 'directory'; // 'directory' | 'documents' | 'login' | 'support'
    this.tickets = [
      { id: "TCK-1042", user: "j.miller@aegiscorp.internal", subject: "VPN client configuration timeout", date: "Today at 08:30" },
      { id: "TCK-1041", user: "k.turner@aegiscorp.internal", subject: "Request access to Q4 compliance folder", date: "Yesterday at 16:15" }
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
      <div class="flex flex-col h-full bg-[#0d131f] text-slate-100 rounded-xl border border-slate-800 shadow-2xl overflow-hidden font-sans">
        <!-- Realistic Browser URL / Address Bar -->
        <div class="bg-slate-900/90 border-b border-slate-800 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-1.5">
              <span class="w-3 h-3 rounded-full bg-rose-500/80 inline-block"></span>
              <span class="w-3 h-3 rounded-full bg-amber-500/80 inline-block"></span>
              <span class="w-3 h-3 rounded-full bg-emerald-500/80 inline-block"></span>
            </div>
            
            <div class="flex items-center bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 w-80 md:w-96 truncate shadow-inner">
              <svg class="w-3.5 h-3.5 mr-2 text-emerald-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
              <span class="text-slate-500">https://</span><span class="text-emerald-400 font-medium">portal.aegiscorp.internal</span><span class="text-cyan-300">${this.getPathForView()}</span>
            </div>
          </div>

          <!-- Enterprise Navigation -->
          <div class="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button id="nav-directory" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'directory' ? 'bg-slate-800 text-emerald-400 font-semibold border border-slate-700' : 'text-slate-400 hover:text-slate-200'}">
              🏢 Asset Directory
            </button>
            <button id="nav-documents" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'documents' ? 'bg-slate-800 text-emerald-400 font-semibold border border-slate-700' : 'text-slate-400 hover:text-slate-200'}">
              📁 Document Center
            </button>
            <button id="nav-support" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'support' ? 'bg-slate-800 text-emerald-400 font-semibold border border-slate-700' : 'text-slate-400 hover:text-slate-200'}">
              🎫 Support
            </button>
            <button id="nav-login" class="px-3 py-1.5 rounded-md transition-all ${this.currentView === 'login' ? 'bg-emerald-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'}">
              🔐 SSO Login
            </button>
          </div>
        </div>

        <!-- Main Body Content -->
        <div class="flex-1 overflow-y-auto p-4 sm:p-6" id="target-subview-content">
          ${this.renderSubview()}
        </div>
      </div>
    `;

    this.bindEvents();
  }

  getPathForView() {
    switch (this.currentView) {
      case 'directory': return '/api/search';
      case 'documents': return '/api/documents';
      case 'support': return '/api/tickets';
      case 'login': return '/auth/login';
      default: return '/';
    }
  }

  renderSubview() {
    switch (this.currentView) {
      case 'directory': return this.renderDirectoryView();
      case 'documents': return this.renderDocumentsView();
      case 'login': return this.renderLoginView();
      case 'support': return this.renderSupportView();
      default: return '';
    }
  }

  // --- 1. ASSET DIRECTORY (SQL Injection & Reflected XSS) ---
  renderDirectoryView() {
    return `
      <div class="max-w-5xl mx-auto space-y-5">
        <!-- Hero Search Section -->
        <div class="bg-gradient-to-r from-slate-900 to-[#131b2e] p-6 rounded-xl border border-slate-800 shadow-xl space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 class="text-lg font-bold text-white flex items-center gap-2">
                Enterprise Infrastructure Directory
              </h2>
              <p class="text-xs text-slate-400">Search corporate hardware inventory, network gateways, and server assets.</p>
            </div>
            <span class="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-2.5 py-1 rounded-md self-start">
              Endpoint: GET /api/search?q=
            </span>
          </div>

          <form id="asset-search-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="asset-search-input" 
                placeholder="Search by asset tag, hostname, appliance type, or model..." 
                class="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono shadow-inner"
              />
            </div>
            <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2.5 rounded-lg text-xs transition-all flex items-center gap-1.5 shadow-md">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              <span>Query</span>
            </button>
          </form>
        </div>

        <!-- Dynamic Results Area -->
        <div id="asset-results-area" class="space-y-4">
          ${this.getStandardDirectoryHTML()}
        </div>
      </div>
    `;
  }

  getStandardDirectoryHTML() {
    return `
      <div class="bg-slate-900/90 rounded-xl border border-slate-800 overflow-hidden shadow-xl">
        <div class="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between text-xs">
          <span class="font-bold text-slate-300">Active Infrastructure Assets</span>
          <span class="text-[11px] text-slate-400 font-mono">Showing 4 indexed assets</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left font-mono text-xs">
            <thead class="bg-slate-950 text-slate-400 border-b border-slate-800">
              <tr>
                <th class="p-3">Asset ID</th>
                <th class="p-3">Appliance Name</th>
                <th class="p-3">IP / Subnet</th>
                <th class="p-3">Environment</th>
                <th class="p-3">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/80 text-slate-200">
              <tr class="hover:bg-slate-800/30">
                <td class="p-3 text-cyan-400 font-bold">ASSET-101</td>
                <td class="p-3 font-medium text-white">Edge Perimeter Firewall (Primary)</td>
                <td class="p-3 text-slate-400">10.0.1.1/24</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">Production</span></td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">Online</span></td>
              </tr>
              <tr class="hover:bg-slate-800/30">
                <td class="p-3 text-cyan-400 font-bold">ASSET-102</td>
                <td class="p-3 font-medium text-white">Core PostgreSQL Database Cluster</td>
                <td class="p-3 text-slate-400">10.0.4.12/24</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">Production</span></td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">Online</span></td>
              </tr>
              <tr class="hover:bg-slate-800/30">
                <td class="p-3 text-cyan-400 font-bold">ASSET-103</td>
                <td class="p-3 font-medium text-white">Enterprise Syslog / SIEM Collector</td>
                <td class="p-3 text-slate-400">10.0.8.50/24</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">Security</span></td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">Online</span></td>
              </tr>
              <tr class="hover:bg-slate-800/30">
                <td class="p-3 text-cyan-400 font-bold">ASSET-104</td>
                <td class="p-3 font-medium text-white">Corporate Identity SSO Gateway</td>
                <td class="p-3 text-slate-400">10.0.2.10/24</td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">Identity</span></td>
                <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">Online</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // --- 2. DOCUMENT REPOSITORY (Directory Traversal / Path Traversal) ---
  renderDocumentsView() {
    return `
      <div class="max-w-4xl mx-auto space-y-5">
        <div class="bg-gradient-to-r from-slate-900 to-[#131b2e] p-6 rounded-xl border border-slate-800 shadow-xl space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 class="text-lg font-bold text-white flex items-center gap-2">
                Corporate Document Repository
              </h2>
              <p class="text-xs text-slate-400">Access and preview compliance audits, operational guidelines, and server policy files.</p>
            </div>
            <span class="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-2.5 py-1 rounded-md self-start">
              Endpoint: GET /api/documents?file=
            </span>
          </div>

          <!-- Document Retrieval Form -->
          <form id="doc-fetch-form" class="flex gap-2">
            <div class="relative flex-1">
              <input 
                type="text" 
                id="doc-file-input" 
                value="annual_compliance_2026.pdf" 
                placeholder="Enter filename to view (e.g. annual_compliance_2026.pdf)" 
                class="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-4 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500 shadow-inner"
              />
            </div>
            <button type="submit" class="bg-cyan-600 hover:bg-cyan-500 text-white font-medium px-4 py-2 rounded-lg text-xs transition-all flex items-center gap-1.5 shadow-md">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>Load File</span>
            </button>
          </form>

          <!-- Standard Documents List -->
          <div class="pt-2 border-t border-slate-800/80">
            <span class="text-[11px] text-slate-400 font-mono block mb-2">Available Public Documents:</span>
            <div class="flex flex-wrap gap-2 text-xs">
              <button type="button" class="btn-sample-doc bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded font-mono border border-slate-700" data-doc="annual_compliance_2026.pdf">
                📄 annual_compliance_2026.pdf
              </button>
              <button type="button" class="btn-sample-doc bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded font-mono border border-slate-700" data-doc="it_security_charter.docx">
                📄 it_security_charter.docx
              </button>
              <button type="button" class="btn-sample-doc bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded font-mono border border-slate-700" data-doc="incident_playbook.pdf">
                📄 incident_playbook.pdf
              </button>
            </div>
          </div>
        </div>

        <!-- File Content Display Card -->
        <div id="doc-preview-area" class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-3 font-mono text-xs">
          ${this.getStandardDocumentPreviewHTML('annual_compliance_2026.pdf')}
        </div>
      </div>
    `;
  }

  getStandardDocumentPreviewHTML(filename) {
    return `
      <div class="flex items-center justify-between border-b border-slate-800 pb-2.5">
        <span class="text-slate-400">File Preview: <strong class="text-white">${escapeHtml(filename)}</strong></span>
        <span class="text-emerald-400 text-[11px]">HTTP 200 OK</span>
      </div>
      <div class="bg-slate-950 p-4 rounded-lg border border-slate-800/80 text-slate-300 leading-relaxed font-sans text-xs">
        <h4 class="font-bold text-white text-sm mb-2">Aegis Corporate IT Security & Compliance Charter 2026</h4>
        <p class="mb-2">This document certifies that Aegis Corporation adheres to enterprise access control standards and automated logging policies. All inbound HTTP requests to internal endpoints are retained in SIEM archives for forensic inspection.</p>
        <p class="text-slate-400">Storage Root: <code>/var/www/portal/storage/documents/</code></p>
      </div>
    `;
  }

  // --- 3. SSO LOGIN (SQL Injection Auth Bypass) ---
  renderLoginView() {
    return `
      <div class="max-w-md mx-auto my-6 space-y-5">
        <div class="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-2xl space-y-5">
          <div class="text-center space-y-1">
            <div class="inline-flex items-center justify-center w-11 h-11 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800 mb-2">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            </div>
            <h2 class="text-base font-bold text-white">Employee Identity Access Management</h2>
            <p class="text-xs text-slate-400">Authenticate using enterprise credentials to access protected management APIs.</p>
          </div>

          <form id="target-login-form" class="space-y-4">
            <div>
              <label class="block text-xs font-mono text-slate-300 mb-1">Corporate ID / Username</label>
              <input 
                type="text" 
                id="login-username" 
                placeholder="e.g. sec_admin" 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div>
              <label class="block text-xs font-mono text-slate-300 mb-1">Password</label>
              <input 
                type="password" 
                id="login-password" 
                placeholder="Enter password" 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            <div id="login-feedback-box" class="hidden text-xs p-3 rounded-lg font-mono"></div>

            <button type="submit" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2.5 rounded-lg text-xs transition-all shadow-md">
              Sign In
            </button>
          </form>

          <div class="pt-3 border-t border-slate-800 text-center">
            <span class="text-[11px] text-slate-500 font-mono">Telemetry: POST /auth/login</span>
          </div>
        </div>
      </div>
    `;
  }

  // --- 4. SUPPORT & FEEDBACK (Stored XSS) ---
  renderSupportView() {
    return `
      <div class="max-w-4xl mx-auto space-y-5">
        <div class="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-xl space-y-4">
          <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 class="text-lg font-bold text-white">Internal IT Support Ticket System</h2>
              <p class="text-xs text-slate-400">Report infrastructure issues to internal systems engineering.</p>
            </div>
            <span class="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-2.5 py-1 rounded-md self-start">
              Endpoint: POST /api/tickets
            </span>
          </div>

          <form id="support-ticket-form" class="space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs font-mono text-slate-300 mb-1">Employee Email</label>
                <input 
                  type="email" 
                  id="ticket-email" 
                  value="operator@aegiscorp.internal" 
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>
              <div>
                <label class="block text-xs font-mono text-slate-300 mb-1">Ticket Subject</label>
                <input 
                  type="text" 
                  id="ticket-subject" 
                  placeholder="Brief summary of request" 
                  class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>
            </div>

            <div>
              <label class="block text-xs font-mono text-slate-300 mb-1">Issue Description</label>
              <textarea 
                id="ticket-details" 
                rows="3" 
                placeholder="Provide incident or inquiry details..." 
                class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-emerald-500"
                required
              ></textarea>
            </div>

            <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-4 py-2 rounded-lg text-xs transition-all">
              Submit Ticket (POST)
            </button>
          </form>
        </div>

        <!-- Open Tickets Table -->
        <div class="bg-slate-900 rounded-xl border border-slate-800 p-5 space-y-3">
          <h3 class="text-xs font-bold text-white font-mono uppercase tracking-wider">Recently Logged Support Tickets</h3>
          <div class="space-y-2" id="ticket-feed">
            ${this.renderTicketList()}
          </div>
        </div>
      </div>
    `;
  }

  renderTicketList() {
    return this.tickets.map(t => `
      <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono flex items-start justify-between gap-3">
        <div>
          <div class="flex items-center gap-2 mb-1">
            <span class="text-cyan-400 font-bold">${escapeHtml(t.id)}</span>
            <span class="text-slate-400 text-[11px]">${escapeHtml(t.user)}</span>
            <span class="text-slate-500 text-[10px]">${escapeHtml(t.date)}</span>
          </div>
          <div class="text-slate-200">${escapeHtml(t.subject)}</div>
        </div>
      </div>
    `).join('');
  }

  // --- EVENT BINDING ---
  bindEvents() {
    const navDir = document.getElementById('nav-directory');
    const navDoc = document.getElementById('nav-documents');
    const navLog = document.getElementById('nav-login');
    const navSup = document.getElementById('nav-support');

    if (navDir) navDir.onclick = () => this.setView('directory');
    if (navDoc) navDoc.onclick = () => this.setView('documents');
    if (navLog) navLog.onclick = () => this.setView('login');
    if (navSup) navSup.onclick = () => this.setView('support');

    if (this.currentView === 'directory') this.bindDirectoryEvents();
    if (this.currentView === 'documents') this.bindDocumentsEvents();
    if (this.currentView === 'login') this.bindLoginEvents();
    if (this.currentView === 'support') this.bindSupportEvents();
  }

  // --- DIRECTORY SEARCH LOGIC (SQLi & Reflected XSS) ---
  bindDirectoryEvents() {
    const form = document.getElementById('asset-search-form');
    const input = document.getElementById('asset-search-input');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const query = (input.value || '').trim();
        if (!query) return;

        const lower = query.toLowerCase();
        let status = 200;

        // Check if single quote causes database syntax error
        if (query.includes("'") && !lower.includes('union') && !lower.includes('or')) {
          status = 500;
        }

        // Ingest real HTTP GET log into SIEM with exact timestamp
        logEngine.ingest({
          client_ip: '203.0.113.195',
          method: 'GET',
          uri: '/api/search',
          query_params: { q: query },
          status: status,
          user_agent: navigator.userAgent
        });

        this.processDirectoryQuery(query, status);
      };
    }
  }

  processDirectoryQuery(query, status) {
    const resultsArea = document.getElementById('asset-results-area');
    if (!resultsArea) return;

    const lower = query.toLowerCase();

    // 1. Reflected XSS
    if (lower.includes('<script>') || lower.includes('onerror=') || lower.includes('<svg') || lower.includes('onload=')) {
      this.triggerXssAlert(query);
      resultsArea.innerHTML = `
        <div class="bg-amber-950/20 border border-amber-600/50 p-4 rounded-xl text-amber-200 space-y-2">
          <div class="font-bold flex items-center gap-2">
            ⚠️ Reflection in Document Object Model:
          </div>
          <div class="font-mono text-xs bg-slate-950 p-3 rounded border border-amber-800 break-all">
            Query string: ${escapeHtml(query)}
          </div>
          <p class="text-xs text-amber-300">The application reflected your search term into the DOM without sanitization.</p>
        </div>
      `;
      return;
    }

    // 2. SQLi Database Error (500)
    if (status === 500) {
      sfx.playError();
      showToast("HTTP 500 Internal Server Error (Database Exception)", "error");
      resultsArea.innerHTML = `
        <div class="bg-rose-950/30 border border-rose-700/60 p-4 rounded-xl text-rose-200 font-mono text-xs space-y-2">
          <div class="font-bold text-rose-400">Server Error: 500 Internal Server Error</div>
          <div class="bg-slate-950 p-3 rounded border border-rose-900 text-slate-300 select-all">
            org.postgresql.util.PSQLException: ERROR: syntax error at or near "'"<br>
            LINE 1: SELECT * FROM assets WHERE name ILIKE '%${escapeHtml(query)}%'
          </div>
          <p class="text-slate-400 text-[11px]">Database error captured and recorded in SIEM access log.</p>
        </div>
      `;
      return;
    }

    // 3. SQLi UNION SELECT Data Exfiltration
    if (lower.includes('union') && lower.includes('select')) {
      sfx.playSuccess();
      showToast("SQL Injection: UNION SELECT executed!", "success");
      resultsArea.innerHTML = `
        <div class="bg-slate-900 border border-emerald-500/60 rounded-xl p-5 shadow-2xl space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <span class="text-xs font-mono text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">UNION Query Succeeded</span>
              <h3 class="text-base font-bold text-white mt-1">Exfiltrated Database Table: <code class="text-cyan-400">users</code></h3>
            </div>
            <span class="text-xs text-slate-400 font-mono">3 records leaked</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-2.5">ID</th>
                  <th class="p-2.5">Username</th>
                  <th class="p-2.5">Password Hash / Secret Key</th>
                  <th class="p-2.5">Email</th>
                  <th class="p-2.5">Role</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800 text-slate-200">
                <tr class="bg-emerald-950/30 text-emerald-300">
                  <td class="p-2.5 font-bold">1</td>
                  <td class="p-2.5 font-bold">sec_admin</td>
                  <td class="p-2.5">BLITZ{5ql1_3xf1ltr4t10n_k9x27p4}</td>
                  <td class="p-2.5">admin@aegiscorp.internal</td>
                  <td class="p-2.5 font-bold text-white">Global Administrator</td>
                </tr>
                <tr>
                  <td class="p-2.5">2</td>
                  <td class="p-2.5">svc_backup</td>
                  <td class="p-2.5">$2y$12$N9qo8uLOickgx2...</td>
                  <td class="p-2.5">backup@aegiscorp.internal</td>
                  <td class="p-2.5">Service Account</td>
                </tr>
                <tr>
                  <td class="p-2.5">3</td>
                  <td class="p-2.5">audit_officer</td>
                  <td class="p-2.5">$2y$12$mKx31PzQ991v...</td>
                  <td class="p-2.5">compliance@aegiscorp.internal</td>
                  <td class="p-2.5">Security Auditor</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="text-[11px] text-slate-400 font-mono">
            Full GET query exfiltration logged to SIEM telemetry.
          </div>
        </div>
      `;
      return;
    }

    // Default regular search
    resultsArea.innerHTML = this.getStandardDirectoryHTML();
  }

  // --- DOCUMENTS LOGIC (Directory Traversal / Path Traversal) ---
  bindDocumentsEvents() {
    const form = document.getElementById('doc-fetch-form');
    const input = document.getElementById('doc-file-input');
    const sampleBtns = document.querySelectorAll('.btn-sample-doc');

    sampleBtns.forEach(btn => {
      btn.onclick = () => {
        if (input) {
          input.value = btn.getAttribute('data-doc');
          form.dispatchEvent(new Event('submit', { cancelable: true }));
        }
      };
    });

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const filepath = (input.value || '').trim();
        if (!filepath) return;

        const isTraversal = filepath.includes('../') || filepath.includes('..\\') || filepath.includes('%2e%2e');
        const status = 200;

        // Ingest real HTTP GET log into SIEM
        logEngine.ingest({
          client_ip: '203.0.113.195',
          method: 'GET',
          uri: '/api/documents',
          query_params: { file: filepath },
          status: status,
          user_agent: navigator.userAgent
        });

        this.processDocumentFetch(filepath);
      };
    }
  }

  processDocumentFetch(filepath) {
    const previewArea = document.getElementById('doc-preview-area');
    if (!previewArea) return;

    const lower = filepath.toLowerCase();

    // 1. Directory Traversal targeting /etc/passwd
    if (lower.includes('etc/passwd') || lower.includes('etc%2fpasswd')) {
      sfx.playAlert();
      showToast("Directory Traversal: /etc/passwd leaked!", "warning");
      previewArea.innerHTML = `
        <div class="flex items-center justify-between border-b border-slate-800 pb-2.5">
          <span class="text-amber-400 font-bold">⚠️ Traversal Success: /etc/passwd</span>
          <span class="text-emerald-400 text-[11px]">HTTP 200 OK</span>
        </div>
        <pre class="bg-slate-950 p-4 rounded-lg border border-slate-800 text-amber-300 font-mono text-xs overflow-x-auto select-all">
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
aegis_app:x:1001:1001:Aegis Service:/var/www/portal:/bin/bash
sec_admin:x:1002:1002:Security Lead:/home/sec_admin:/bin/bash
postgres:x:104:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
        </pre>
      `;
      return;
    }

    // 2. Directory Traversal targeting system configuration/secrets
    if (lower.includes('secrets.env') || lower.includes('config.env') || lower.includes('.env')) {
      sfx.playSuccess();
      showToast("Directory Traversal: Sensitive configuration file exposed!", "success");
      previewArea.innerHTML = `
        <div class="flex items-center justify-between border-b border-slate-800 pb-2.5">
          <span class="text-emerald-400 font-bold">✓ Traversal Exfiltration: /system/secrets.env</span>
          <span class="text-emerald-400 text-[11px]">HTTP 200 OK</span>
        </div>
        <pre class="bg-slate-950 p-4 rounded-lg border border-slate-800 text-emerald-300 font-mono text-xs overflow-x-auto select-all">
# Aegis Internal System Secrets & Configuration
NODE_ENV=production
DATABASE_URL=postgres://pgadmin:SuperSecret2026@10.0.4.12:5432/aegis_db
JWT_SECRET_SIGNER=0x79a1f4b209e8d1c9
FLAG_SYSTEM_SECRET=BLITZ{p4th_tr4v3rs4l_f1l3_r34d_8a3d1}
ALLOWED_ORIGIN=https://portal.aegiscorp.internal
        </pre>
      `;
      return;
    }

    // Default regular document
    previewArea.innerHTML = this.getStandardDocumentPreviewHTML(filepath);
  }

  // --- LOGIN EVENTS ---
  bindLoginEvents() {
    const form = document.getElementById('target-login-form');
    const uInput = document.getElementById('login-username');
    const pInput = document.getElementById('login-password');
    const fbBox = document.getElementById('login-feedback-box');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const username = (uInput.value || '').trim();
        const password = (pInput.value || '').trim();

        // SQLi Auth Bypass: ' OR '1'='1 or admin' --
        const isSqliBypass = password.includes("'") && (password.toLowerCase().includes('or') || password.includes('--'));
        const status = isSqliBypass ? 302 : 401;

        // Ingest real HTTP POST log with actual request body
        logEngine.ingest({
          client_ip: '203.0.113.195',
          method: 'POST',
          uri: '/auth/login',
          body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
          status: status,
          user_agent: navigator.userAgent
        });

        if (isSqliBypass) {
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-emerald-950 text-emerald-300 border border-emerald-700 block";
          fbBox.innerHTML = `<strong>✓ Authentication Bypassed via SQL Injection!</strong> Session established for user '${escapeHtml(username)}'.`;
          sfx.playSuccess();
        } else {
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-rose-950 text-rose-300 border border-rose-800 block";
          fbBox.innerHTML = `<strong>✕ 401 Unauthorized:</strong> Invalid credentials. Attempt logged to audit trail.`;
          sfx.playError();
        }
      };
    }
  }

  // --- SUPPORT TICKET EVENTS (Stored XSS) ---
  bindSupportEvents() {
    const form = document.getElementById('support-ticket-form');
    const emailInput = document.getElementById('ticket-email');
    const subjInput = document.getElementById('ticket-subject');
    const detailsInput = document.getElementById('ticket-details');

    if (form) {
      form.onsubmit = (e) => {
        e.preventDefault();
        const email = (emailInput.value || '').trim();
        const subj = (subjInput.value || '').trim();
        const details = (detailsInput.value || '').trim();

        // Log POST to SIEM
        logEngine.ingest({
          client_ip: '203.0.113.195',
          method: 'POST',
          uri: '/api/tickets',
          body: `email=${encodeURIComponent(email)}&subject=${encodeURIComponent(subj)}&details=${encodeURIComponent(details)}`,
          status: 201,
          user_agent: navigator.userAgent
        });

        this.tickets.unshift({
          id: `TCK-${Math.floor(Math.random() * 800 + 1050)}`,
          user: email,
          subject: subj,
          date: 'Just now'
        });

        const feed = document.getElementById('ticket-feed');
        if (feed) feed.innerHTML = this.renderTicketList();

        if (details.toLowerCase().includes('<script') || details.toLowerCase().includes('onerror=') || subj.toLowerCase().includes('<script')) {
          this.triggerXssAlert(details || subj);
        } else {
          showToast("Ticket submitted successfully (POST logged).", "success");
        }

        subjInput.value = '';
        detailsInput.value = '';
      };
    }
  }

  triggerXssAlert(payload) {
    sfx.playAlert();
    const modal = document.createElement('div');
    modal.className = "fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-sm";
    modal.innerHTML = `
      <div class="bg-slate-900 border-2 border-amber-500 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4 font-mono text-xs">
        <div class="flex items-center gap-3 text-amber-400">
          <svg class="w-6 h-6 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <span class="font-bold text-sm text-white">Browser Security Sandbox: Script Execution</span>
        </div>
        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
          <span class="text-slate-500 block mb-1">Executed Payload:</span>
          <div class="text-amber-300 break-all font-bold">${escapeHtml(payload)}</div>
        </div>
        <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
          <span class="text-slate-500 block mb-1">Exposed Session Token:</span>
          <div class="text-cyan-400 break-all">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</div>
        </div>
        <div class="bg-emerald-950/60 p-3 rounded-lg border border-emerald-600 text-emerald-300">
          <span class="font-bold block mb-1">Challenge Flag:</span>
          <div class="text-emerald-400 font-bold select-all">BLITZ{x55_d0m_3x3cut10n_9c417e2}</div>
        </div>
        <button type="button" class="close-xss-btn w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-2 rounded-lg transition-all">
          Dismiss & View Telemetry in SIEM
        </button>
      </div>
    `;

    document.body.appendChild(modal);
    modal.querySelector('.close-xss-btn').onclick = () => modal.remove();
  }
}

export const targetApp = new TargetApp();
