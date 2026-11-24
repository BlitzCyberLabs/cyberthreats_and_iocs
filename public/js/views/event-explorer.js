/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Event Explorer View
 * Deep-dive forensic log exploration, search, multi-field filtering, pagination, and detail drawer.
 */

import { api } from '../api.js';

export function renderEventExplorer(container, state, navigateTo, openEventModal) {
  let search = '';
  let severity = 'ALL';
  let category = 'ALL';
  let sourceIp = '';
  let myActivityOnly = false;
  let page = 1;
  let limit = 20;

  async function loadAndRender() {
    try {
      const res = await api.getEvents({
        search,
        severity: severity === 'ALL' ? '' : severity,
        category: category === 'ALL' ? '' : category,
        source_ip: sourceIp,
        my_activity_only: myActivityOnly ? 'true' : 'false',
        page,
        limit
      });

      render(res.events || [], res.pagination || { page: 1, limit: 20, total: 0, totalPages: 1 });
    } catch (err) {
      container.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-sm">Error loading events: ${err.message}</div>`;
    }
  }

  function render(events, pagination) {
    container.innerHTML = `
      <div class="space-y-6">
        <!-- Event Explorer Header & Search Bar -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800 uppercase tracking-widest">
                  SIEM EVENT LOGS
                </span>
                <span class="text-xs text-slate-400 font-mono">Forensic Access & Telemetry Explorer</span>
              </div>
              <h1 class="text-xl font-bold text-white tracking-tight mt-1">
                Security Event Explorer
              </h1>
            </div>

            <!-- Toggle: SHOW MY ACTIVITY ONLY -->
            <label class="flex items-center gap-2.5 bg-slate-950 px-4 py-2 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-all self-start md:self-auto">
              <input type="checkbox" id="ee-toggle-my-activity" ${myActivityOnly ? 'checked' : ''} class="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 cursor-pointer" />
              <span class="text-xs font-mono font-bold ${myActivityOnly ? 'text-cyan-400' : 'text-slate-400'}">
                SHOW MY ACTIVITY ONLY
              </span>
            </label>
          </div>

          <!-- Multi-field Filter Controls -->
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 font-mono text-xs">
            <!-- Free Text / Keyword Search -->
            <div class="relative">
              <input type="text" id="ee-search" value="${search}" placeholder="Search keywords, IDs, URIs, payloads..." class="w-full bg-slate-950 border border-slate-700 rounded-lg pl-8 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
              <svg class="w-4 h-4 text-slate-500 absolute left-2.5 top-2.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
            </div>

            <!-- Severity Filter -->
            <div>
              <select id="ee-severity" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500">
                <option value="ALL" ${severity === 'ALL' ? 'selected' : ''}>Severity: ALL</option>
                <option value="CRITICAL" ${severity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option>
                <option value="HIGH" ${severity === 'HIGH' ? 'selected' : ''}>HIGH</option>
                <option value="MEDIUM" ${severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option>
                <option value="LOW" ${severity === 'LOW' ? 'selected' : ''}>LOW</option>
                <option value="INFO" ${severity === 'INFO' ? 'selected' : ''}>INFO</option>
              </select>
            </div>

            <!-- Category Filter -->
            <div>
              <select id="ee-category" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500">
                <option value="ALL" ${category === 'ALL' ? 'selected' : ''}>Category: ALL</option>
                <option value="sqli" ${category === 'sqli' ? 'selected' : ''}>SQL Injection (sqli)</option>
                <option value="xss" ${category === 'xss' ? 'selected' : ''}>Cross-Site Scripting (xss)</option>
                <option value="idor" ${category === 'idor' ? 'selected' : ''}>Unauthorized Access (idor)</option>
                <option value="auth" ${category === 'auth' ? 'selected' : ''}>Authentication (auth)</option>
                <option value="brute_force" ${category === 'brute_force' ? 'selected' : ''}>Brute Force (brute_force)</option>
                <option value="recon" ${category === 'recon' ? 'selected' : ''}>Recon / Scanning (recon)</option>
                <option value="malware" ${category === 'malware' ? 'selected' : ''}>C2 / Beaconing (malware)</option>
                <option value="normal" ${category === 'normal' ? 'selected' : ''}>Normal Activity (normal)</option>
              </select>
            </div>

            <!-- Source IP Filter -->
            <div>
              <input type="text" id="ee-source-ip" value="${sourceIp}" placeholder="Filter by Source IP..." class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
            </div>
          </div>
        </div>

        <!-- Main Events Table -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div class="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
            <span class="text-slate-400">
              Showing <strong class="text-cyan-400 font-bold">${events.length}</strong> of <strong class="text-white">${pagination.total}</strong> recorded security events
            </span>
            <span class="text-slate-500 text-[11px]">Click row to open forensic detail panel</span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-950 text-slate-400 border-b border-slate-800 sticky top-0">
                <tr>
                  <th class="p-3.5">Event ID</th>
                  <th class="p-3.5">Timestamp</th>
                  <th class="p-3.5">Source IP</th>
                  <th class="p-3.5">Event Type</th>
                  <th class="p-3.5">Severity</th>
                  <th class="p-3.5">Target Endpoint</th>
                  <th class="p-3.5">Source</th>
                  <th class="p-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80 text-slate-200">
                ${events.length === 0 ? `
                  <tr>
                    <td colspan="8" class="p-8 text-center text-slate-500 font-sans">
                      No security events match the current search criteria.
                    </td>
                  </tr>
                ` : events.map(evt => renderRow(evt)).join('')}
              </tbody>
            </table>
          </div>

          <!-- Pagination Bar -->
          <div class="px-5 py-4 border-t border-slate-800 bg-slate-950/80 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
            <div class="text-slate-400 text-[11px]">
              Page <span class="text-white font-bold">${pagination.page}</span> of <span class="text-white font-bold">${pagination.totalPages || 1}</span>
            </div>

            <div class="flex items-center gap-2">
              <button id="btn-page-prev" ${pagination.page <= 1 ? 'disabled' : ''} class="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 disabled:opacity-40 disabled:pointer-events-none transition-all">
                &larr; Previous
              </button>
              <button id="btn-page-next" ${pagination.page >= pagination.totalPages ? 'disabled' : ''} class="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 disabled:opacity-40 disabled:pointer-events-none transition-all">
                Next &rarr;
              </button>
            </div>
          </div>
        </div>
      </div>
    `;

    bindEvents(pagination);
  }

  function renderRow(evt) {
    const isStudentEvent = evt.is_simulated === 0;

    const severityBadges = {
      CRITICAL: 'bg-rose-950 text-rose-300 border-rose-700 font-bold',
      HIGH: 'bg-orange-950 text-orange-300 border-orange-700 font-bold',
      MEDIUM: 'bg-yellow-950 text-yellow-300 border-yellow-700',
      LOW: 'bg-emerald-950 text-emerald-400 border-emerald-800',
      INFO: 'bg-blue-950 text-blue-300 border-blue-800'
    };

    const rowBg = isStudentEvent 
      ? 'bg-cyan-950/20 hover:bg-cyan-950/30 border-l-4 border-l-cyan-500' 
      : 'hover:bg-slate-800/40';

    return `
      <tr class="event-row cursor-pointer transition-colors ${rowBg}" data-event-id="${evt.id}">
        <td class="p-3.5 font-bold ${isStudentEvent ? 'text-cyan-400' : 'text-slate-300'}">${evt.id}</td>
        <td class="p-3.5 text-slate-400 text-[11px]">${new Date(evt.timestamp).toLocaleString()}</td>
        <td class="p-3.5 font-bold ${isStudentEvent ? 'text-cyan-300 select-all' : 'text-slate-400'}">${evt.source_ip}</td>
        <td class="p-3.5 font-sans font-medium text-slate-100">${evt.event_type}</td>
        <td class="p-3.5">
          <span class="px-2 py-0.5 rounded text-[10px] border ${severityBadges[evt.severity] || severityBadges.INFO}">
            ${evt.severity}
          </span>
        </td>
        <td class="p-3.5 text-slate-400 truncate max-w-xs" title="${evt.endpoint}">${evt.endpoint}</td>
        <td class="p-3.5">
          ${isStudentEvent ? `
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-600 shadow-sm animate-pulse">
              ● MY ACTIVITY
            </span>
          ` : `
            <span class="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-slate-500 border border-slate-800">
              SIMULATED TRAINING DATA
            </span>
          `}
        </td>
        <td class="p-3.5 text-right">
          <button class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans border border-slate-700 transition-all">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }

  function bindEvents(pagination) {
    document.getElementById('ee-toggle-my-activity')?.addEventListener('change', (e) => {
      myActivityOnly = e.target.checked;
      page = 1;
      loadAndRender();
    });

    document.getElementById('ee-search')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        search = e.target.value.trim();
        page = 1;
        loadAndRender();
      }
    });

    document.getElementById('ee-severity')?.addEventListener('change', (e) => {
      severity = e.target.value;
      page = 1;
      loadAndRender();
    });

    document.getElementById('ee-category')?.addEventListener('change', (e) => {
      category = e.target.value;
      page = 1;
      loadAndRender();
    });

    document.getElementById('ee-source-ip')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        sourceIp = e.target.value.trim();
        page = 1;
        loadAndRender();
      }
    });

    document.getElementById('btn-page-prev')?.addEventListener('click', () => {
      if (page > 1) {
        page--;
        loadAndRender();
      }
    });

    document.getElementById('btn-page-next')?.addEventListener('click', () => {
      if (page < pagination.totalPages) {
        page++;
        loadAndRender();
      }
    });

    container.querySelectorAll('.event-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-event-id');
        if (id) openEventModal(id);
      });
    });
  }

  loadAndRender();
}
