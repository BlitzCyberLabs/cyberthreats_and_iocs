/**
 * BLITZ Cyber Threats & IOC Investigation Lab - SOC Dashboard View
 * Enterprise SIEM-style telemetry monitoring console inspired by Splunk Enterprise & Microsoft Sentinel.
 */

import { api } from '../api.js';

export function renderSocDashboard(container, state, navigateTo, openEventModal) {
  let myActivityOnly = false;
  let severityChart = null;

  async function loadDataAndRender() {
    try {
      const stats = await api.getStats();
      const eventsRes = await api.getEvents({
        limit: 15,
        my_activity_only: myActivityOnly ? 'true' : 'false'
      });

      render(stats, eventsRes.events || []);
    } catch (err) {
      container.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-sm">Error loading SOC dashboard data: ${err.message}</div>`;
    }
  }

  function render(stats, recentEvents) {
    container.innerHTML = `
      <div class="space-y-6">
        <!-- SIEM Control & Filter Header -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl flex flex-wrap items-center justify-between gap-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-700/60 flex items-center justify-center text-cyan-400 shadow-md">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <h1 class="text-base font-bold text-white font-mono tracking-tight">Enterprise SOC SIEM Console</h1>
                <span class="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono font-bold">LIVE TELEMETRY STREAM</span>
              </div>
              <p class="text-xs text-slate-400 font-mono">
                Monitoring Host: <span class="text-cyan-400">blitzcorp.internal</span> • Connection IP: <span class="text-slate-200 font-bold">${state.session?.publicIp || 'Active'}</span>
              </p>
            </div>
          </div>

          <!-- Prominent Toggle: SHOW MY ACTIVITY ONLY -->
          <div class="flex items-center gap-3">
            <label class="flex items-center gap-2.5 bg-slate-950 px-4 py-2 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-all shadow-inner">
              <input type="checkbox" id="toggle-my-activity" ${myActivityOnly ? 'checked' : ''} class="w-4 h-4 rounded text-cyan-500 focus:ring-0 bg-slate-900 border-slate-700 cursor-pointer" />
              <span class="text-xs font-mono font-bold ${myActivityOnly ? 'text-cyan-400' : 'text-slate-400'}">
                SHOW MY ACTIVITY ONLY
              </span>
            </label>

            <button id="btn-open-explorer" class="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono text-xs transition-all flex items-center gap-1.5">
              <span>Event Explorer</span>
              <svg class="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
            </button>
          </div>
        </div>

        <!-- Metric KPI Cards -->
        <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 font-mono">
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-slate-500 uppercase block truncate">Total Events</span>
            <div class="text-xl font-bold text-white mt-1">${stats.totalEvents}</div>
            <span class="text-[10px] text-slate-500 font-sans">Database</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-cyan-400 uppercase block truncate">My Activity</span>
            <div class="text-xl font-bold text-cyan-300 mt-1">${stats.actualStudentEvents}</div>
            <span class="text-[10px] text-cyan-500 font-sans">Actual attacks</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-slate-400 uppercase block truncate">Simulated</span>
            <div class="text-xl font-bold text-slate-300 mt-1">${stats.simulatedEvents}</div>
            <span class="text-[10px] text-slate-500 font-sans">Baseline logs</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-rose-400 uppercase block truncate">Critical</span>
            <div class="text-xl font-bold text-rose-400 mt-1">${stats.severities?.CRITICAL || 0}</div>
            <span class="text-[10px] text-rose-500/80 font-sans">Immediate triage</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-orange-400 uppercase block truncate">High</span>
            <div class="text-xl font-bold text-orange-400 mt-1">${stats.severities?.HIGH || 0}</div>
            <span class="text-[10px] text-orange-500/80 font-sans">Exploit probes</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-yellow-400 uppercase block truncate">Medium</span>
            <div class="text-xl font-bold text-yellow-400 mt-1">${stats.severities?.MEDIUM || 0}</div>
            <span class="text-[10px] text-yellow-500/80 font-sans">Suspicious</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-emerald-400 uppercase block truncate">Low</span>
            <div class="text-xl font-bold text-emerald-400 mt-1">${stats.severities?.LOW || 0}</div>
            <span class="text-[10px] text-emerald-500/80 font-sans">Anomalies</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 p-3 rounded-xl">
            <span class="text-[10px] text-blue-400 uppercase block truncate">Info</span>
            <div class="text-xl font-bold text-blue-400 mt-1">${stats.severities?.INFO || 0}</div>
            <span class="text-[10px] text-blue-500/80 font-sans">Audited auth</span>
          </div>
        </div>

        <!-- Charts Row -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <!-- Severity Breakdown Chart -->
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
                Threat Severity Distribution
              </h3>
              <span class="text-[10px] text-slate-500 font-mono">SIEM Alert Triage</span>
            </div>
            <div class="h-52 relative flex items-center justify-center">
              <canvas id="soc-severity-chart"></canvas>
            </div>
          </div>

          <!-- Attack Categories Histogram -->
          <div class="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-xl">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-xs font-bold font-mono text-slate-300 uppercase tracking-wider">
                Event Category Breakdown
              </h3>
              <span class="text-[10px] text-slate-500 font-mono">Correlated Telemetry</span>
            </div>
            <div class="h-52 relative flex items-center justify-center">
              <canvas id="soc-category-chart"></canvas>
            </div>
          </div>
        </div>

        <!-- Recent Security Events Table -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div class="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 class="text-sm font-bold text-white font-mono uppercase tracking-wide">
                Recent Security Telemetry Stream
              </h3>
              <p class="text-xs text-slate-400">Click any event row to open the forensic log inspector</p>
            </div>
            <span class="text-xs font-mono text-slate-400">
              Showing ${recentEvents.length} events
            </span>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-3.5">Event ID</th>
                  <th class="p-3.5">Timestamp</th>
                  <th class="p-3.5">Source IP</th>
                  <th class="p-3.5">Event Type</th>
                  <th class="p-3.5">Severity</th>
                  <th class="p-3.5">Endpoint</th>
                  <th class="p-3.5">Source</th>
                  <th class="p-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80 text-slate-200">
                ${recentEvents.length === 0 ? `
                  <tr>
                    <td colspan="8" class="p-8 text-center text-slate-500 font-sans">
                      No events found matching current filter.
                    </td>
                  </tr>
                ` : recentEvents.map(evt => renderEventRow(evt)).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    bindEvents(stats);
    renderCharts(stats);
  }

  function renderEventRow(evt) {
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
        <td class="p-3.5 text-slate-400 text-[11px]">${new Date(evt.timestamp).toLocaleTimeString()}</td>
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
          <button class="btn-inspect-row px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans border border-slate-700 transition-all">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }

  function bindEvents(stats) {
    document.getElementById('toggle-my-activity')?.addEventListener('change', (e) => {
      myActivityOnly = e.target.checked;
      loadDataAndRender();
    });

    document.getElementById('btn-open-explorer')?.addEventListener('click', () => {
      navigateTo('event-explorer');
    });

    container.querySelectorAll('.event-row').forEach(row => {
      row.addEventListener('click', () => {
        const eventId = row.getAttribute('data-event-id');
        if (eventId) openEventModal(eventId);
      });
    });
  }

  function renderCharts(stats) {
    // Severity Donut Chart
    const sevCanvas = document.getElementById('soc-severity-chart');
    if (sevCanvas && window.Chart) {
      new Chart(sevCanvas, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{
            data: [
              stats.severities?.CRITICAL || 0,
              stats.severities?.HIGH || 0,
              stats.severities?.MEDIUM || 0,
              stats.severities?.LOW || 0,
              stats.severities?.INFO || 0
            ],
            backgroundColor: [
              '#f43f5e', // Critical
              '#fb923c', // High
              '#facc15', // Medium
              '#34d399', // Low
              '#60a5fa'  // Info
            ],
            borderColor: '#0f172a',
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#94a3b8', font: { family: 'monospace', size: 10 }, boxWidth: 12 }
            }
          }
        }
      });
    }

    // Category Bar Chart
    const catCanvas = document.getElementById('soc-category-chart');
    if (catCanvas && window.Chart && stats.categories) {
      new Chart(catCanvas, {
        type: 'bar',
        data: {
          labels: stats.categories.map(c => c.attack_category.toUpperCase()),
          datasets: [{
            label: 'Event Volume',
            data: stats.categories.map(c => c.count),
            backgroundColor: '#0284c7',
            borderColor: '#38bdf8',
            borderWidth: 1,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: { ticks: { color: '#94a3b8', font: { family: 'monospace', size: 10 } }, grid: { color: '#1e293b' } },
            y: { ticks: { color: '#94a3b8', font: { family: 'monospace', size: 10 } }, grid: { color: '#1e293b' } }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    }
  }

  loadDataAndRender();
}
