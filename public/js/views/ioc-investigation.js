/**
 * BLITZ Cyber Threats & IOC Investigation Lab - IOC Investigation View
 * Dedicated Indicator of Compromise (IoC) analysis, threat dossiers, and correlation workflow.
 */

import { api } from '../api.js';

export function renderIocInvestigation(container, state, navigateTo, openEventModal) {
  async function loadAndRender() {
    try {
      const data = await api.getIocIndicators();
      render(data.dossiers || [], data.recentIocEvents || []);
    } catch (err) {
      container.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-sm">Error loading IOC data: ${err.message}</div>`;
    }
  }

  function render(dossiers, recentEvents) {
    container.innerHTML = `
      <div class="space-y-6">
        <!-- Header -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800 uppercase tracking-widest">
              THREAT INTELLIGENCE &amp; FORENSICS
            </span>
            <span class="text-xs text-slate-400 font-mono">Correlation &amp; Indicator Triaging</span>
          </div>
          <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1">
            Indicators of Compromise (IOC) Investigation Workspace
          </h1>
          <p class="text-xs text-slate-400 max-w-3xl leading-relaxed mt-1">
            Analyze threat indicators associated with real and simulated attack activity. Correlate offensive payloads with server access log signatures, identify specific IoCs, and retrieve the Investigation Flags embedded inside your event records.
          </p>
        </div>

        <!-- Curated Attack Dossiers (Guided Investigation) -->
        <div class="space-y-4">
          <h2 class="text-sm font-bold text-white font-mono uppercase tracking-wide">
            Target Attack Investigation Dossiers
          </h2>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            ${dossiers.map(d => renderDossierCard(d)).join('')}
          </div>
        </div>

        <!-- Recent Correlated IOC Events Table -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
          <div class="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h3 class="text-sm font-bold text-white font-mono uppercase tracking-wide">
                Identified Indicators of Compromise (Recent Events)
              </h3>
              <p class="text-xs text-slate-400">Events with explicit IoC indicators captured in query parameters and request bodies</p>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full text-left font-mono text-xs">
              <thead class="bg-slate-950 text-slate-400 border-b border-slate-800">
                <tr>
                  <th class="p-3.5">Event ID</th>
                  <th class="p-3.5">Timestamp</th>
                  <th class="p-3.5">Source IP</th>
                  <th class="p-3.5">Category</th>
                  <th class="p-3.5">Endpoint</th>
                  <th class="p-3.5">IoC Evidence</th>
                  <th class="p-3.5">Source</th>
                  <th class="p-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-800/80 text-slate-200">
                ${recentEvents.slice(0, 15).map(evt => `
                  <tr class="ioc-event-row cursor-pointer hover:bg-slate-800/50 transition-colors ${evt.is_my_activity ? 'bg-cyan-950/20 border-l-4 border-l-cyan-500' : ''}" data-event-id="${evt.id}">
                    <td class="p-3.5 font-bold ${evt.is_my_activity ? 'text-cyan-400' : 'text-slate-300'}">${evt.id}</td>
                    <td class="p-3.5 text-slate-400 text-[11px]">${new Date(evt.timestamp).toLocaleTimeString()}</td>
                    <td class="p-3.5 font-bold ${evt.is_my_activity ? 'text-cyan-300' : 'text-slate-400'}">${evt.source_ip}</td>
                    <td class="p-3.5"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 uppercase">${evt.attack_category}</span></td>
                    <td class="p-3.5 text-slate-400 truncate max-w-xs">${evt.endpoint}</td>
                    <td class="p-3.5 text-amber-300 font-bold truncate max-w-sm" title="${evt.ioc_indicators}">${evt.ioc_indicators}</td>
                    <td class="p-3.5">
                      ${evt.is_my_activity ? `
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-600 animate-pulse">
                          ● MY ACTIVITY
                        </span>
                      ` : `
                        <span class="px-2 py-0.5 rounded text-[10px] bg-slate-950 text-slate-500 border border-slate-800">
                          SIMULATED
                        </span>
                      `}
                    </td>
                    <td class="p-3.5 text-right">
                      <button class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-[11px] font-sans border border-slate-700 transition-all">
                        Inspect
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    bindEvents();
  }

  function renderDossierCard(d) {
    return `
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-5 flex flex-col justify-between shadow-xl space-y-4">
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">
              ${d.id}
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${d.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border-rose-800' : 'bg-orange-950 text-orange-300 border-orange-800'}">
              ${d.severity}
            </span>
          </div>

          <h3 class="text-sm font-bold text-white">${d.title}</h3>
          <p class="text-xs text-slate-400 leading-relaxed font-sans">${d.description}</p>

          <div class="space-y-2 pt-2 border-t border-slate-800 font-mono text-[11px]">
            <div>
              <span class="text-slate-500 block uppercase text-[10px]">Monitored Endpoints</span>
              <div class="text-cyan-300 mt-0.5">${d.monitoredEndpoints.join(', ')}</div>
            </div>
            <div>
              <span class="text-slate-500 block uppercase text-[10px]">Suspicious Payload Indicators</span>
              <div class="text-amber-300 mt-0.5 flex flex-wrap gap-1">
                ${d.suspiciousPayloads.map(p => `<code class="bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 select-all">${p}</code>`).join('')}
              </div>
            </div>
            <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-slate-300 font-sans text-xs">
              <strong>💡 Investigation Guide:</strong> ${d.investigationGuide}
            </div>
          </div>
        </div>

        <button class="btn-pivot-dossier w-full py-2 rounded-xl bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 font-semibold text-xs font-mono transition-all flex items-center justify-center gap-1.5" data-category="${d.attackCategory}">
          <span>Pivot to Correlated Events</span>
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>
        </button>
      </div>
    `;
  }

  function bindEvents() {
    container.querySelectorAll('.btn-pivot-dossier').forEach(btn => {
      btn.addEventListener('click', () => {
        const cat = btn.getAttribute('data-category');
        navigateTo('event-explorer', { category: cat });
      });
    });

    container.querySelectorAll('.ioc-event-row').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-event-id');
        if (id) openEventModal(id);
      });
    });
  }

  loadAndRender();
}
