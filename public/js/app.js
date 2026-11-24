/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Main Frontend App Coordinator
 */

import { api } from './api.js';
import { renderOverview } from './views/overview.js';
import { renderAttackLab } from './views/attack-lab.js';
import { renderSocDashboard } from './views/soc-dashboard.js';
import { renderEventExplorer } from './views/event-explorer.js';
import { renderIocInvestigation } from './views/ioc-investigation.js';
import { renderChallengeProgress } from './views/challenge-progress.js';
import { renderStudentInstructions } from './views/student-instructions.js';

class BlitzApp {
  constructor() {
    this.currentView = 'overview';
    this.viewParams = {};
    this.state = {
      session: null,
      progress: null
    };
    this.sseSource = null;
  }

  async init() {
    await this.refreshState();
    this.initSSE();
    this.bindGlobalNavigation();
    this.render();
  }

  async refreshState() {
    try {
      const [session, progress] = await Promise.all([
        api.getSession(),
        api.getProgress()
      ]);
      this.state.session = session;
      this.state.progress = progress;
      this.updateNavbarHeader();
    } catch (err) {
      console.error('Error refreshing state:', err);
    }
  }

  initSSE() {
    try {
      this.sseSource = new EventSource('/api/events/stream');
      this.sseSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'NEW_ATTACK_EVENT') {
            this.showToast(`🛡️ New Security Alert Recorded from ${data.event.source_ip}: ${data.event.event_type}`, 'alert');
            this.refreshState();
            // If currently on SOC or Event Explorer, re-render
            if (this.currentView === 'soc-dashboard' || this.currentView === 'event-explorer') {
              this.render();
            }
          }
        } catch (e) {
          console.error('SSE parse error:', e);
        }
      };
    } catch (e) {
      console.warn('SSE not supported or failed to connect:', e);
    }
  }

  updateNavbarHeader() {
    const s = this.state.session;
    if (!s) return;

    const ipBadge = document.getElementById('nav-client-ip');
    if (ipBadge) ipBadge.textContent = s.publicIp || 'ONLINE';

    const progBadge = document.getElementById('nav-progress-pct');
    if (progBadge) progBadge.textContent = `${this.state.progress?.stats?.completionPercentage || 0}%`;
  }

  navigateTo(viewName, params = {}) {
    this.currentView = viewName;
    this.viewParams = params;
    window.scrollTo({ top: 0, behavior: 'smooth' });
    this.render();
  }

  bindGlobalNavigation() {
    document.querySelectorAll('.nav-link').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const view = btn.getAttribute('data-view');
        if (view) {
          this.navigateTo(view);
        }
      });
    });
  }

  render() {
    // Update active nav button
    document.querySelectorAll('.nav-link').forEach(btn => {
      const view = btn.getAttribute('data-view');
      if (view === this.currentView) {
        btn.className = "nav-link px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 text-white shadow-md shadow-blue-950/40 transition-all flex items-center gap-1.5";
      } else {
        btn.className = "nav-link px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-all flex items-center gap-1.5";
      }
    });

    const container = document.getElementById('app-main-content');
    if (!container) return;

    const openEventModal = (id) => this.showEventModal(id);

    switch (this.currentView) {
      case 'overview':
        renderOverview(container, this.state, (v, p) => this.navigateTo(v, p));
        break;
      case 'attack-lab':
        renderAttackLab(container, this.state, (v, p) => this.navigateTo(v, p), this.viewParams);
        break;
      case 'soc-dashboard':
        renderSocDashboard(container, this.state, (v, p) => this.navigateTo(v, p), openEventModal);
        break;
      case 'event-explorer':
        renderEventExplorer(container, this.state, (v, p) => this.navigateTo(v, p), openEventModal);
        break;
      case 'ioc-investigation':
        renderIocInvestigation(container, this.state, (v, p) => this.navigateTo(v, p), openEventModal);
        break;
      case 'challenge-progress':
        renderChallengeProgress(container, this.state, (v, p) => this.navigateTo(v, p));
        break;
      case 'student-instructions':
        renderStudentInstructions(container, this.state, (v, p) => this.navigateTo(v, p));
        break;
      default:
        renderOverview(container, this.state, (v, p) => this.navigateTo(v, p));
    }
  }

  async showEventModal(eventId) {
    try {
      const res = await api.getEventDetails(eventId);
      if (!res.success || !res.event) return;
      const evt = res.event;
      const isStudentEvent = evt.is_simulated === 0;

      const modal = document.createElement('div');
      modal.className = "fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md";
      modal.innerHTML = `
        <div class="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-sans text-xs text-slate-200">
          
          <!-- Modal Header -->
          <div class="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
            <div class="flex items-center gap-2.5">
              <span class="w-2.5 h-2.5 rounded-full ${isStudentEvent ? 'bg-cyan-400 animate-pulse' : 'bg-slate-500'}"></span>
              <span class="font-mono font-bold text-white text-sm">Forensic Event Inspector: ${evt.id}</span>
            </div>
            <button id="modal-close-btn" class="text-slate-400 hover:text-white p-1 text-sm font-bold">✕</button>
          </div>

          <!-- Modal Content -->
          <div class="p-6 space-y-4 overflow-y-auto flex-1 font-mono">
            
            <!-- INVESTIGATION FLAG CALLOUT (Displayed only when opening student's attack event!) -->
            ${evt.investigation_flag ? `
              <div class="bg-gradient-to-r from-emerald-950 via-slate-900 to-emerald-950 border-2 border-emerald-500 rounded-xl p-4 shadow-xl space-y-2">
                <div class="flex items-center gap-2 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                  <span>INVESTIGATION CHALLENGE FLAG UNCOVERED!</span>
                </div>
                <div class="bg-slate-950 p-3 rounded-lg border border-emerald-700/60 flex items-center justify-between">
                  <span class="text-emerald-300 font-bold text-sm select-all">${evt.investigation_flag}</span>
                  <button id="btn-copy-inv-flag" class="px-3 py-1 rounded bg-emerald-900 hover:bg-emerald-800 text-emerald-200 text-xs font-sans font-semibold">
                    Copy Flag
                  </button>
                </div>
                <p class="text-[11px] text-slate-400 font-sans">
                  This flag confirms you successfully triaged the matching security event in the SOC SIEM console. Submit it in the <strong>Challenge Progress</strong> section to finalize Stage 2!
                </p>
              </div>
            ` : ''}

            <!-- Metadata Grid -->
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px]">
              <div>
                <span class="text-slate-500 uppercase block">Source IP</span>
                <span class="font-bold ${isStudentEvent ? 'text-cyan-300' : 'text-slate-300'} select-all">${evt.source_ip}</span>
              </div>
              <div>
                <span class="text-slate-500 uppercase block">Event Type</span>
                <span class="font-bold text-white font-sans">${evt.event_type}</span>
              </div>
              <div>
                <span class="text-slate-500 uppercase block">Severity</span>
                <span class="font-bold ${evt.severity === 'CRITICAL' ? 'text-rose-400' : (evt.severity === 'HIGH' ? 'text-orange-400' : 'text-yellow-400')}">${evt.severity}</span>
              </div>
              <div>
                <span class="text-slate-500 uppercase block">HTTP Method</span>
                <span class="font-bold text-white">${evt.method}</span>
              </div>
              <div>
                <span class="text-slate-500 uppercase block">Attack Category</span>
                <span class="font-bold text-cyan-400 uppercase">${evt.attack_category}</span>
              </div>
              <div>
                <span class="text-slate-500 uppercase block">Telemetry Source</span>
                <span class="font-bold ${isStudentEvent ? 'text-cyan-300' : 'text-slate-400'}">${isStudentEvent ? 'MY ACTIVITY' : 'SIMULATED'}</span>
              </div>
            </div>

            <!-- Target Endpoint & Timestamp -->
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
              <span class="text-slate-500 text-[10px] uppercase block">Target Endpoint</span>
              <div class="text-white select-all font-bold">${evt.endpoint}</div>
              <span class="text-slate-500 text-[10px] uppercase block pt-1">Event Timestamp</span>
              <div class="text-slate-300 text-[11px]">${new Date(evt.timestamp).toISOString()} (${new Date(evt.timestamp).toLocaleString()})</div>
            </div>

            <!-- Description -->
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
              <span class="text-slate-500 text-[10px] uppercase block">Security Incident Description</span>
              <div class="text-slate-200 font-sans leading-relaxed">${evt.description}</div>
            </div>

            <!-- IOC Indicators -->
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
              <span class="text-slate-500 text-[10px] uppercase block">Indicators of Compromise (IoC)</span>
              <div class="text-amber-300 select-all font-bold">${evt.ioc_indicators || 'None recorded'}</div>
            </div>

            <!-- Payload Details -->
            ${evt.payload_details ? `
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1 text-xs">
                <span class="text-slate-500 text-[10px] uppercase block">Decoded Request Payload Details</span>
                <pre class="text-[11px] text-slate-300 overflow-x-auto select-all leading-tight whitespace-pre-wrap">${typeof evt.payload_details === 'string' ? evt.payload_details : JSON.stringify(evt.payload_details, null, 2)}</pre>
              </div>
            ` : ''}

          </div>

          <!-- Modal Footer -->
          <div class="px-6 py-3 bg-slate-950 border-t border-slate-800 flex justify-end">
            <button id="modal-done-btn" class="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-bold transition-all">
              Close Inspector
            </button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);

      const closeModal = () => modal.remove();
      modal.querySelector('#modal-close-btn')?.addEventListener('click', closeModal);
      modal.querySelector('#modal-done-btn')?.addEventListener('click', closeModal);

      modal.querySelector('#btn-copy-inv-flag')?.addEventListener('click', () => {
        navigator.clipboard.writeText(evt.investigation_flag);
        alert('Investigation Flag copied! Submit it in Challenge Progress.');
      });
    } catch (e) {
      console.error('Error fetching event modal details:', e);
    }
  }

  showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) return;

    const toast = document.createElement('div');
    toast.className = `p-3 rounded-xl shadow-2xl text-xs font-mono border flex items-center justify-between gap-3 pointer-events-auto transition-all duration-300 ${
      type === 'alert' ? 'bg-rose-950 text-rose-300 border-rose-700' : 'bg-slate-900 text-slate-200 border-slate-700'
    }`;
    toast.innerHTML = `
      <span>${message}</span>
      <button class="text-slate-400 hover:text-white text-xs font-bold">✕</button>
    `;

    toastContainer.appendChild(toast);
    toast.querySelector('button')?.addEventListener('click', () => toast.remove());
    setTimeout(() => toast.remove(), 6000);
  }
}

// Initialize on DOM load
window.addEventListener('DOMContentLoaded', () => {
  window.blitzApp = new BlitzApp();
  window.blitzApp.init();
});
