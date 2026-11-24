/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Overview View
 */

import { api } from '../api.js';

export function renderOverview(container, state, navigateTo) {
  const session = state.session || {};
  const progress = state.progress?.challenges || {};
  const stats = state.progress?.stats || {};

  container.innerHTML = `
    <div class="space-y-6">
      <!-- Welcome Hero Banner -->
      <div class="bg-gradient-to-r from-slate-900 via-indigo-950/70 to-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div class="absolute -right-10 -bottom-10 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none"></div>
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div class="space-y-2 max-w-2xl">
            <div class="flex items-center gap-2">
              <span class="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800 uppercase tracking-widest">
                DEFENSIVE CYBER RANGE v2.0
              </span>
              <span class="text-xs text-slate-400 font-mono">Enterprise Threat Hunting</span>
            </div>
            <h1 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Welcome to <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">BLITZ Cyber Threats & IOC Investigation Lab</span>
            </h1>
            <p class="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              Perform real, controlled application attacks in the isolated Attack Lab, observe how your offensive actions generate real-time forensic event telemetry, investigate Indicators of Compromise (IoCs) in the enterprise SOC dashboard, and validate both attack and investigation flags.
            </p>
          </div>

          <div class="flex flex-col sm:flex-row gap-3 shrink-0">
            <button id="btn-hero-attack" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-semibold text-xs transition-all shadow-lg shadow-rose-950/50 flex items-center justify-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
              <span>Launch Attack Lab</span>
            </button>
            <button id="btn-hero-soc" class="px-5 py-2.5 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 border border-slate-700 font-semibold text-xs transition-all flex items-center justify-center gap-2">
              <svg class="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
              <span>Open SOC Dashboard</span>
            </button>
          </div>
        </div>
      </div>

      <!-- MY CONNECTION INFORMATION (DEDICATED & PROMINENT CARD) -->
      <div class="bg-gradient-to-br from-slate-900 via-slate-900/95 to-slate-950 border-2 border-cyan-500/40 rounded-2xl p-6 shadow-2xl shadow-cyan-950/20 relative">
        <div class="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-5">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl bg-cyan-950 border border-cyan-600/50 flex items-center justify-center text-cyan-400 shadow-inner">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
            </div>
            <div>
              <h2 class="text-base font-bold text-white tracking-wide uppercase font-mono">
                MY CONNECTION INFORMATION
              </h2>
              <p class="text-xs text-slate-400">Actual live client network telemetry recorded in backend security logs</p>
            </div>
          </div>
          <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800 animate-pulse">
            <span class="w-2 h-2 rounded-full bg-emerald-400 inline-block"></span>
            <span>CONNECTION ONLINE</span>
          </span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
          <!-- Public IP -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Public IP Address</span>
            <div class="flex items-center justify-between mt-2">
              <span id="conn-ip-text" class="text-lg font-bold text-cyan-300 font-mono select-all">
                ${session.publicIp || 'IP ADDRESS: UNAVAILABLE'}
              </span>
              <button id="btn-copy-ip" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[11px] font-sans font-medium transition-all">
                Copy IP
              </button>
            </div>
          </div>

          <!-- Session ID -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Student Session ID</span>
            <div class="mt-2 text-sm font-bold text-slate-200 truncate select-all" title="${session.rawSessionId || ''}">
              ${session.sessionId || 'Pending...'}
            </div>
          </div>

          <!-- Browser / Agent -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Detected Browser</span>
            <div class="mt-2 text-sm font-bold text-slate-200 truncate">
              ${session.browser || 'Web Client'}
            </div>
          </div>

          <!-- Events Generated By Me -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Events Generated By Me</span>
            <div class="mt-2 flex items-baseline gap-2">
              <span class="text-xl font-bold text-cyan-400">${session.eventsGenerated || 0}</span>
              <span class="text-[11px] text-slate-500 font-sans">real attack records</span>
            </div>
          </div>

          <!-- Last Activity -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Last Activity</span>
            <div class="mt-2 text-xs font-mono text-slate-300">
              ${session.lastActivity ? new Date(session.lastActivity).toLocaleTimeString() : 'Just now'}
            </div>
          </div>

          <!-- Challenge Progress Quick Status -->
          <div class="bg-slate-950/80 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            <span class="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">Lab Progress</span>
            <div class="mt-2 flex items-center justify-between">
              <span class="text-sm font-bold text-emerald-400">${stats.completionPercentage || 0}% Completed</span>
              <span class="text-[11px] text-slate-400 font-sans">${stats.totalStagesCompleted || 0} / 6 Flags</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick KPI Counters -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div class="text-[11px] font-mono text-slate-400 uppercase">Total Challenges</div>
          <div class="text-2xl font-bold text-white mt-1">3</div>
          <div class="text-[11px] text-slate-500 mt-1 font-sans">SQLi • XSS • IDOR</div>
        </div>
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div class="text-[11px] font-mono text-slate-400 uppercase">Completed Challenges</div>
          <div class="text-2xl font-bold text-emerald-400 mt-1">${stats.fullyCompletedChallenges || 0}</div>
          <div class="text-[11px] text-emerald-500/80 mt-1 font-sans">${stats.totalStagesCompleted || 0} of 6 stages done</div>
        </div>
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div class="text-[11px] font-mono text-slate-400 uppercase">Total Events By Me</div>
          <div class="text-2xl font-bold text-cyan-400 mt-1">${session.eventsGenerated || 0}</div>
          <div class="text-[11px] text-cyan-500/80 mt-1 font-sans">Live backend records</div>
        </div>
        <div class="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div class="text-[11px] font-mono text-slate-400 uppercase">Critical / High Alerts</div>
          <div class="text-2xl font-bold text-rose-400 mt-1">${(session.metrics?.criticalAlerts || 0) + (session.metrics?.highAlerts || 0)}</div>
          <div class="text-[11px] text-rose-400/80 mt-1 font-sans">${session.metrics?.criticalAlerts || 0} Critical | ${session.metrics?.highAlerts || 0} High</div>
        </div>
      </div>

      <!-- Three Challenge Cards -->
      <div class="space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-base font-bold text-white tracking-tight font-mono uppercase">
            Interactive Penetration-Testing Challenges
          </h2>
          <span class="text-xs text-slate-400 font-sans">Each challenge awards 1 Attack Flag & 1 Investigation Flag</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <!-- Card 1: SQL Injection -->
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between hover:border-slate-700 transition-all shadow-xl">
            <div class="space-y-3">
              <div class="flex items-center justify-between">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                  EASY
                </span>
                <span class="text-xs font-mono ${progress.sqli?.is_fully_completed ? 'text-emerald-400 font-bold' : 'text-slate-400'}">
                  ${progress.sqli?.is_fully_completed ? '✓ COMPLETED' : (progress.sqli?.attack_completed ? '● IN PROGRESS' : '○ NOT STARTED')}
                </span>
              </div>
              <h3 class="text-base font-bold text-white">SQL Injection Authentication Bypass</h3>
              <p class="text-xs text-slate-400 leading-relaxed font-sans">
                Exploit an unparameterized SQL login form to bypass credential verification and access the internal enterprise administration dashboard.
              </p>
              <div class="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 space-y-1 text-[11px]">
                <div class="text-slate-500 font-mono uppercase text-[10px]">Learning Objective</div>
                <div class="text-slate-300">Understand how improperly concatenated SQL queries allow auth bypass and recognize SQLi IoCs in web logs.</div>
              </div>
            </div>
            <div class="pt-5 mt-4 border-t border-slate-800/80 flex items-center justify-between">
              <div class="text-[11px] font-mono text-slate-400">
                ${progress.sqli?.attack_completed ? 'Stage 1: Done' : 'Stage 1: Pending'}
              </div>
              <button class="btn-start-challenge px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-sm flex items-center gap-1.5" data-challenge="sqli">
                <span>Start Challenge</span>
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
              </button>
            </div>
          </div>

          <!-- Card 2: XSS -->
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between hover:border-slate-700 transition-all shadow-xl">
            <div class="space-y-3">
              <div class="flex items-center justify-between">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">
                  MEDIUM
                </span>
                <span class="text-xs font-mono ${progress.xss?.is_fully_completed ? 'text-emerald-400 font-bold' : 'text-slate-400'}">
                  ${progress.xss?.is_fully_completed ? '✓ COMPLETED' : (progress.xss?.attack_completed ? '● IN PROGRESS' : '○ NOT STARTED')}
                </span>
              </div>
              <h3 class="text-base font-bold text-white">Cross-Site Scripting (Reflected XSS)</h3>
              <p class="text-xs text-slate-400 leading-relaxed font-sans">
                Inject an executable JavaScript payload (<code class="text-amber-300 font-mono">&lt;script&gt;alert('2')&lt;/script&gt;</code>) into the search bar and observe execution in a sandboxed browser context.
              </p>
              <div class="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 space-y-1 text-[11px]">
                <div class="text-slate-500 font-mono uppercase text-[10px]">Learning Objective</div>
                <div class="text-slate-300">Understand reflected DOM script execution and identify URL percent-encoded script tags in SIEM telemetry.</div>
              </div>
            </div>
            <div class="pt-5 mt-4 border-t border-slate-800/80 flex items-center justify-between">
              <div class="text-[11px] font-mono text-slate-400">
                ${progress.xss?.attack_completed ? 'Stage 1: Done' : 'Stage 1: Pending'}
              </div>
              <button class="btn-start-challenge px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-sm flex items-center gap-1.5" data-challenge="xss">
                <span>Start Challenge</span>
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
              </button>
            </div>
          </div>

          <!-- Card 3: IDOR -->
          <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between hover:border-slate-700 transition-all shadow-xl">
            <div class="space-y-3">
              <div class="flex items-center justify-between">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">
                  MEDIUM
                </span>
                <span class="text-xs font-mono ${progress.idor?.is_fully_completed ? 'text-emerald-400 font-bold' : 'text-slate-400'}">
                  ${progress.idor?.is_fully_completed ? '✓ COMPLETED' : (progress.idor?.attack_completed ? '● IN PROGRESS' : '○ NOT STARTED')}
                </span>
              </div>
              <h3 class="text-base font-bold text-white">Insecure Direct Object Reference (IDOR)</h3>
              <p class="text-xs text-slate-400 leading-relaxed font-sans">
                Inspect user profile URLs, tamper with numeric resource identifiers, and access another employee's confidential profile without authorization.
              </p>
              <div class="bg-slate-950/80 p-3 rounded-lg border border-slate-800/80 space-y-1 text-[11px]">
                <div class="text-slate-500 font-mono uppercase text-[10px]">Learning Objective</div>
                <div class="text-slate-300">Discover broken object-level authorization (BOLA) and correlate unauthorized parameter tampering in access audit logs.</div>
              </div>
            </div>
            <div class="pt-5 mt-4 border-t border-slate-800/80 flex items-center justify-between">
              <div class="text-[11px] font-mono text-slate-400">
                ${progress.idor?.attack_completed ? 'Stage 1: Done' : 'Stage 1: Pending'}
              </div>
              <button class="btn-start-challenge px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-all shadow-sm flex items-center gap-1.5" data-challenge="idor">
                <span>Start Challenge</span>
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;

  // Bind Events
  document.getElementById('btn-hero-attack')?.addEventListener('click', () => navigateTo('attack-lab'));
  document.getElementById('btn-hero-soc')?.addEventListener('click', () => navigateTo('soc-dashboard'));

  document.querySelectorAll('.btn-start-challenge').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const challengeId = btn.getAttribute('data-challenge');
      navigateTo('attack-lab', { challengeId });
    });
  });

  document.getElementById('btn-copy-ip')?.addEventListener('click', () => {
    const ip = session.publicIp || '';
    if (ip && ip !== 'IP ADDRESS: UNAVAILABLE') {
      navigator.clipboard.writeText(ip);
      const copyBtn = document.getElementById('btn-copy-ip');
      if (copyBtn) {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => copyBtn.textContent = 'Copy IP', 2000);
      }
    }
  });
}
