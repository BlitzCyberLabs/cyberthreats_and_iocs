/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Challenge Progress View
 * Flag submission system and dual-stage progress tracking for SQLi, XSS, and IDOR.
 */

import { api } from '../api.js';

export function renderChallengeProgress(container, state, navigateTo) {
  async function loadAndRender() {
    try {
      const data = await api.getProgress();
      render(data.challenges || {}, data.stats || {});
    } catch (err) {
      container.innerHTML = `<div class="p-8 text-center text-red-400 font-mono text-sm">Error loading progress: ${err.message}</div>`;
    }
  }

  function render(challenges, stats) {
    container.innerHTML = `
      <div class="space-y-6">
        <!-- Progress Header -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 uppercase tracking-widest">
                  LAB EVALUATION SYSTEM
                </span>
                <span class="text-xs text-slate-400 font-mono">Flag Validation &amp; Stage Verification</span>
              </div>
              <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1">
                Challenge Progress &amp; Flag Submission
              </h1>
              <p class="text-xs text-slate-400 mt-1">
                Each challenge requires completing two distinct stages: executing the attack (Attack Flag) and investigating your generated security event in the SOC dashboard (Investigation Flag).
              </p>
            </div>

            <!-- Overall Progress Percentage Ring / Box -->
            <div class="bg-slate-950 px-6 py-4 rounded-xl border border-slate-800 text-center shrink-0">
              <span class="text-[10px] font-mono text-slate-500 uppercase block">Overall Completion</span>
              <div class="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400 mt-1">
                ${stats.completionPercentage || 0}%
              </div>
              <span class="text-[11px] font-mono text-slate-400">${stats.totalStagesCompleted || 0} of 6 Stages Validated</span>
            </div>
          </div>

          <!-- Progress Bar -->
          <div class="w-full bg-slate-950 h-2.5 rounded-full overflow-hidden border border-slate-800">
            <div class="bg-gradient-to-r from-blue-500 to-emerald-400 h-full transition-all duration-500" style="width: ${stats.completionPercentage || 0}%;"></div>
          </div>

          <!-- Summary Metric Counters -->
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
            <div class="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
              <span class="text-slate-500 uppercase text-[10px]">Fully Completed</span>
              <div class="text-base font-bold text-emerald-400 mt-0.5">${stats.fullyCompletedChallenges || 0} / 3 Challenges</div>
            </div>
            <div class="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
              <span class="text-slate-500 uppercase text-[10px]">Total Submissions</span>
              <div class="text-base font-bold text-slate-200 mt-0.5">${stats.totalFlagsSubmitted || 0} Attempts</div>
            </div>
            <div class="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
              <span class="text-slate-500 uppercase text-[10px]">Correct Flags</span>
              <div class="text-base font-bold text-emerald-400 mt-0.5">${stats.correctFlags || 0} Validated</div>
            </div>
            <div class="bg-slate-950/80 p-3 rounded-xl border border-slate-800">
              <span class="text-slate-500 uppercase text-[10px]">Incorrect Attempts</span>
              <div class="text-base font-bold text-rose-400 mt-0.5">${stats.incorrectAttempts || 0} Failed</div>
            </div>
          </div>
        </div>

        <!-- The 3 Challenge Verification Cards -->
        <div class="space-y-6">
          ${renderChallengeValidationCard('sqli', '1. SQL Injection Authentication Bypass', challenges.sqli || {})}
          ${renderChallengeValidationCard('xss', '2. Cross-Site Scripting (Reflected XSS)', challenges.xss || {})}
          ${renderChallengeValidationCard('idor', '3. Insecure Direct Object Reference (IDOR)', challenges.idor || {})}
        </div>
      </div>
    `;

    bindFormEvents();
  }

  function renderChallengeValidationCard(challengeId, title, cState) {
    const isCompleted = cState.is_fully_completed;

    return `
      <div class="bg-slate-900 border ${isCompleted ? 'border-emerald-600/60 shadow-emerald-950/20' : 'border-slate-800'} rounded-2xl p-6 shadow-xl space-y-5">
        <div class="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl ${isCompleted ? 'bg-emerald-950 text-emerald-400 border border-emerald-700' : 'bg-blue-950 text-blue-400 border border-blue-800'} flex items-center justify-center font-bold text-sm">
              ${isCompleted ? '✓' : '●'}
            </div>
            <div>
              <h3 class="text-base font-bold text-white">${title}</h3>
              <p class="text-xs text-slate-400 font-mono">Status: ${isCompleted ? '<span class="text-emerald-400 font-bold">CHALLENGE FULLY COMPLETED</span>' : '<span class="text-amber-400 font-bold">PENDING VERIFICATION</span>'}</p>
            </div>
          </div>
          <span class="px-3 py-1 rounded-full text-xs font-mono font-bold ${isCompleted ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-950 text-slate-400 border border-slate-800'}">
            ${isCompleted ? '100% COMPLETE' : (cState.attack_completed || cState.investigation_completed ? '50% COMPLETE' : '0% COMPLETE')}
          </span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <!-- Stage 1: Attack Flag -->
          <div class="bg-slate-950/80 border ${cState.attack_completed ? 'border-emerald-800/80' : 'border-slate-800'} rounded-xl p-5 flex flex-col justify-between space-y-4">
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">STAGE 1: ATTACK EXECUTION</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${cState.attack_completed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-900 text-slate-500'}">
                  ${cState.attack_completed ? '✓ STAGE COMPLETED' : 'PENDING EXPLOIT'}
                </span>
              </div>
              <p class="text-xs text-slate-300 font-sans">
                Execute the exploit in the Attack Lab to trigger the vulnerability and retrieve the Attack Flag.
              </p>
              ${cState.attack_completed_at ? `
                <div class="text-[10px] font-mono text-emerald-500">Completed at: ${new Date(cState.attack_completed_at).toLocaleString()}</div>
              ` : ''}
            </div>

            <form class="flag-submit-form space-y-2 font-mono text-xs" data-challenge="${challengeId}" data-type="attack">
              <div class="flex gap-2">
                <input 
                  type="text" 
                  name="flag" 
                  placeholder="BLITZ{...}" 
                  class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  ${cState.attack_completed ? 'disabled value="[Flag Validated]"' : ''}
                  required
                />
                <button 
                  type="submit" 
                  class="px-4 py-2 rounded-lg ${cState.attack_completed ? 'bg-emerald-900/40 text-emerald-500 cursor-not-allowed border border-emerald-800' : 'bg-blue-600 hover:bg-blue-500 text-white font-bold'} transition-all text-xs font-sans"
                  ${cState.attack_completed ? 'disabled' : ''}
                >
                  ${cState.attack_completed ? 'Verified' : 'Submit'}
                </button>
              </div>
              <div class="form-feedback hidden text-[11px] p-2 rounded font-mono"></div>
            </form>
          </div>

          <!-- Stage 2: Investigation Flag -->
          <div class="bg-slate-950/80 border ${cState.investigation_completed ? 'border-emerald-800/80' : 'border-slate-800'} rounded-xl p-5 flex flex-col justify-between space-y-4">
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider">STAGE 2: SOC INVESTIGATION</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold ${cState.investigation_completed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-900 text-slate-500'}">
                  ${cState.investigation_completed ? '✓ STAGE COMPLETED' : 'PENDING SOC TRIAGE'}
                </span>
              </div>
              <p class="text-xs text-slate-300 font-sans">
                Open the SOC Dashboard or Event Explorer, locate the event generated from your IP, click Inspect to reveal the Investigation Flag.
              </p>
              ${cState.investigation_completed_at ? `
                <div class="text-[10px] font-mono text-emerald-500">Completed at: ${new Date(cState.investigation_completed_at).toLocaleString()}</div>
              ` : ''}
            </div>

            <form class="flag-submit-form space-y-2 font-mono text-xs" data-challenge="${challengeId}" data-type="investigation">
              <div class="flex gap-2">
                <input 
                  type="text" 
                  name="flag" 
                  placeholder="BLITZ{...}" 
                  class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-xs"
                  ${cState.investigation_completed ? 'disabled value="[Flag Validated]"' : ''}
                  required
                />
                <button 
                  type="submit" 
                  class="px-4 py-2 rounded-lg ${cState.investigation_completed ? 'bg-emerald-900/40 text-emerald-500 cursor-not-allowed border border-emerald-800' : 'bg-blue-600 hover:bg-blue-500 text-white font-bold'} transition-all text-xs font-sans"
                  ${cState.investigation_completed ? 'disabled' : ''}
                >
                  ${cState.investigation_completed ? 'Verified' : 'Submit'}
                </button>
              </div>
              <div class="form-feedback hidden text-[11px] p-2 rounded font-mono"></div>
            </form>
          </div>
        </div>
      </div>
    `;
  }

  function bindFormEvents() {
    container.querySelectorAll('.flag-submit-form').forEach(form => {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const challengeId = form.getAttribute('data-challenge');
        const flagType = form.getAttribute('data-type');
        const flagInput = form.querySelector('input[name="flag"]');
        const feedback = form.querySelector('.form-feedback');
        const flagVal = flagInput.value.trim();

        if (!flagVal) return;

        try {
          const res = await api.submitFlag(challengeId, flagType, flagVal);
          feedback.classList.remove('hidden');

          if (res.success && res.isCorrect) {
            feedback.className = "form-feedback text-[11px] p-2.5 rounded font-mono bg-emerald-950 text-emerald-300 border border-emerald-700 block";
            feedback.innerHTML = `✓ ${res.message}`;
            setTimeout(() => {
              loadAndRender();
            }, 1200);
          } else {
            feedback.className = "form-feedback text-[11px] p-2.5 rounded font-mono bg-red-950 text-red-300 border border-red-800 block";
            feedback.textContent = `✕ ${res.message}`;
          }
        } catch (err) {
          feedback.classList.remove('hidden');
          feedback.className = "form-feedback text-[11px] p-2.5 rounded font-mono bg-red-950 text-red-300 border border-red-800 block";
          feedback.textContent = `Error: ${err.message}`;
        }
      });
    });
  }

  loadAndRender();
}
