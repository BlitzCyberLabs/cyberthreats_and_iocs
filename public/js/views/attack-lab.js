/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Attack Lab View
 * Interactive penetration testing interfaces for SQLi, XSS, and IDOR.
 */

import { api } from '../api.js';

export function renderAttackLab(container, state, navigateTo, params = {}) {
  let activeChallenge = params.challengeId || 'sqli';

  function render() {
    container.innerHTML = `
      <div class="space-y-6">
        <!-- Attack Lab Header -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-wrap items-center justify-between gap-4">
          <div>
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800 uppercase tracking-widest">
                OFFENSIVE LAB RANGE
              </span>
              <span class="text-xs text-slate-400 font-mono">Controlled Vulnerability Sandbox</span>
            </div>
            <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1">
              Interactive Attack Environment
            </h1>
            <p class="text-xs text-slate-400">
              Execute controlled penetration testing attacks. Each exploit generates a real backend security event recorded in your individual SOC dashboard.
            </p>
          </div>

          <!-- Challenge Selector Tabs -->
          <div class="flex items-center bg-slate-950 p-1.5 rounded-xl border border-slate-800 gap-1 font-mono text-xs">
            <button class="challenge-tab px-3.5 py-1.5 rounded-lg font-medium transition-all ${activeChallenge === 'sqli' ? 'bg-blue-600 text-white font-bold shadow-sm' : 'text-slate-400 hover:text-white'}" data-tab="sqli">
              1. SQL Injection
            </button>
            <button class="challenge-tab px-3.5 py-1.5 rounded-lg font-medium transition-all ${activeChallenge === 'xss' ? 'bg-blue-600 text-white font-bold shadow-sm' : 'text-slate-400 hover:text-white'}" data-tab="xss">
              2. Reflected XSS
            </button>
            <button class="challenge-tab px-3.5 py-1.5 rounded-lg font-medium transition-all ${activeChallenge === 'idor' ? 'bg-blue-600 text-white font-bold shadow-sm' : 'text-slate-400 hover:text-white'}" data-tab="idor">
              3. IDOR
            </button>
          </div>
        </div>

        <!-- Active Challenge Workspace -->
        <div id="challenge-workspace" class="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-2xl">
          ${renderChallengeContent(activeChallenge)}
        </div>
      </div>
    `;

    bindTabEvents();
    bindChallengeHandlers(activeChallenge);
  }

  function bindTabEvents() {
    container.querySelectorAll('.challenge-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        activeChallenge = tab.getAttribute('data-tab');
        render();
      });
    });
  }

  function renderChallengeContent(challengeId) {
    if (challengeId === 'sqli') {
      return `
        <div class="space-y-6 max-w-4xl mx-auto">
          <div class="border-b border-slate-800 pb-4">
            <div class="flex items-center justify-between">
              <h2 class="text-lg font-bold text-white font-mono flex items-center gap-2">
                <span>🛡️ Challenge 1:</span>
                <span>SQL Injection Authentication Bypass</span>
              </h2>
              <span class="px-2.5 py-0.5 rounded text-[11px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">EASY</span>
            </div>
            <p class="text-xs text-slate-400 mt-1">
              Target: <code class="text-cyan-300 font-mono">POST /api/challenge/sqli/login</code> • Bypass database authentication to gain administrative access.
            </p>
          </div>

          <!-- Vulnerable Login Box -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-6 max-w-md mx-auto space-y-4 shadow-lg">
            <div class="text-center space-y-1 mb-2">
              <div class="w-10 h-10 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30 flex items-center justify-center mx-auto">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
              </div>
              <h3 class="text-sm font-bold text-white">Enterprise Single Sign-On (SSO)</h3>
              <p class="text-[11px] text-slate-500">Sign in to access the confidential Administrative Control Panel.</p>
            </div>

            <form id="form-sqli-login" class="space-y-3 font-mono text-xs">
              <div>
                <label class="block text-slate-400 mb-1">Corporate ID / Username</label>
                <input type="text" id="sqli-user" placeholder="e.g. admin' --" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500" required />
              </div>
              <div>
                <label class="block text-slate-400 mb-1">Password</label>
                <input type="password" id="sqli-pass" placeholder="Enter password or payload" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:border-blue-500" />
              </div>
              <button type="submit" class="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-2.5 rounded-lg transition-all shadow-md font-sans">
                Authenticate
              </button>
            </form>

            <div id="sqli-feedback" class="hidden text-xs p-3 rounded-lg font-mono"></div>
          </div>

          <!-- Example Payloads Reference Helper -->
          <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-2">
            <span class="text-slate-400 font-bold block text-[11px] uppercase tracking-wider">💡 Common Authentication Bypass Payloads:</span>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] text-amber-300">
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">admin' --</span>
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">admin' #</span>
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">admin' or '1'='1</span>
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">or 1=1--</span>
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">1' or '1' = '1</span>
              <span class="bg-slate-900 p-1.5 rounded border border-slate-800 cursor-pointer hover:bg-slate-800 select-all">admin') or ('1'='1</span>
            </div>
          </div>
        </div>
      `;
    }

    if (challengeId === 'xss') {
      return `
        <div class="space-y-6 max-w-4xl mx-auto">
          <div class="border-b border-slate-800 pb-4">
            <div class="flex items-center justify-between">
              <h2 class="text-lg font-bold text-white font-mono flex items-center gap-2">
                <span>🛡️ Challenge 2:</span>
                <span>Cross-Site Scripting (Reflected XSS)</span>
              </h2>
              <span class="px-2.5 py-0.5 rounded text-[11px] font-mono bg-amber-950 text-amber-400 border border-amber-800 font-bold">MEDIUM</span>
            </div>
            <p class="text-xs text-slate-400 mt-1">
              Target: <code class="text-cyan-300 font-mono">GET /api/challenge/xss/sandbox?q=</code> • Execute JavaScript in the client browser context.
            </p>
          </div>

          <!-- Sandboxed Iframe Container -->
          <div class="space-y-3">
            <div class="flex items-center justify-between text-xs text-slate-400 font-mono">
              <span>Isolated Challenge Frame (Security Sandboxed)</span>
              <span class="text-emerald-400">Sandbox Isolation Active</span>
            </div>
            <div class="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-xl h-64">
              <iframe id="xss-sandbox-frame" src="/api/challenge/xss/sandbox" class="w-full h-full border-0"></iframe>
            </div>
          </div>

          <div id="xss-feedback" class="hidden text-xs p-4 rounded-xl font-mono"></div>

          <!-- Payload Guide Card -->
          <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-2">
            <span class="text-slate-400 font-bold block text-[11px] uppercase tracking-wider">🎯 Required Attack Objective:</span>
            <p class="text-slate-300 font-sans text-xs">
              Inject the following exact payload into the search input inside the sandbox frame above:
            </p>
            <div class="bg-slate-900 p-2.5 rounded border border-slate-800 text-amber-300 font-mono font-bold select-all inline-block">
              &lt;script&gt;alert('2')&lt;/script&gt;
            </div>
            <p class="text-[11px] text-slate-400 font-sans mt-1">
              The payload will reflect into the DOM, execute in the isolated browser context, and trigger an alert displaying <strong class="text-cyan-300 font-mono">2</strong>, validating the exploit.
            </p>
          </div>
        </div>
      `;
    }

    if (challengeId === 'idor') {
      return `
        <div class="space-y-6 max-w-4xl mx-auto">
          <div class="border-b border-slate-800 pb-4">
            <div class="flex items-center justify-between">
              <h2 class="text-lg font-bold text-white font-mono flex items-center gap-2">
                <span>🛡️ Challenge 3:</span>
                <span>Insecure Direct Object Reference (IDOR)</span>
              </h2>
              <span class="px-2.5 py-0.5 rounded text-[11px] font-mono bg-amber-950 text-amber-400 border border-amber-800 font-bold">MEDIUM</span>
            </div>
            <p class="text-xs text-slate-400 mt-1">
              Target: <code class="text-cyan-300 font-mono">GET /api/challenge/idor/profile/:id</code> • Modify the resource ID to access an unauthorized profile.
            </p>
          </div>

          <!-- Profile URL Address Bar Simulator -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-4">
            <div class="flex items-center gap-2 font-mono text-xs bg-slate-900 p-2 rounded-lg border border-slate-800">
              <span class="text-slate-500 select-none">https://blitzcorp.internal/idor/profile/</span>
              <input type="number" id="idor-input-id" value="1001" class="w-24 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-cyan-300 font-bold text-xs focus:outline-none focus:border-cyan-500" />
              <button id="btn-idor-fetch" class="ml-auto px-4 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold font-sans text-xs transition-all">
                Fetch Profile
              </button>
            </div>

            <div id="idor-profile-display" class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
              <!-- Dynamically populated profile card -->
              <div class="animate-pulse text-slate-500 font-mono text-xs">Loading initial profile 1001...</div>
            </div>
          </div>

          <div id="idor-feedback" class="hidden text-xs p-4 rounded-xl font-mono"></div>

          <!-- Challenge Clue Card -->
          <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 font-mono text-xs space-y-2">
            <span class="text-slate-400 font-bold block text-[11px] uppercase tracking-wider">🎯 IDOR Attack Objective:</span>
            <p class="text-slate-300 font-sans text-xs">
              Your authorized employee profile is User ID <strong class="text-cyan-300 font-mono">1001</strong> (Alex Morgan). 
              A confidential network administrator account exists at User ID <strong class="text-amber-300 font-mono">1002</strong> (Jordan Smith). 
              Tamper with the numeric identifier in the URL route above to exploit broken object-level authorization and exfiltrate Jordan Smith’s profile data.
            </p>
          </div>
        </div>
      `;
    }
  }

  function bindChallengeHandlers(challengeId) {
    if (challengeId === 'sqli') {
      const form = document.getElementById('form-sqli-login');
      const uInput = document.getElementById('sqli-user');
      const pInput = document.getElementById('sqli-pass');
      const fbBox = document.getElementById('sqli-feedback');

      form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = uInput.value.trim();
        const password = pInput.value.trim();

        try {
          const res = await api.sqliLogin(username, password);
          if (res.success) {
            fbBox.className = "text-xs p-5 rounded-xl font-mono bg-emerald-950/90 text-emerald-300 border border-emerald-600 block space-y-3";
            fbBox.innerHTML = `
              <div class="flex items-center gap-2 font-bold text-sm text-emerald-400">
                <span>✓ ${res.message}</span>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                <div class="text-slate-400 text-[11px]">Logged in as: <strong>${res.account.name}</strong> (${res.account.role})</div>
                <div class="text-slate-400 text-[11px]">Department: ${res.account.department}</div>
              </div>
              <div class="bg-slate-950 p-3 rounded-lg border border-emerald-700/60 flex items-center justify-between">
                <div>
                  <span class="text-slate-400 text-[10px] block">ATTACK COMPLETION FLAG:</span>
                  <span class="text-emerald-400 font-bold text-sm select-all">${res.attackFlag}</span>
                </div>
                <button class="btn-copy-flag px-3 py-1 rounded bg-emerald-900 hover:bg-emerald-800 text-emerald-200 text-xs font-sans" data-flag="${res.attackFlag}">
                  Copy Flag
                </button>
              </div>
              <div class="text-[11px] text-cyan-300 font-sans pt-1">
                📌 <strong>Next Step:</strong> Go to the <strong>SOC Dashboard</strong> or <strong>Event Explorer</strong> to investigate the SQLi event logged from your IP and uncover the separate <strong>Investigation Flag</strong>!
              </div>
            `;

            fbBox.querySelector('.btn-copy-flag')?.addEventListener('click', () => {
              navigator.clipboard.writeText(res.attackFlag);
              alert('Attack Flag copied to clipboard! Submit it in Challenge Progress.');
            });
          } else {
            fbBox.className = "text-xs p-3 rounded-lg font-mono bg-red-950 text-red-300 border border-red-800 block";
            fbBox.textContent = `✕ ${res.message}`;
          }
        } catch (err) {
          fbBox.className = "text-xs p-3 rounded-lg font-mono bg-red-950 text-red-300 border border-red-800 block";
          fbBox.textContent = `Error executing request: ${err.message}`;
        }
      });
    }

    if (challengeId === 'xss') {
      const fbBox = document.getElementById('xss-feedback');

      // Listen for window message from sandboxed iframe
      const messageListener = async (e) => {
        if (e.data && e.data.type === 'XSS_SUCCESS') {
          try {
            const res = await api.verifyXss(e.data.payload);
            if (res.success) {
              fbBox.className = "text-xs p-5 rounded-xl font-mono bg-emerald-950/90 text-emerald-300 border border-emerald-600 block space-y-3";
              fbBox.innerHTML = `
                <div class="flex items-center gap-2 font-bold text-sm text-emerald-400">
                  <span>✓ Script Execution Confirmed!</span>
                </div>
                <p class="text-slate-300 font-sans text-xs">${res.message}</p>
                <div class="bg-slate-950 p-3 rounded-lg border border-emerald-700/60 flex items-center justify-between">
                  <div>
                    <span class="text-slate-400 text-[10px] block">ATTACK COMPLETION FLAG:</span>
                    <span class="text-emerald-400 font-bold text-sm select-all">${res.attackFlag}</span>
                  </div>
                  <button class="btn-copy-flag px-3 py-1 rounded bg-emerald-900 hover:bg-emerald-800 text-emerald-200 text-xs font-sans" data-flag="${res.attackFlag}">
                    Copy Flag
                  </button>
                </div>
                <div class="text-[11px] text-cyan-300 font-sans pt-1">
                  📌 <strong>Next Step:</strong> Open the <strong>SOC Dashboard</strong> or <strong>Event Explorer</strong> to inspect the Cross-Site Scripting security event and discover the <strong>Investigation Flag</strong>.
                </div>
              `;

              fbBox.querySelector('.btn-copy-flag')?.addEventListener('click', () => {
                navigator.clipboard.writeText(res.attackFlag);
                alert('Attack Flag copied to clipboard! Submit it in Challenge Progress.');
              });
            }
          } catch (err) {
            console.error('Error verifying XSS:', err);
          }
        }
      };

      window.addEventListener('message', messageListener, { once: false });
    }

    if (challengeId === 'idor') {
      const idInput = document.getElementById('idor-input-id');
      const fetchBtn = document.getElementById('btn-idor-fetch');
      const displayArea = document.getElementById('idor-profile-display');
      const fbBox = document.getElementById('idor-feedback');

      async function loadProfile(id) {
        try {
          const res = await api.getIdorProfile(id);
          if (res.success && res.profile) {
            const p = res.profile;
            displayArea.innerHTML = `
              <div class="flex items-start justify-between">
                <div class="flex items-center gap-3">
                  <div class="w-12 h-12 rounded-xl ${res.isUnauthorizedAccess ? 'bg-amber-600/20 text-amber-400 border border-amber-500/30' : 'bg-blue-600/20 text-blue-400 border border-blue-500/30'} flex items-center justify-center font-bold text-base">
                    ${p.name.split(' ').map(n=>n[0]).join('')}
                  </div>
                  <div>
                    <h4 class="text-base font-bold text-white">${p.name}</h4>
                    <p class="text-xs text-slate-400 font-mono">@${p.username} • User ID: ${p.id}</p>
                  </div>
                </div>
                <span class="px-2.5 py-1 rounded text-xs font-mono font-bold ${res.isUnauthorizedAccess ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'}">
                  ${res.isUnauthorizedAccess ? 'UNAUTHORIZED TARGET ACCESS' : 'AUTHORIZED SESSION USER'}
                </span>
              </div>

              <div class="grid grid-cols-2 gap-3 pt-3 border-t border-slate-800 text-xs font-mono">
                <div>
                  <span class="text-slate-500 text-[10px] uppercase">Department</span>
                  <div class="text-slate-200 mt-0.5">${p.department}</div>
                </div>
                <div>
                  <span class="text-slate-500 text-[10px] uppercase">Job Role</span>
                  <div class="text-slate-200 mt-0.5">${p.role}</div>
                </div>
                <div>
                  <span class="text-slate-500 text-[10px] uppercase">Email Address</span>
                  <div class="text-slate-200 mt-0.5">${p.email || 'N/A'}</div>
                </div>
                <div>
                  <span class="text-slate-500 text-[10px] uppercase">Access Clearance</span>
                  <div class="text-slate-200 mt-0.5">${res.isUnauthorizedAccess ? 'CRITICAL - ROOT NETWORK' : 'STANDARD - ANALYST'}</div>
                </div>
              </div>

              <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs text-slate-400 font-sans">
                <strong>Profile Dossier:</strong> ${p.bio || 'No confidential notes on record.'}
              </div>
            `;

            if (res.isUnauthorizedAccess && res.attackFlag) {
              fbBox.className = "text-xs p-5 rounded-xl font-mono bg-emerald-950/90 text-emerald-300 border border-emerald-600 block space-y-3 mt-4";
              fbBox.innerHTML = `
                <div class="flex items-center gap-2 font-bold text-sm text-emerald-400">
                  <span>✓ IDOR Vulnerability Exploited!</span>
                </div>
                <p class="text-slate-300 font-sans text-xs">${res.message}</p>
                <div class="bg-slate-950 p-3 rounded-lg border border-emerald-700/60 flex items-center justify-between">
                  <div>
                    <span class="text-slate-400 text-[10px] block">ATTACK COMPLETION FLAG:</span>
                    <span class="text-emerald-400 font-bold text-sm select-all">${res.attackFlag}</span>
                  </div>
                  <button class="btn-copy-flag px-3 py-1 rounded bg-emerald-900 hover:bg-emerald-800 text-emerald-200 text-xs font-sans" data-flag="${res.attackFlag}">
                    Copy Flag
                  </button>
                </div>
                <div class="text-[11px] text-cyan-300 font-sans pt-1">
                  📌 <strong>Next Step:</strong> Switch to the <strong>SOC Dashboard</strong> or <strong>Event Explorer</strong> to investigate the generated CRITICAL Unauthorized Object Access event and find the <strong>Investigation Flag</strong>.
                </div>
              `;

              fbBox.querySelector('.btn-copy-flag')?.addEventListener('click', () => {
                navigator.clipboard.writeText(res.attackFlag);
                alert('Attack Flag copied to clipboard! Submit it in Challenge Progress.');
              });
            } else {
              fbBox.className = "hidden";
            }
          }
        } catch (err) {
          displayArea.innerHTML = `<div class="text-red-400 font-mono text-xs">Error loading profile: ${err.message}</div>`;
        }
      }

      // Initial load of authorized profile 1001
      loadProfile('1001');

      fetchBtn?.addEventListener('click', () => {
        const id = idInput.value.trim();
        if (id) loadProfile(id);
      });
    }
  }

  render();
}
