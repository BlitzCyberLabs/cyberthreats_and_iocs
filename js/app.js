/**
 * Main Application Orchestrator for SOC Lab
 * Manages views between the Target Web Application and SOC SIEM Console.
 */

import { store } from './store.js';
import { logEngine } from './log-engine.js';
import { targetApp } from './target-app.js';
import { socSiem } from './soc-siem.js';
import { sfx } from './utils.js';

class App {
  async init() {
    // 1. Initialize Log Engine & load baseline logs
    await logEngine.init();

    // 2. Initialize Target Web Application
    targetApp.init('target-app-container');

    // 3. Initialize SOC SIEM Console
    socSiem.init('siem-container');

    // 4. Bind Navigation
    this.bindNavigation();

    // 5. Subscribe to tab switches
    store.on('tabChange', (tab) => {
      this.switchTabUI(tab);
    });

    console.log("SOC Training Lab initialized successfully.");
  }

  bindNavigation() {
    const navBtns = document.querySelectorAll('.main-nav-btn');
    navBtns.forEach(btn => {
      btn.onclick = () => {
        const tab = btn.getAttribute('data-tab');
        sfx.playClick();
        store.setTab(tab);
      };
    });

    // Instructions Guide Modal
    const guideBtn = document.getElementById('btn-open-guide');
    const guideModal = document.getElementById('guide-modal');
    const guideClose = document.getElementById('btn-close-guide');

    if (guideBtn && guideModal) {
      guideBtn.onclick = () => {
        guideModal.classList.remove('hidden');
      };
    }

    if (guideClose && guideModal) {
      guideClose.onclick = () => {
        guideModal.classList.add('hidden');
      };
    }
  }

  switchTabUI(tab) {
    document.querySelectorAll('.tab-view-container').forEach(el => el.classList.add('hidden'));

    const activeEl = document.getElementById(`view-${tab}`);
    if (activeEl) activeEl.classList.remove('hidden');

    document.querySelectorAll('.main-nav-btn').forEach(btn => {
      const bTab = btn.getAttribute('data-tab');
      if (bTab === tab) {
        btn.className = "main-nav-btn px-4 py-2 rounded-lg text-xs font-semibold bg-emerald-600 text-white shadow-lg shadow-emerald-900/40 transition-all flex items-center gap-2";
      } else {
        btn.className = "main-nav-btn px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-all flex items-center gap-2";
      }
    });

    // If switching to SIEM, trigger chart redraw
    if (tab === 'siem') {
      socSiem.render();
    }
  }
}

export const app = new App();
window.addEventListener('DOMContentLoaded', () => {
  app.init();
});
