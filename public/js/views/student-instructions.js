/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Student Instructions View
 */

export function renderStudentInstructions(container, state, navigateTo) {
  container.innerHTML = `
    <div class="space-y-6 max-w-5xl mx-auto">
      <!-- Instructions Header -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div class="flex items-center gap-2">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800 uppercase tracking-widest">
              OFFICIAL LAB GUIDE
            </span>
            <span class="text-xs text-slate-400 font-mono">Documentation &amp; Assessment Resources</span>
          </div>
          <h1 class="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1">
            Student Field Manual &amp; Investigation Guidelines
          </h1>
          <p class="text-xs text-slate-400 mt-1">
            Read this manual carefully before beginning exercises. Learn how to correlate offensive activity with real-time defensive telemetry.
          </p>
        </div>

        <!-- Downloadable Documents Section -->
        <div class="flex flex-col sm:flex-row gap-3 shrink-0">
          <a href="/documents/BLITZ_Cyber_Threats_IOC_Investigation_Questionnaire.docx" download class="px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs font-mono transition-all shadow-md flex items-center justify-center gap-2">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            <span>Student Questionnaire (.docx)</span>
          </a>
          <a href="/documents/BLITZ_Cyber_Threats_Instructor_Answer_Key.docx" download class="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs font-mono transition-all flex items-center justify-center gap-2">
            <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
            <span>Instructor Key (.docx)</span>
          </a>
        </div>
      </div>

      <!-- Core Instructions Accordion / Cards -->
      <div class="space-y-6 text-xs leading-relaxed text-slate-300 font-sans">
        
        <!-- Section 1: Lab Architecture & Workflow -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
          <div class="flex items-center gap-2 font-mono text-sm font-bold text-cyan-400">
            <span>01.</span>
            <span>Two-Stage Training Workflow: Attack &amp; Investigation</span>
          </div>
          <p>
            Unlike traditional Jeopardy-style CTF competitions, BLITZ Lab teaches end-to-end security skills: you first execute a controlled penetration testing attack, then shift into the role of a SOC Analyst to triage, investigate, and analyze the resulting telemetry in your SIEM log monitor.
          </p>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 font-mono text-[11px]">
            <div class="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span class="text-rose-400 font-bold block mb-1 uppercase">Stage 1: Attack Execution</span>
              Execute the vulnerability exploit in the <strong>Attack Lab</strong>. When successful, the application confirms the exploit and provides an <strong>Attack Flag</strong> (formatted as <code class="text-emerald-400">BLITZ{...}</code>).
            </div>
            <div class="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span class="text-cyan-400 font-bold block mb-1 uppercase">Stage 2: SOC Investigation</span>
              Open the <strong>SOC Dashboard</strong> or <strong>Event Explorer</strong>. Locate the event generated from your public IP, click <strong>Inspect</strong> to view the forensic details, and discover the embedded <strong>Investigation Flag</strong>.
            </div>
          </div>
        </div>

        <!-- Section 2: Identifying Your Real Telemetry -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
          <div class="flex items-center gap-2 font-mono text-sm font-bold text-cyan-400">
            <span>02.</span>
            <span>How to Identify Real Student Events vs. Simulated Baseline Logs</span>
          </div>
          <p>
            To mirror a realistic enterprise SIEM monitoring thousands of daily events, the SOC console contains a pre-seeded baseline of 550+ synthetic security events.
          </p>
          <div class="space-y-2 font-mono text-[11px]">
            <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span class="text-cyan-300 font-bold block">Your Real Student Events:</span>
                <span class="text-slate-400">Tagged with <span class="text-cyan-400 font-bold">● MY ACTIVITY</span> and recorded with your actual detected incoming public connection IP.</span>
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-700">is_simulated: 0</span>
            </div>
            <div class="bg-slate-950 p-3 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span class="text-slate-400 font-bold block">Synthetic Background Telemetry:</span>
                <span class="text-slate-500">Tagged with <span class="text-slate-400">SIMULATED TRAINING DATA</span> using RFC 5737 documentation test IP pools (<code class="text-slate-400">192.0.2.0/24</code>, <code class="text-slate-400">198.51.100.0/24</code>, <code class="text-slate-400">203.0.113.0/24</code>).</span>
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] bg-slate-900 text-slate-500 border border-slate-800">is_simulated: 1</span>
            </div>
          </div>
          <p class="text-slate-400 pt-1">
            💡 <em>Tip: Enable the <strong>SHOW MY ACTIVITY ONLY</strong> toggle in the SOC Dashboard or Event Explorer to instantly filter out all synthetic events and focus solely on your own offensive actions.</em>
          </p>
        </div>

        <!-- Section 3: Challenge Walkthroughs & Objectives -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div class="flex items-center gap-2 font-mono text-sm font-bold text-cyan-400">
            <span>03.</span>
            <span>Challenge Objectives &amp; Technical Clues</span>
          </div>

          <div class="space-y-3 font-mono text-[11px]">
            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-white font-bold text-xs">CHALLENGE 1: SQL INJECTION AUTHENTICATION BYPASS</span>
                <span class="text-emerald-400 font-bold">EASY</span>
              </div>
              <p class="text-slate-300 font-sans">
                The corporate login form improperly concatenates user input directly into dynamic SQL queries. Inject boolean tautology expressions (such as <code class="text-amber-300 select-all">admin' --</code> or <code class="text-amber-300 select-all">' OR '1'='1</code>) to force the authentication query to evaluate to true.
              </p>
            </div>

            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-white font-bold text-xs">CHALLENGE 2: CROSS-SITE SCRIPTING (REFLECTED XSS)</span>
                <span class="text-amber-400 font-bold">MEDIUM</span>
              </div>
              <p class="text-slate-300 font-sans">
                The search query parameter is reflected back into the document without context-aware HTML entity encoding. In the sandboxed frame, inject the payload <code class="text-amber-300 select-all">&lt;script&gt;alert('2')&lt;/script&gt;</code>. When the browser executes the script and displays an alert with the value 2, the attack is verified.
              </p>
            </div>

            <div class="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-white font-bold text-xs">CHALLENGE 3: INSECURE DIRECT OBJECT REFERENCE (IDOR)</span>
                <span class="text-amber-400 font-bold">MEDIUM</span>
              </div>
              <p class="text-slate-300 font-sans">
                The application relies on client-supplied numeric identifiers in the URL route to fetch user profiles without validating whether the current session has authorization to access that object. Modify the user ID parameter from your authorized ID (<code class="text-cyan-300">1001</code>) to the confidential administrator record (<code class="text-amber-300">1002</code>).
              </p>
            </div>
          </div>
        </div>

        <!-- Section 4: Submitting Flags -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-3">
          <div class="flex items-center gap-2 font-mono text-sm font-bold text-cyan-400">
            <span>04.</span>
            <span>Submitting Flags &amp; Finalizing Evaluation</span>
          </div>
          <p>
            Navigate to the <strong>Challenge Progress</strong> tab. For each challenge, enter the Attack Flag obtained from the Attack Lab into Stage 1, and enter the Investigation Flag retrieved from the event details drawer into Stage 2. Once both flags are submitted and validated, the challenge will be marked as 100% COMPLETED.
          </p>
        </div>

      </div>
    </div>
  `;
}
