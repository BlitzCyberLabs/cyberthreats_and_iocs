/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Isolated Vulnerable Challenge Routes
 * Implements SQL Injection, Cross-Site Scripting, and IDOR training endpoints.
 */

import express from 'express';
import { db } from '../db/database.js';
import { recordAndBroadcastAttackEvent } from '../services/event-broadcaster.js';

export const challengesRouter = express.Router();

// ==========================================
// CHALLENGE 1: SQL INJECTION AUTHENTICATION BYPASS
// ==========================================
challengesRouter.post('/sqli/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const { sessionId, clientIp, userAgent } = req.studentSession;

  const rawUser = String(username).trim();
  const rawPass = String(password).trim();

  // Normalize smart quotes and test for SQLi bypass patterns
  const normInput = `${rawUser} ${rawPass}`.replace(/[’‘`]/g, "'").replace(/[“”]/g, '"').toLowerCase();
  
  // Tautologies, comments, and boolean bypasses
  const tautologyPattern = /\b(or|and)\b\s*(\(?\s*['"]?[^'"\s=]+['"]?\s*=\s*['"]?[^'"\s=]+|\d+\s*=\s*\d+)/i;
  const commentPattern = /(--|#|\/\*)/;
  const quoteWithComment = /['"]\s*(--|#|\/\*|\bor\b|\band\b)/i;
  const booleanProbe = /\bor\b\s+\d+\s*=\s*\d+/i;
  const adminComment = /admin['"\)]*\s*(--|#|\/\*)/i;

  const isSqliBypass = 
    tautologyPattern.test(normInput) || 
    (commentPattern.test(normInput) && (normInput.includes('admin') || normInput.includes("'") || normInput.includes('or'))) ||
    quoteWithComment.test(normInput) ||
    booleanProbe.test(normInput) ||
    adminComment.test(normInput);

  // Normal valid credentials for testing
  const isNormalAdmin = rawUser === 'admin' && rawPass === 'ComplexAdminPassword!2026_NeverGuessed';

  if (isSqliBypass || isNormalAdmin) {
    // Record real backend security event
    const attackFlag = 'BLITZ{sql_auth_bypass_success}';
    const investigationFlag = 'BLITZ{sql_ioc_7f92kx}';

    recordAndBroadcastAttackEvent({
      sessionId,
      sourceIp: clientIp,
      eventType: 'SQL Injection Attempt',
      attackCategory: 'sqli',
      severity: 'HIGH',
      endpoint: '/api/challenge/sqli/login',
      method: 'POST',
      userAgent,
      description: 'SQL injection authentication bypass detected. User input bypassed credential verification via SQL tautology/comment injection.',
      iocIndicators: `method:POST, status:302, uri:/api/challenge/sqli/login, pattern:${rawUser.substring(0, 30)}`,
      investigationFlag,
      payloadDetails: {
        username: rawUser,
        password: rawPass.length > 0 ? '********' : '',
        query_executed: `SELECT * FROM users WHERE username = '${rawUser}' AND password = '...'`,
        bypass_logic: 'Tautology / Comment Truncation (Evaluated to TRUE)'
      }
    });

    // Mark attack stage as completed in challenge progress
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE challenge_progress 
      SET attack_completed = 1, attack_completed_at = COALESCE(attack_completed_at, ?)
      WHERE session_id = ? AND challenge_id = 'sqli'
    `).run(now, sessionId);

    return res.json({
      success: true,
      message: 'Authentication Successful: Bypassed database authentication logic!',
      account: {
        id: 1,
        username: 'admin',
        name: 'Root System Administrator',
        role: 'Global Administrator',
        department: 'Security Operations'
      },
      attackFlag,
      nextStep: 'Switch to the SOC Dashboard or Event Explorer to investigate the SQL Injection event you just generated and uncover the Investigation Flag.'
    });
  }

  // Failed login
  return res.status(401).json({
    success: false,
    message: 'Invalid username or password. Authentication failed.'
  });
});

// ==========================================
// CHALLENGE 2: CROSS-SITE SCRIPTING (XSS)
// ==========================================

// Search API (simulates backend search response)
challengesRouter.get('/xss/search', (req, res) => {
  const query = req.query.q || '';
  const items = [
    { id: 'KB-101', title: 'Network Perimeter Firewall Rules', category: 'Infrastructure' },
    { id: 'KB-102', title: 'SIEM Log Forwarding Configuration Guide', category: 'Security' },
    { id: 'KB-103', title: 'Database Encryption Key Rotation Procedures', category: 'Compliance' }
  ];

  const filtered = query
    ? items.filter(item => item.title.toLowerCase().includes(String(query).toLowerCase()))
    : items;

  res.json({
    query,
    count: filtered.length,
    results: filtered
  });
});

// Isolated Sandboxed Search Page (Runs in isolated iframe sandbox)
challengesRouter.get('/xss/sandbox', (req, res) => {
  const query = req.query.q || '';

  // Render isolated sandboxed HTML page with reflected input
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Vulnerable Enterprise Search Sandbox</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; font-size: 13px; margin: 0; }
    .search-box { display: flex; gap: 8px; margin-bottom: 16px; }
    input { flex: 1; background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px 12px; color: #fff; font-size: 12px; }
    button { background: #0284c7; color: white; border: none; border-radius: 6px; padding: 8px 16px; font-weight: bold; cursor: pointer; }
    .results { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-top: 12px; }
    .item { padding: 8px 0; border-bottom: 1px solid #334155; }
    .badge { background: #0369a1; color: #bae6fd; font-size: 10px; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <form method="GET" action="/api/challenge/xss/sandbox" class="search-box">
    <input type="text" name="q" value="${query.replace(/"/g, '&quot;')}" placeholder="Search internal knowledgebase...">
    <button type="submit">Search</button>
  </form>

  <div class="results">
    <div>Results for: <strong id="reflected-output"></strong></div>
    <div style="margin-top: 10px; font-size: 11px; color: #94a3b8;">
      Found 3 articles matching your query parameters.
    </div>
  </div>

  <script>
    // Overriding alert to detect the required challenge payload alert('2')
    const originalAlert = window.alert;
    window.alert = function(msg) {
      if (String(msg) === '2') {
        window.parent.postMessage({ type: 'XSS_SUCCESS', payload: "<script>alert('2')<\/script>" }, '*');
      }
      return originalAlert(msg);
    };

    // Reflect the query into the DOM to allow execution of injected script tags
    const rawQuery = ${JSON.stringify(query)};
    if (rawQuery) {
      document.getElementById('reflected-output').innerHTML = rawQuery;
      
      // Specifically execute scripts that innerHTML ignores by specification
      const scripts = document.getElementById('reflected-output').getElementsByTagName('script');
      for (let s of Array.from(scripts)) {
        const newScript = document.createElement('script');
        newScript.text = s.text;
        document.body.appendChild(newScript);
      }
    }
  </script>
</body>
</html>`);
});

// Verification endpoint called upon confirmed execution of alert('2')
challengesRouter.post('/xss/verify', (req, res) => {
  const { sessionId, clientIp, userAgent } = req.studentSession;
  const attackFlag = 'BLITZ{xss_script_execution_success}';
  const investigationFlag = 'BLITZ{xss_ioc_4m82qp}';

  recordAndBroadcastAttackEvent({
    sessionId,
    sourceIp: clientIp,
    eventType: 'Cross-Site Scripting',
    attackCategory: 'xss',
    severity: 'HIGH',
    endpoint: '/api/challenge/xss/search',
    method: 'GET',
    userAgent,
    description: 'Reflected XSS payload submitted and successfully executed in browser context.',
    iocIndicators: `tag:<script>, execution:alert('2'), uri:/api/challenge/xss/search?q=%3Cscript%3Ealert('2')%3C/script%3E`,
    investigationFlag,
    payloadDetails: {
      injected_code: "<script>alert('2')</script>",
      execution_context: "Sandboxed DOM (reflected via query parameter 'q')",
      alert_value: "2"
    }
  });

  const now = new Date().toISOString();
  db.prepare(`
    UPDATE challenge_progress 
    SET attack_completed = 1, attack_completed_at = COALESCE(attack_completed_at, ?)
    WHERE session_id = ? AND challenge_id = 'xss'
  `).run(now, sessionId);

  res.json({
    success: true,
    message: 'XSS Execution Verified! The payload executed inside the browser security context.',
    attackFlag,
    nextStep: 'Navigate to the SOC Dashboard or Event Explorer to inspect the generated XSS security event and find the Investigation Flag.'
  });
});

// ==========================================
// CHALLENGE 3: INSECURE DIRECT OBJECT REFERENCE (IDOR)
// ==========================================
challengesRouter.get('/idor/profile/:id', (req, res) => {
  const { id } = req.params;
  const { sessionId, clientIp, userAgent } = req.studentSession;

  const numericId = parseInt(id, 10);
  if (isNaN(numericId)) {
    return res.status(400).json({ success: false, message: 'Invalid profile ID parameter.' });
  }

  const userStmt = db.prepare('SELECT id, username, name, role, department, email, bio FROM dummy_users WHERE id = ?');
  const profile = userStmt.get(numericId);

  if (!profile) {
    return res.status(404).json({ success: false, message: 'User profile not found.' });
  }

  // ID 1001 is the student's authorized profile
  if (numericId === 1001) {
    return res.json({
      success: true,
      profile,
      isAuthorized: true,
      message: 'Viewing your authorized user profile (Alex Morgan - ID 1001).'
    });
  }

  // ID 1002 is the target unauthorized profile (Jordan Smith)
  if (numericId === 1002) {
    const attackFlag = 'BLITZ{idor_unauthorized_access}';
    const investigationFlag = 'BLITZ{idor_ioc_9p31mz}';

    recordAndBroadcastAttackEvent({
      sessionId,
      sourceIp: clientIp,
      eventType: 'Unauthorized Object Access',
      attackCategory: 'idor',
      severity: 'CRITICAL',
      endpoint: '/api/challenge/idor/profile/1002',
      method: 'GET',
      userAgent,
      description: 'Student accessed a second dummy user profile (ID 1002: Jordan Smith) by modifying the resource identifier.',
      iocIndicators: `object_id:1002, authorized_scope:1001, horizontal_privilege_bypass`,
      investigationFlag,
      payloadDetails: {
        authorized_user_id: 1001,
        requested_user_id: 1002,
        compromised_account: 'Jordan Smith (Senior Network Engineer)',
        violation: 'Broken Object Level Authorization (BOLA / IDOR)'
      }
    });

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE challenge_progress 
      SET attack_completed = 1, attack_completed_at = COALESCE(attack_completed_at, ?)
      WHERE session_id = ? AND challenge_id = 'idor'
    `).run(now, sessionId);

    return res.json({
      success: true,
      profile,
      isUnauthorizedAccess: true,
      attackFlag,
      message: 'IDOR Vulnerability Exploited! Successfully accessed Jordan Smith’s confidential profile.',
      nextStep: 'Open the SOC Dashboard or Event Explorer to inspect the CRITICAL Unauthorized Object Access event and find the Investigation Flag.'
    });
  }

  // Any other profile
  res.json({
    success: true,
    profile,
    isAuthorized: false,
    message: 'Profile retrieved.'
  });
});
