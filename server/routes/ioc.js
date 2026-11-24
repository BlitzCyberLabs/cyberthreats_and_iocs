/**
 * BLITZ Cyber Threats & IOC Investigation Lab - IOC Investigation & Correlation Routes
 */

import express from 'express';
import { db } from '../db/database.js';

export const iocRouter = express.Router();

iocRouter.get('/indicators', (req, res) => {
  const { sessionId } = req.studentSession;

  // Retrieve distinct IOC indicators from events belonging to this student session + simulated baseline
  const rows = db.prepare(`
    SELECT 
      id, event_type, attack_category, severity, source_ip, endpoint, method,
      timestamp, ioc_indicators, is_simulated,
      CASE WHEN session_id = ? THEN 1 ELSE 0 END as is_my_activity
    FROM events
    WHERE (session_id IS NULL OR session_id = ?)
    ORDER BY is_my_activity DESC, timestamp DESC
    LIMIT 200
  `).all(sessionId, sessionId);

  // Group into curated IOC dossiers
  const dossiers = [
    {
      id: 'IOC-DOSSIER-SQLI',
      title: 'SQL Injection Authentication Bypass Indicators',
      attackCategory: 'sqli',
      severity: 'HIGH',
      description: 'SQL queries manipulating WHERE clause logic via boolean tautologies or comment truncations to gain administrative sessions.',
      suspiciousPayloads: ["admin' --", "' OR '1'='1", "or 1=1--", "admin' #", "admin') or ('1'='1"],
      monitoredEndpoints: ['/api/challenge/sqli/login'],
      investigationGuide: 'Examine POST login events with HTTP 302 redirection where the request payload contains single quotes and boolean operators. Click the event to uncover the investigation flag.',
      pivotQuery: 'category=sqli'
    },
    {
      id: 'IOC-DOSSIER-XSS',
      title: 'Reflected Cross-Site Scripting (XSS) Script Execution',
      attackCategory: 'xss',
      severity: 'HIGH',
      description: 'Arbitrary JavaScript execution inside client browsers due to unsanitized HTML entity reflection in search query parameters.',
      suspiciousPayloads: ["<script>alert('2')</script>", "%3Cscript%3Ealert('2')%3C/script%3E"],
      monitoredEndpoints: ['/api/challenge/xss/search'],
      investigationGuide: 'Filter by category "xss". Look for GET requests to the search endpoint containing script tags or event handlers. Open the event details to retrieve the investigation flag.',
      pivotQuery: 'category=xss'
    },
    {
      id: 'IOC-DOSSIER-IDOR',
      title: 'Broken Object Level Authorization (IDOR)',
      attackCategory: 'idor',
      severity: 'CRITICAL',
      description: 'Unauthorized horizontal access to confidential records by altering numeric user identifiers in URL route parameters without server-side permission checks.',
      suspiciousPayloads: ['/api/challenge/idor/profile/1002'],
      monitoredEndpoints: ['/api/challenge/idor/profile/:id'],
      investigationGuide: 'Filter for CRITICAL events under category "idor". Identify unauthorized access to user ID 1002 (Jordan Smith) and open the event details to reveal the investigation flag.',
      pivotQuery: 'category=idor'
    }
  ];

  res.json({
    dossiers,
    recentIocEvents: rows.slice(0, 50)
  });
});
