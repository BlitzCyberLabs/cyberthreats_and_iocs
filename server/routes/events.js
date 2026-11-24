/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Event Explorer & SOC Routes
 */

import express from 'express';
import { db } from '../db/database.js';
import { registerSSEClient } from '../services/event-broadcaster.js';

export const eventsRouter = express.Router();

// SSE Live Stream Endpoint
eventsRouter.get('/stream', (req, res) => {
  const { sessionId } = req.studentSession;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  // Send initial handshake
  res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'SSE Stream Active' })}\n\n`);

  registerSSEClient(sessionId, res);
});

// Event Explorer / SOC Events List API with filtering, search, pagination
eventsRouter.get('/', (req, res) => {
  const { sessionId } = req.studentSession;
  const {
    search = '',
    severity = '',
    category = '',
    source_ip = '',
    my_activity_only = 'false',
    page = 1,
    limit = 25,
    sort_by = 'timestamp',
    sort_dir = 'DESC'
  } = req.query;

  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(100, Math.max(5, parseInt(limit, 10) || 25));
  const offset = (pageNum - 1) * limitNum;

  // Build query filters
  const conditions = [];
  const params = [];

  // Session isolation: students see global synthetic events (session_id IS NULL) PLUS their own events (session_id = ?)
  // They NEVER see another student's real events!
  const isMyActivityOnly = my_activity_only === 'true' || my_activity_only === '1';

  if (isMyActivityOnly) {
    conditions.push('session_id = ? AND is_simulated = 0');
    params.push(sessionId);
  } else {
    conditions.push('(session_id IS NULL OR session_id = ?)');
    params.push(sessionId);
  }

  if (severity && severity !== 'ALL') {
    conditions.push('severity = ?');
    params.push(severity.toUpperCase());
  }

  if (category && category !== 'ALL') {
    conditions.push('attack_category = ?');
    params.push(category.toLowerCase());
  }

  if (source_ip) {
    conditions.push('source_ip LIKE ?');
    params.push(`%${source_ip}%`);
  }

  if (search) {
    conditions.push(`(
      id LIKE ? OR 
      event_type LIKE ? OR 
      description LIKE ? OR 
      endpoint LIKE ? OR 
      ioc_indicators LIKE ? OR
      source_ip LIKE ?
    )`);
    const s = `%${search}%`;
    params.push(s, s, s, s, s, s);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  // Safe sorting
  const validColumns = ['timestamp', 'severity', 'event_type', 'source_ip', 'attack_category'];
  const safeSortCol = validColumns.includes(sort_by) ? sort_by : 'timestamp';
  const safeSortDir = sort_dir.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

  // Count total matching
  const countSql = `SELECT COUNT(*) as total FROM events ${whereClause}`;
  const countStmt = db.prepare(countSql);
  const { total } = countStmt.get(...params);

  // Fetch paginated records (OMITTING investigation_flag in general list!)
  const selectSql = `
    SELECT 
      id, session_id, timestamp, source_ip, event_type, attack_category,
      severity, endpoint, method, user_agent, description, ioc_indicators,
      is_simulated,
      CASE WHEN investigation_flag IS NOT NULL THEN 1 ELSE 0 END as has_investigation_flag
    FROM events
    ${whereClause}
    ORDER BY ${safeSortCol} ${safeSortDir}
    LIMIT ? OFFSET ?
  `;

  const fetchStmt = db.prepare(selectSql);
  const rows = fetchStmt.all(...params, limitNum, offset);

  res.json({
    events: rows,
    pagination: {
      page: pageNum,
      limit: limitNum,
      total,
      totalPages: Math.ceil(total / limitNum)
    }
  });
});

// Single Event Details (Reveals Investigation Flag ONLY on detail view for student's own event!)
eventsRouter.get('/:id', (req, res) => {
  const { id } = req.params;
  const { sessionId } = req.studentSession;

  const eventStmt = db.prepare(`
    SELECT * FROM events 
    WHERE id = ? AND (session_id IS NULL OR session_id = ?)
  `);
  const event = eventStmt.get(id, sessionId);

  if (!event) {
    return res.status(404).json({ success: false, message: 'Security event not found or access denied.' });
  }

  // If this is a real student attack event with an investigation flag,
  // mark the investigation stage as ready / viewed
  if (event.investigation_flag && event.session_id === sessionId) {
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE challenge_progress 
      SET investigation_completed = 1, investigation_completed_at = COALESCE(investigation_completed_at, ?)
      WHERE session_id = ? AND challenge_id = ?
    `).run(now, sessionId, event.attack_category);
  }

  res.json({
    success: true,
    event
  });
});

// SOC Dashboard KPI Analytics & Charts Data
eventsRouter.get('/stats/summary', (req, res) => {
  const { sessionId } = req.studentSession;

  // Severity counts
  const severityStmt = db.prepare(`
    SELECT 
      severity, COUNT(*) as count
    FROM events
    WHERE (session_id IS NULL OR session_id = ?)
    GROUP BY severity
  `);
  const severityRows = severityStmt.all(sessionId);

  const severities = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };
  severityRows.forEach(r => {
    if (severities[r.severity] !== undefined) severities[r.severity] = r.count;
  });

  // Total counts: actual vs simulated
  const countsStmt = db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN is_simulated = 0 AND session_id = ? THEN 1 ELSE 0 END) as actual_student_events,
      SUM(CASE WHEN is_simulated = 1 THEN 1 ELSE 0 END) as simulated_events
    FROM events
    WHERE (session_id IS NULL OR session_id = ?)
  `);
  const totalCounts = countsStmt.get(sessionId, sessionId) || { total: 0, actual_student_events: 0, simulated_events: 0 };

  // Category breakdown
  const categoryStmt = db.prepare(`
    SELECT attack_category, COUNT(*) as count
    FROM events
    WHERE (session_id IS NULL OR session_id = ?)
    GROUP BY attack_category
    ORDER BY count DESC
  `);
  const categoryRows = categoryStmt.all(sessionId);

  // Latest event timestamp
  const latestStmt = db.prepare(`
    SELECT timestamp FROM events
    WHERE (session_id IS NULL OR session_id = ?)
    ORDER BY timestamp DESC LIMIT 1
  `);
  const latestEvent = latestStmt.get(sessionId);

  res.json({
    totalEvents: totalCounts.total,
    actualStudentEvents: totalCounts.actual_student_events || 0,
    simulatedEvents: totalCounts.simulated_events || 0,
    latestEventTime: latestEvent?.timestamp || new Date().toISOString(),
    severities,
    categories: categoryRows
  });
});
