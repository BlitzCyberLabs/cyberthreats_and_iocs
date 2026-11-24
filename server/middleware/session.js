/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Session & IP Middleware
 * Automatically provisions isolated student sessions and detects actual incoming IP.
 */

import { randomUUID } from 'node:crypto';
import { db } from '../db/database.js';

const COOKIE_NAME = 'blitz_session_id';

export function getClientIp(req) {
  // If behind a trusted reverse proxy, check standard forwarded headers
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded && typeof forwarded === 'string') {
    const parts = forwarded.split(',').map(s => s.trim());
    if (parts.length > 0 && parts[0]) {
      return cleanIp(parts[0]);
    }
  }

  const realIp = req.headers['x-real-ip'];
  if (realIp && typeof realIp === 'string') {
    return cleanIp(realIp.trim());
  }

  const socketIp = req.socket?.remoteAddress;
  if (socketIp) {
    return cleanIp(socketIp);
  }

  return 'IP ADDRESS: UNAVAILABLE';
}

function cleanIp(ip) {
  if (!ip) return 'IP ADDRESS: UNAVAILABLE';
  // Normalize IPv6 mapped IPv4 address (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    return '127.0.0.1';
  }
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  return ip;
}

export function sessionMiddleware(req, res, next) {
  let sessionId = req.cookies?.[COOKIE_NAME];
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown Browser';
  const now = new Date().toISOString();

  let existingSession = null;

  if (sessionId) {
    const sessionStmt = db.prepare('SELECT * FROM sessions WHERE session_id = ?');
    existingSession = sessionStmt.get(sessionId);
  }

  if (!existingSession) {
    // Generate new secure session ID
    sessionId = `sess_${randomUUID().replace(/-/g, '')}`;

    const insertSession = db.prepare(`
      INSERT INTO sessions (session_id, client_ip, user_agent, created_at, last_activity)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertSession.run(sessionId, clientIp, userAgent, now, now);

    // Initialize challenge progress for this student
    const insertProgress = db.prepare(`
      INSERT OR IGNORE INTO challenge_progress (session_id, challenge_id, attack_completed, investigation_completed)
      VALUES (?, ?, 0, 0)
    `);
    insertProgress.run(sessionId, 'sqli');
    insertProgress.run(sessionId, 'xss');
    insertProgress.run(sessionId, 'idor');

    // Set secure HTTP-only cookie
    res.cookie(COOKIE_NAME, sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    req.studentSession = {
      sessionId,
      clientIp,
      userAgent,
      createdAt: now,
      lastActivity: now,
      isNew: true
    };
  } else {
    // Update last activity and client IP if changed
    const updateStmt = db.prepare(`
      UPDATE sessions 
      SET last_activity = ?, client_ip = ?, user_agent = ?
      WHERE session_id = ?
    `);
    updateStmt.run(now, clientIp, userAgent, sessionId);

    req.studentSession = {
      sessionId,
      clientIp,
      userAgent,
      createdAt: existingSession.created_at,
      lastActivity: now,
      isNew: false
    };
  }

  next();
}
