/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Real-Time SSE Broadcaster
 * Pushes real backend security events to active student dashboards in real-time.
 */

import { db } from '../db/database.js';

// Map of sessionId -> Set of active SSE res objects
const activeClients = new Map();

export function registerSSEClient(sessionId, res) {
  if (!activeClients.has(sessionId)) {
    activeClients.set(sessionId, new Set());
  }
  activeClients.get(sessionId).add(res);

  res.on('close', () => {
    const clients = activeClients.get(sessionId);
    if (clients) {
      clients.delete(res);
      if (clients.size === 0) {
        activeClients.delete(sessionId);
      }
    }
  });
}

/**
 * Persists an actual student attack event to the database and broadcasts to the student's dashboard
 */
export function recordAndBroadcastAttackEvent({
  sessionId,
  sourceIp,
  eventType,
  attackCategory,
  severity,
  endpoint,
  method,
  userAgent,
  description,
  iocIndicators,
  investigationFlag,
  payloadDetails
}) {
  const eventId = `EVT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;
  const timestamp = new Date().toISOString();

  const insertStmt = db.prepare(`
    INSERT INTO events (
      id, session_id, timestamp, source_ip, event_type, attack_category,
      severity, endpoint, method, user_agent, description, ioc_indicators,
      is_simulated, investigation_flag, payload_details
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `);

  insertStmt.run(
    eventId,
    sessionId,
    timestamp,
    sourceIp,
    eventType,
    attackCategory,
    severity,
    endpoint,
    method,
    userAgent || 'Unknown',
    description,
    iocIndicators,
    investigationFlag,
    typeof payloadDetails === 'object' ? JSON.stringify(payloadDetails) : payloadDetails
  );

  const eventPayload = {
    id: eventId,
    timestamp,
    source_ip: sourceIp,
    event_type: eventType,
    attack_category: attackCategory,
    severity,
    endpoint,
    method,
    description,
    ioc_indicators: iocIndicators,
    is_simulated: 0,
    has_investigation_flag: !!investigationFlag
    // Note: investigation_flag is purposely NOT included in the broadcast stream!
    // It is only revealed when the student explicitly opens the event's detail drawer!
  };

  const clients = activeClients.get(sessionId);
  if (clients && clients.size > 0) {
    const sseData = `data: ${JSON.stringify({ type: 'NEW_ATTACK_EVENT', event: eventPayload })}\n\n`;
    for (const client of clients) {
      try {
        client.write(sseData);
      } catch (e) {
        console.error('Failed to write to SSE client:', e);
      }
    }
  }

  return eventPayload;
}
