/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Database Engine
 * Powered by Node.js built-in SQLite (DatabaseSync)
 */

import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const dbPath = path.join(dataDir, 'blitz_lab.db');
export const db = new DatabaseSync(dbPath);

// Enable WAL mode for high performance concurrency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

// Initialize tables
export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      client_ip TEXT NOT NULL,
      user_agent TEXT,
      created_at TEXT NOT NULL,
      last_activity TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      session_id TEXT, -- NULL for global synthetic events, or student session_id for real events
      timestamp TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      event_type TEXT NOT NULL,
      attack_category TEXT NOT NULL,
      severity TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      user_agent TEXT,
      description TEXT NOT NULL,
      ioc_indicators TEXT,
      is_simulated INTEGER NOT NULL DEFAULT 1,
      investigation_flag TEXT,
      payload_details TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_category ON events(attack_category);
    CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

    CREATE TABLE IF NOT EXISTS challenge_progress (
      session_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      attack_completed INTEGER NOT NULL DEFAULT 0,
      attack_completed_at TEXT,
      investigation_completed INTEGER NOT NULL DEFAULT 0,
      investigation_completed_at TEXT,
      attack_flag_submitted TEXT,
      investigation_flag_submitted TEXT,
      PRIMARY KEY (session_id, challenge_id)
    );

    CREATE TABLE IF NOT EXISTS flag_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      challenge_id TEXT NOT NULL,
      flag_type TEXT NOT NULL,
      submitted_flag TEXT NOT NULL,
      is_correct INTEGER NOT NULL,
      submitted_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS dummy_users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      department TEXT NOT NULL,
      email TEXT,
      bio TEXT
    );
  `);

  seedDummyUsers();
}

function seedDummyUsers() {
  const countStmt = db.prepare('SELECT COUNT(*) as count FROM dummy_users');
  const result = countStmt.get();
  if (result.count === 0) {
    const insertStmt = db.prepare(`
      INSERT INTO dummy_users (id, username, password, name, role, department, email, bio)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Master dummy admin for SQL Injection challenge
    insertStmt.run(
      1,
      'admin',
      'ComplexAdminPassword!2026_NeverGuessed',
      'Root System Administrator',
      'Global Administrator',
      'Security Operations',
      'admin@blitzcorp.internal',
      'Enterprise Infrastructure Superuser account'
    );

    // Dummy user 1001 for IDOR challenge (initially authorized profile)
    insertStmt.run(
      1001,
      'student_alpha',
      'AlphaPass#992',
      'Alex Morgan',
      'Junior Security Analyst',
      'Cybersecurity',
      'alex.morgan@blitzcorp.internal',
      'Authorized student profile ID 1001. Specializes in defensive telemetry and SIEM monitoring.'
    );

    // Dummy user 1002 for IDOR challenge (unauthorized target profile)
    insertStmt.run(
      1002,
      'student_beta',
      'BetaVault$7714',
      'Jordan Smith',
      'Senior Network Engineer',
      'Network Security',
      'jordan.smith@blitzcorp.internal',
      'Confidential profile ID 1002. Holds administrative credentials for core network gateways and routers.'
    );

    // Additional dummy records
    insertStmt.run(
      1003,
      'sec_lead',
      'LeadSecret#4412',
      'Elena Vance',
      'Incident Response Lead',
      'Threat Intelligence',
      'elena.vance@blitzcorp.internal',
      'Tier 3 incident escalation coordinator.'
    );
  }
}
