/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Flag Validation & Challenge Progress
 */

import express from 'express';
import { db } from '../db/database.js';

export const flagsRouter = express.Router();

const MASTER_FLAGS = {
  sqli: {
    attack: 'BLITZ{sql_auth_bypass_success}',
    investigation: 'BLITZ{sql_ioc_7f92kx}',
    name: 'SQL Injection Authentication Bypass'
  },
  xss: {
    attack: 'BLITZ{xss_script_execution_success}',
    investigation: 'BLITZ{xss_ioc_4m82qp}',
    name: 'Cross-Site Scripting (Reflected XSS)'
  },
  idor: {
    attack: 'BLITZ{idor_unauthorized_access}',
    investigation: 'BLITZ{idor_ioc_9p31mz}',
    name: 'Insecure Direct Object Reference (IDOR)'
  }
};

// Submit a Flag
flagsRouter.post('/submit', (req, res) => {
  const { challenge_id, flag_type, flag } = req.body;
  const { sessionId } = req.studentSession;

  if (!challenge_id || !flag_type || !flag) {
    return res.status(400).json({
      success: false,
      message: 'Missing challenge_id, flag_type, or flag string in request.'
    });
  }

  const challenge = MASTER_FLAGS[challenge_id.toLowerCase()];
  if (!challenge) {
    return res.status(400).json({ success: false, message: 'Unknown challenge identifier.' });
  }

  const expectedFlag = challenge[flag_type.toLowerCase()];
  if (!expectedFlag) {
    return res.status(400).json({ success: false, message: "Invalid flag_type. Must be 'attack' or 'investigation'." });
  }

  const submittedClean = String(flag).trim();
  const isCorrect = submittedClean === expectedFlag;
  const now = new Date().toISOString();

  // Log submission history
  db.prepare(`
    INSERT INTO flag_submissions (session_id, challenge_id, flag_type, submitted_flag, is_correct, submitted_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, challenge_id, flag_type, submittedClean, isCorrect ? 1 : 0, now);

  if (!isCorrect) {
    return res.json({
      success: false,
      isCorrect: false,
      message: 'Incorrect Flag! Check your investigation evidence or verify the flag format.'
    });
  }

  // Update challenge progress in database
  if (flag_type.toLowerCase() === 'attack') {
    db.prepare(`
      UPDATE challenge_progress 
      SET attack_completed = 1, attack_completed_at = COALESCE(attack_completed_at, ?), attack_flag_submitted = ?
      WHERE session_id = ? AND challenge_id = ?
    `).run(now, submittedClean, sessionId, challenge_id);
  } else {
    db.prepare(`
      UPDATE challenge_progress 
      SET investigation_completed = 1, investigation_completed_at = COALESCE(investigation_completed_at, ?) , investigation_flag_submitted = ?
      WHERE session_id = ? AND challenge_id = ?
    `).run(now, submittedClean, sessionId, challenge_id);
  }

  // Check if both stages are now complete
  const progStmt = db.prepare(`
    SELECT attack_completed, investigation_completed 
    FROM challenge_progress 
    WHERE session_id = ? AND challenge_id = ?
  `);
  const currentProg = progStmt.get(sessionId, challenge_id);
  const isChallengeFullyComplete = currentProg?.attack_completed === 1 && currentProg?.investigation_completed === 1;

  res.json({
    success: true,
    isCorrect: true,
    challengeId: challenge_id,
    flagType: flag_type,
    isChallengeFullyComplete,
    message: isChallengeFullyComplete
      ? `Congratulations! You have completed BOTH stages of ${challenge.name}!`
      : `Correct Flag accepted for Stage: ${flag_type.toUpperCase()}! Complete the remaining stage to finalize this challenge.`
  });
});

// Retrieve Student Challenge Progress
flagsRouter.get('/progress', (req, res) => {
  const { sessionId } = req.studentSession;

  const rows = db.prepare(`
    SELECT 
      challenge_id, attack_completed, attack_completed_at, 
      investigation_completed, investigation_completed_at,
      attack_flag_submitted, investigation_flag_submitted
    FROM challenge_progress
    WHERE session_id = ?
  `).all(sessionId);

  const submissionStats = db.prepare(`
    SELECT 
      COUNT(*) as total_attempts,
      SUM(CASE WHEN is_correct = 1 THEN 1 ELSE 0 END) as correct_flags,
      SUM(CASE WHEN is_correct = 0 THEN 1 ELSE 0 END) as incorrect_attempts
    FROM flag_submissions
    WHERE session_id = ?
  `).get(sessionId) || { total_attempts: 0, correct_flags: 0, incorrect_attempts: 0 };

  const challenges = {
    sqli: {
      name: 'SQL Injection Authentication Bypass',
      attack_completed: false,
      investigation_completed: false,
      is_fully_completed: false
    },
    xss: {
      name: 'Cross-Site Scripting (Reflected XSS)',
      attack_completed: false,
      investigation_completed: false,
      is_fully_completed: false
    },
    idor: {
      name: 'Insecure Direct Object Reference (IDOR)',
      attack_completed: false,
      investigation_completed: false,
      is_fully_completed: false
    }
  };

  let totalStagesCompleted = 0;
  let fullyCompletedChallenges = 0;

  rows.forEach(r => {
    if (challenges[r.challenge_id]) {
      const c = challenges[r.challenge_id];
      c.attack_completed = !!r.attack_completed;
      c.attack_completed_at = r.attack_completed_at;
      c.investigation_completed = !!r.investigation_completed;
      c.investigation_completed_at = r.investigation_completed_at;
      c.is_fully_completed = c.attack_completed && c.investigation_completed;

      if (c.attack_completed) totalStagesCompleted++;
      if (c.investigation_completed) totalStagesCompleted++;
      if (c.is_fully_completed) fullyCompletedChallenges++;
    }
  });

  const completionPercentage = Math.round((totalStagesCompleted / 6) * 100);

  res.json({
    challenges,
    stats: {
      totalFlagsSubmitted: submissionStats.total_attempts,
      correctFlags: submissionStats.correct_flags || 0,
      incorrectAttempts: submissionStats.incorrect_attempts || 0,
      totalStagesCompleted,
      fullyCompletedChallenges,
      completionPercentage
    }
  });
});
