/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Express App Configuration
 */

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sessionMiddleware } from './middleware/session.js';
import { sessionRouter } from './routes/session.js';
import { challengesRouter } from './routes/challenges.js';
import { eventsRouter } from './routes/events.js';
import { flagsRouter } from './routes/flags.js';
import { iocRouter } from './routes/ioc.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, '..', 'public');

export const app = express();

// Trust reverse proxy headers (e.g. Nginx, Docker, Cloudflare) if configured
app.set('trust proxy', 1);

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Apply session and IP detection middleware across all routes
app.use(sessionMiddleware);

// API Routes
app.use('/api/session', sessionRouter);
app.use('/api/challenge', challengesRouter);
app.use('/api/events', eventsRouter);
app.use('/api/flags', flagsRouter);
app.use('/api/ioc', iocRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    session: req.studentSession.sessionId,
    detectedIp: req.studentSession.clientIp
  });
});

// Serve frontend static assets from public/
app.use(express.static(publicDir));

// Fallback route for SPA
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) {
    return res.sendFile(path.join(publicDir, 'index.html'));
  }
  next();
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[ServerError]', err);
  res.status(500).json({
    success: false,
    message: 'An unexpected server error occurred.',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});
