/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Server Entrypoint
 */

import { app } from './app.js';
import { initDatabase } from './db/database.js';
import { seedSyntheticEvents } from './db/seed-data.js';

const PORT = process.env.PORT || 3000;

// Initialize database schema and seed data
console.log('------------------------------------------------------------');
console.log('   BLITZ CYBER THREATS & IOC INVESTIGATION LAB (v2.0)       ');
console.log('   Enterprise SOC Training & Threat Hunting Platform       ');
console.log('------------------------------------------------------------');

initDatabase();
seedSyntheticEvents();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Server] Lab server running successfully on port ${PORT}`);
  console.log(`[Server] Local URL: http://localhost:${PORT}`);
  console.log(`[Server] Session isolation & SSE live stream active.`);
  console.log('------------------------------------------------------------');
});
