/**
 * SOC SIEM Detection Engine & Signature Rules
 * Inspects HTTP request fields (Method, URI, Query Params, Body, User-Agent)
 * for known Indicators of Compromise (IoCs) across SQLi, XSS, and Brute Force.
 */

import { decodePayloadSafely } from './utils.js';

export const DETECTION_RULES = [
  {
    id: "RULE-SEC-001",
    name: "SQL Injection - UNION / Data Exfiltration Signature",
    category: "sqli",
    severity: "CRITICAL",
    description: "Detects UNION SELECT statements or stacked exfiltration queries in URL parameters or request bodies.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      const unionPattern = /\bunion\s+(all\s+)?select\b/i;
      const schemaPattern = /\binformation_schema\b/i;

      if (unionPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (UNION-Based)",
          reason: "UNION SELECT statement identified. Attacker is attempting to merge query results to extract unauthorized database records.",
          mitigation: "Use Parameterized Queries / Prepared Statements and strictly enforce type validation."
        };
      }

      if (schemaPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Schema Reconnaissance)",
          reason: "Access to information_schema detected. Attacker is enumerating database tables and columns.",
          mitigation: "Restrict database user permissions and disable system metadata tables."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-002",
    name: "SQL Injection - Authentication Bypass / Tautology Probe",
    category: "sqli",
    severity: "CRITICAL",
    description: "Detects SQL boolean tautologies (' OR '1'='1, OR 1=1), comment delimiters (-- , /* */, #), or unhandled syntax error probes.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const rawDecoded = decodePayloadSafely(target);
      const decoded = rawDecoded.replace(/[’‘`]/g, "'").replace(/[“”]/g, '"').toLowerCase();

      const tautologyPattern = /\b(or|and)\b\s*(\(?\s*['"]?[^'"\s=]+['"]?\s*=\s*['"]?[^'"\s=]+|\d+\s*=\s*\d+)/i;
      const commentPattern = /(--|\/\*|#|%23)/i;
      const booleanProbe = /\bor\b\s+\d+\s*=\s*\d+/i;
      const adminComment = /admin['"\)]*\s*(--|#|\/\*)/i;

      if (tautologyPattern.test(decoded) || booleanProbe.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Authentication Bypass / Tautology)",
          reason: "Boolean tautology expression (' OR '1'='1, or 1=1) detected in request payload. Used to bypass login authentication logic.",
          mitigation: "Bind all query parameters using prepared statements (e.g. PDO in PHP, PreparedStatement in Java)."
        };
      }

      if (commentPattern.test(decoded) && (/admin|select|where|login|or|and/i.test(decoded) || adminComment.test(decoded))) {
        return {
          matched: true,
          type: "SQL Injection (Comment Truncation)",
          reason: "SQL comment delimiter sequence (-- or /* */ or #) attempting to truncate server SQL query logic.",
          mitigation: "Use parameterized queries and reject unescaped query delimiter syntax."
        };
      }

      if (log.status === 500 && (decoded.includes("'") || decoded.includes('"'))) {
        return {
          matched: true,
          type: "SQL Injection (Error-Based Syntax Probe)",
          reason: "HTTP 500 unhandled database exception triggered by unescaped quotation mark probe in parameter.",
          mitigation: "Implement robust error handling that masks database error details from clients."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-003",
    name: "Cross-Site Scripting (XSS) - Script Tag or Event Handler",
    category: "xss",
    severity: "HIGH",
    description: "Detects HTML tag injection (<script>, <iframe>, <svg>), JavaScript pseudoprotocols (javascript:), or event handler hooks (onerror=, onload=) intended to execute arbitrary client-side code.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      const scriptTagPattern = /<\s*script\b[^>]*>/i;
      const eventHandlerPattern = /\bon\w+\s*=\s*['"]?[^'">\s]+/i;
      const jsProtoPattern = /javascript\s*:/i;
      const dangerousTags = /<\s*(iframe|svg|img|object|embed|body|link)\b[^>]*\b(onload|onerror|src)\s*=/i;
      const cookieStealer = /document\.cookie|window\.location|eval\s*\(/i;

      if (scriptTagPattern.test(decoded)) {
        return {
          matched: true,
          type: "Cross-Site Scripting (Script Tag Injection)",
          reason: "Raw <script> tag detected in payload. Attacker is injecting client-side JavaScript.",
          mitigation: "Apply context-aware HTML entity encoding on output and enforce a strict Content Security Policy (CSP)."
        };
      }

      if (eventHandlerPattern.test(decoded) || dangerousTags.test(decoded)) {
        return {
          matched: true,
          type: "Cross-Site Scripting (Event Handler / Polyglot)",
          reason: "HTML element with inline event handler (e.g. <img src=x onerror=...>) detected.",
          mitigation: "Sanitize user inputs with a trusted sanitizer (DOMPurify) and strip dangerous attributes."
        };
      }

      if (cookieStealer.test(decoded) && (/<|%3c|on/i.test(target))) {
        return {
          matched: true,
          type: "Cross-Site Scripting (Cookie / Credential Theft)",
          reason: "Payload references document.cookie within an injection context.",
          mitigation: "Set HttpOnly and SameSite flags on all sensitive session cookies."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-004",
    name: "Authentication Brute Force / High-Frequency Login Failures",
    category: "brute_force",
    severity: "HIGH",
    description: "Detects bursts of HTTP 401 Unauthorized status responses targeting login endpoints (/auth/login), or sudden credential compromise transitions (401 -> 302).",
    check: (log, contextLogs = []) => {
      const isLoginEndpoint = log.uri && (log.uri.includes('/login') || log.uri.includes('/auth'));

      if (isLoginEndpoint) {
        if (log.status === 401) {
          const recentAttempts = contextLogs.filter(l => 
            l.client_ip === log.client_ip && 
            (l.uri && (l.uri.includes('/login') || l.uri.includes('/auth'))) && 
            l.status === 401 &&
            Math.abs(new Date(l.timestamp) - new Date(log.timestamp)) < 120000
          );

          if (recentAttempts.length >= 2) {
            return {
              matched: true,
              type: "Authentication Brute Force (High Frequency)",
              reason: `Multiple consecutive failed authentication attempts (${recentAttempts.length} within 2 mins) from IP ${log.client_ip}.`,
              mitigation: "Enforce account lockout thresholds, progressive rate-limiting, and Multi-Factor Authentication (MFA)."
            };
          }
        }

        // Check for sudden 302/200 following consecutive 401s (Compromise!)
        if ((log.status === 200 || log.status === 302) && log.method === 'POST') {
          const precedingFailures = contextLogs.filter(l => 
            l.client_ip === log.client_ip && 
            (l.uri && (l.uri.includes('/login') || l.uri.includes('/auth'))) && 
            l.status === 401 &&
            (new Date(log.timestamp) - new Date(l.timestamp)) > 0 &&
            (new Date(log.timestamp) - new Date(l.timestamp)) < 180000
          );

          if (precedingFailures.length >= 3) {
            return {
              matched: true,
              type: "Account Takeover / Successful Brute Force Compromise",
              reason: `Successful authentication (status ${log.status}) immediately following ${precedingFailures.length} failed attempts from IP ${log.client_ip}. Probable valid password discovered!`,
              mitigation: "Immediately invalidate the session, trigger an out-of-band password reset, and block the offending source IP address."
            };
          }
        }
      }
      return null;
    }
  },
  {
    id: "RULE-SEC-005",
    name: "Automated Security Scanner User-Agent Detected",
    category: "recon",
    severity: "MEDIUM",
    description: "Detects User-Agent headers associated with automated penetration testing tools or vulnerability scanners (sqlmap, nikto, hydra, dirbuster).",
    check: (log) => {
      const ua = (log.user_agent || '').toLowerCase();
      const scanners = [
        { name: 'sqlmap', pattern: /sqlmap/i },
        { name: 'Hydra', pattern: /hydra/i },
        { name: 'Nikto', pattern: /nikto/i },
        { name: 'DirBuster / Gobuster', pattern: /dirbuster|gobuster|ffuf/i }
      ];

      for (const s of scanners) {
        if (s.pattern.test(ua)) {
          return {
            matched: true,
            type: `Automated Tool Scanner (${s.name})`,
            reason: `User-Agent string identifies automated tool: "${log.user_agent}".`,
            mitigation: "Block generic automated scanner User-Agents at the CDN / reverse proxy."
          };
        }
      }
      return null;
    }
  }
];

function getSearchablePayload(log) {
  let combined = log.uri || '';
  if (log.query_params) {
    for (const [k, v] of Object.entries(log.query_params)) {
      combined += ` ${k}=${v}`;
    }
  }
  if (log.body) {
    if (typeof log.body === 'string') combined += ` ${log.body}`;
    else if (typeof log.body === 'object') combined += ` ${JSON.stringify(log.body)}`;
  }
  return combined;
}

/**
 * Evaluates a single log against all SIEM rules
 */
export function inspectLogForIoCs(log, contextLogs = []) {
  for (const rule of DETECTION_RULES) {
    const result = rule.check(log, contextLogs);
    if (result && result.matched) {
      return {
        matched_rule: rule.id,
        rule_name: rule.name,
        severity: rule.severity,
        category: rule.category,
        ioc_detected: true,
        ioc_details: `${result.reason} [Action: ${result.mitigation}]`,
        attack_type: result.type,
        mitigation: result.mitigation
      };
    }
  }

  return {
    matched_rule: null,
    rule_name: null,
    severity: "INFO",
    category: log.category || "legitimate",
    ioc_detected: false,
    ioc_details: null,
    attack_type: null,
    mitigation: null
  };
}
