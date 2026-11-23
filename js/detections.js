/**
 * SOC SIEM Detection Engine & Signature Rules
 * Inspects HTTP request fields (Method, URI, Query Params, Body, User-Agent)
 * for known Indicators of Compromise (IoCs).
 */

import { decodePayloadSafely } from './utils.js';

export const DETECTION_RULES = [
  {
    id: "RULE-SEC-001",
    name: "SQL Injection - UNION / Data Exfiltration Signature",
    category: "sqli",
    severity: "CRITICAL",
    description: "Detects UNION SELECT statements, information_schema harvesting, or stacked exfiltration queries in URL parameters or request bodies.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      // Check for UNION SELECT patterns
      const unionPattern = /\bunion\s+(all\s+)?select\b/i;
      const schemaPattern = /\binformation_schema\b/i;
      const dbFuncPattern = /\b(current_user|database|user|schema|version)\s*\(\s*\)/i;
      const hexPattern = /0x[0-9a-f]{2,}/i;

      if (unionPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (UNION-Based)",
          reason: "UNION SELECT pattern identified. Attacker is attempting to merge query results to extract unauthorized database records.",
          mitigation: "Use Parameterized Queries / Prepared Statements (e.g. PDO in PHP, PreparedStatement in Java) and strictly validate input types."
        };
      }

      if (schemaPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Schema Reconnaissance)",
          reason: "Access to information_schema detected. Attacker is probing database metadata for tables and columns.",
          mitigation: "Restrict database user permissions to only required application tables and disable metadata access."
        };
      }

      if (hexPattern.test(decoded) && /select|from/i.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Hex-Encoded Exfiltration)",
          reason: "Hex-encoded character strings detected within SQL context (e.g., 0x3a delimiter bypass).",
          mitigation: "Implement Web Application Firewall (WAF) SQLi inspection and enforce strict input validation."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-002",
    name: "SQL Injection - Tautology / Comment Signature",
    category: "sqli",
    severity: "HIGH",
    description: "Detects classic SQL boolean tautologies (' OR '1'='1), inline SQL comments (-- , /* */, #), or error probes.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      // Tautologies like ' OR 1=1, ' OR 'a'='a', " OR 1=1
      const tautologyPattern = /('|")\s*(or|and)\s+['"\d\w]+\s*=\s*['"\d\w]+/i;
      const commentPattern = /(--|\/\*|#|%23)/i;
      const errorQuotePattern = /'|"/;

      if (tautologyPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Tautology / Auth Bypass)",
          reason: "Boolean tautology expression (' OR 1=1) detected. Commonly used to bypass authentication gates or force full record enumeration.",
          mitigation: "Never concatenate user input directly into SQL strings. Always bind parameters."
        };
      }

      if (commentPattern.test(decoded) && (/admin|select|where|login|or|and/i.test(decoded))) {
        return {
          matched: true,
          type: "SQL Injection (Comment Truncation)",
          reason: "SQL comment sequence (-- or /* */) coupled with SQL keywords detected, attempting to truncate remaining server SQL query logic.",
          mitigation: "Reject input containing unescaped SQL syntax operators or use ORM abstraction layers."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-003",
    name: "Cross-Site Scripting (XSS) - Malicious Script or Event Handler",
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
          reason: "Raw <script> tag detected in payload. Attacker is attempting to execute JavaScript in the victim's browser context.",
          mitigation: "Context-aware HTML entity encoding on output (e.g., &lt;script&gt;) and implement Content Security Policy (CSP)."
        };
      }

      if (eventHandlerPattern.test(decoded) || dangerousTags.test(decoded)) {
        return {
          matched: true,
          type: "Cross-Site Scripting (Event Handler / Polyglot)",
          reason: "HTML element with inline JavaScript event handler (e.g. <img src=x onerror=...>) detected.",
          mitigation: "Sanitize user inputs with a trusted sanitizer (DOMPurify) and strip dangerous attributes."
        };
      }

      if (cookieStealer.test(decoded) && (/<|%3c|on/i.test(target))) {
        return {
          matched: true,
          type: "Cross-Site Scripting (Cookie / Credential Theft)",
          reason: "Payload references document.cookie or browser redirect methods within injection syntax.",
          mitigation: "Set HttpOnly and SameSite flags on all sensitive session cookies to prevent JavaScript access."
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
    description: "Detects abnormal bursts of HTTP 401 Unauthorized status responses targeting authentication endpoints (/api/login, /login), or credential stuffing signatures.",
    check: (log, contextLogs = []) => {
      if (log.uri && log.uri.includes('/login')) {
        // If this single log is a 401, check recent history for this IP
        if (log.status === 401) {
          const recentAttempts = contextLogs.filter(l => 
            l.client_ip === log.client_ip && 
            l.uri && l.uri.includes('/login') && 
            l.status === 401 &&
            Math.abs(new Date(l.timestamp) - new Date(log.timestamp)) < 120000 // 2 minutes window
          );

          if (recentAttempts.length >= 3) {
            return {
              matched: true,
              type: "Authentication Brute Force (High Frequency)",
              reason: `Multiple consecutive failed authentication attempts (${recentAttempts.length} within 2 mins) from IP ${log.client_ip}.`,
              mitigation: "Enforce account lockout thresholds, progressive rate-limiting (e.g., exponential backoff / CAPTCHA), and Multi-Factor Authentication (MFA)."
            };
          }
        }

        // Check for sudden 302/200 following consecutive 401s (Compromise!)
        if ((log.status === 200 || log.status === 302) && log.method === 'POST') {
          const precedingFailures = contextLogs.filter(l => 
            l.client_ip === log.client_ip && 
            l.uri && l.uri.includes('/login') && 
            l.status === 401 &&
            (new Date(log.timestamp) - new Date(l.timestamp)) > 0 &&
            (new Date(log.timestamp) - new Date(l.timestamp)) < 180000
          );

          if (precedingFailures.length >= 4) {
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
    description: "Detects User-Agent headers associated with automated penetration testing tools or vulnerability scanners (sqlmap, hydra, nikto, dirbuster, gobuster).",
    check: (log) => {
      const ua = (log.user_agent || '').toLowerCase();
      const scanners = [
        { name: 'sqlmap', pattern: /sqlmap/i },
        { name: 'Hydra', pattern: /hydra/i },
        { name: 'Nikto', pattern: /nikto/i },
        { name: 'DirBuster / Gobuster', pattern: /dirbuster|gobuster|ffuf/i },
        { name: 'Python Requests Script', pattern: /python-requests/i }
      ];

      for (const s of scanners) {
        if (s.pattern.test(ua)) {
          return {
            matched: true,
            type: `Automated Tool Scanner (${s.name})`,
            reason: `User-Agent string explicitly identifies automated attack tool: "${log.user_agent}".`,
            mitigation: "Block generic automated scanner User-Agents at the CDN / reverse proxy and inspect IP reputation."
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
    category: "legitimate",
    ioc_detected: false,
    ioc_details: null,
    attack_type: null,
    mitigation: null
  };
}
