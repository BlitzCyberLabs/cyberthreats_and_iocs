/**
 * SOC SIEM Detection Engine & Signature Rules
 * Inspects HTTP request fields (Method, URI, Query Params, Body, User-Agent)
 * for known Indicators of Compromise (IoCs) across SQLi, XSS, and Directory Traversal.
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

      const unionPattern = /\bunion\s+(all\s+)?select\b/i;
      const schemaPattern = /\binformation_schema\b/i;
      const hexPattern = /0x[0-9a-f]{2,}/i;

      if (unionPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (UNION-Based)",
          reason: "UNION SELECT statement identified. Attacker is merging query results to extract unauthorized database records.",
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

      if (hexPattern.test(decoded) && /select|from/i.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Hex-Encoded Exfiltration)",
          reason: "Hex-encoded character strings detected within SQL context.",
          mitigation: "Enforce Web Application Firewall (WAF) query inspection."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-002",
    name: "SQL Injection - Syntax Anomaly / Tautology Probe",
    category: "sqli",
    severity: "HIGH",
    description: "Detects SQL boolean tautologies (' OR '1'='1), inline SQL comments (-- , /* */, #), or unhandled syntax error probes.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      const tautologyPattern = /('|")\s*(or|and)\s+['"\d\w]+\s*=\s*['"\d\w]+/i;
      const commentPattern = /(--|\/\*|#|%23)/i;
      const isolatedQuote = /^'|'$/;

      if (tautologyPattern.test(decoded)) {
        return {
          matched: true,
          type: "SQL Injection (Tautology / Auth Bypass)",
          reason: "Boolean tautology expression (' OR 1=1) detected. Used to bypass authentication or force record enumeration.",
          mitigation: "Bind all query parameters using prepared statements."
        };
      }

      if (commentPattern.test(decoded) && (/admin|select|where|login|or|and/i.test(decoded))) {
        return {
          matched: true,
          type: "SQL Injection (Comment Truncation)",
          reason: "SQL comment sequence (-- or /* */) attempting to truncate server SQL query logic.",
          mitigation: "Use parameterized queries and reject unescaped query delimiter syntax."
        };
      }

      if (log.status === 500 && (decoded.includes("'") || decoded.includes('"'))) {
        return {
          matched: true,
          type: "SQL Injection (Error-Based Syntax Probe)",
          reason: "HTTP 500 unhandled database exception triggered by unescaped quotation mark probe.",
          mitigation: "Implement robust error handling that masks database error details from clients."
        };
      }

      return null;
    }
  },
  {
    id: "RULE-SEC-006",
    name: "Directory Traversal - Dot-Dot-Slash (../) Path Escape Attempt",
    category: "path_traversal",
    severity: "CRITICAL",
    description: "Detects path traversal sequences (../, ..\\, %2e%2e%2f) attempting to escape the document root and access arbitrary operating system or configuration files.",
    check: (log) => {
      const target = getSearchablePayload(log);
      const decoded = decodePayloadSafely(target).toLowerCase();

      // Dot-dot-slash patterns (raw or encoded)
      const traversalPattern = /(?:\.\.[/\\])+|(?:\%2e\%2e[\/\\])+|(?:\%2e\%2e\%2f)+/i;
      const sensitiveFiles = /(?:etc\/passwd|etc\/shadow|secrets\.env|\.env|win\.ini|windows\/system32|boot\.ini)/i;

      if (traversalPattern.test(target) || traversalPattern.test(decoded)) {
        return {
          matched: true,
          type: "Directory Traversal (Path Traversal)",
          reason: `Path traversal pattern (../) detected. Attacker is attempting to escape the web application directory tree.`,
          mitigation: "Sanitize user-supplied file paths using path.basename(), validate against a strict whitelist of permitted files, and use secure file storage abstractions."
        };
      }

      if (sensitiveFiles.test(decoded)) {
        return {
          matched: true,
          type: "Directory Traversal (Sensitive System File Probe)",
          reason: `Attempted access to protected system resource detected in request URI: "${decoded}".`,
          mitigation: "Never pass unsanitized client inputs directly to filesystem APIs (e.g. fs.readFile, include, file_get_contents)."
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
    id: "RULE-SEC-005",
    name: "Automated Security Scanner User-Agent Detected",
    category: "recon",
    severity: "MEDIUM",
    description: "Detects User-Agent headers associated with automated penetration testing tools or vulnerability scanners (sqlmap, nikto, dirbuster).",
    check: (log) => {
      const ua = (log.user_agent || '').toLowerCase();
      const scanners = [
        { name: 'sqlmap', pattern: /sqlmap/i },
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
