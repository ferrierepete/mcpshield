import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';
import { getSuspiciousPatterns } from '../data/index.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

function getCompiledSuspiciousUrlPatterns(): RegExp[] {
  return getSuspiciousPatterns().suspiciousUrlPatterns.map(p => new RegExp(p, 'i'));
}

function getCompiledTyposquatPatterns(): Array<{ original: string; pattern: RegExp }> {
  return getSuspiciousPatterns().typosquatPatterns.map(t => ({
    original: t.original,
    pattern: new RegExp(t.pattern, 'i'),
  }));
}

export function scanThreats(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const args = (config.args || []).join(' ');
  const env = config.env || {};

  // Check for typosquatting
  const cmd = config.command || '';
  const pkgArgs = config.args || [];

  if (cmd === 'npx' || cmd === 'bunx') {
    for (const arg of pkgArgs) {
      // Extract the scope (part before the first /) for scope-aware comparison
      const scopeMatch = arg.match(/^(@[^/]+)/);
      const argScope = scopeMatch ? scopeMatch[1] : arg;

      for (const { original, pattern } of getCompiledTyposquatPatterns()) {
        if (pattern.test(arg)) {
          // Extract the original scope for comparison
          const originalScopeMatch = original.match(/^(@[^/]+)/);
          const originalScope = originalScopeMatch ? originalScopeMatch[1] : original;

          // Flag if the arg's scope matches the typosquat regex
          // but is NOT the exact original scope (prevents scope-extension bypass)
          if (argScope !== originalScope) {
            findings.push(createFinding({
              title: 'Potential Typosquat',
              description: `Package "${arg}" looks similar to the trusted package "${original}" but is NOT the same. This may be a typosquatting attack.`,
              severity: 'critical',
              category: 'supply-chain',
              serverName: name,
              remediation: `Verify this is the intended package. The trusted package is "${original}".`,
              references: [OWASP_MCP_URL, 'MCP09:2025 - Shadow MCP Servers', 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
            }));
          }
        }
      }
    }
  }

  // Check for suspicious URLs in arguments, env, url field, or command
  const urlField = config.url || '';
  const headerValues = config.headers ? Object.values(config.headers).join(' ') : '';
  const allText = `${args} ${Object.values(env).join(' ')} ${urlField} ${headerValues} ${cmd}`;
  for (const pattern of getCompiledSuspiciousUrlPatterns()) {
    if (pattern.test(allText)) {
      findings.push(createFinding({
        title: 'Suspicious URL Detected',
        description: `Found a URL matching a suspicious pattern (${pattern.source}). This could indicate data exfiltration or command-and-control communication.`,
        severity: 'critical',
        category: 'data-exposure',
        serverName: name,
        remediation: 'Investigate this URL immediately. Remove the server if the destination is suspicious.',
        references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization', 'MCP05:2025 - Command Injection & Execution'],
      }));
    }
  }

  // Check for suspicious URLs directly in the command field
  for (const pattern of getCompiledSuspiciousUrlPatterns()) {
    if (pattern.test(cmd)) {
      const alreadyFlagged = findings.some(
        f => f.title === 'Suspicious URL in Command' && f.serverName === name
      );
      if (!alreadyFlagged) {
        findings.push(createFinding({
          title: 'Suspicious URL in Command',
          description: `The command field contains a URL matching a suspicious pattern (${pattern.source}). Commands should be local binaries, not remote URLs.`,
          severity: 'critical',
          category: 'supply-chain',
          serverName: name,
          remediation: 'Investigate this command immediately. MCP server commands should reference local executables.',
          references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution', 'MCP02:2025 - Tool Poisoning'],
        }));
      }
    }
  }

  // Check for credentials embedded in URLs (user:pass@host)
  if (urlField && /[^\s:]+:[^\s@]+@[^\s]/.test(urlField)) {
    findings.push(createFinding({
      title: 'Credentials Embedded in URL',
      description: `The server URL contains embedded credentials (user:password@host). Credentials should not be stored in plaintext URLs.`,
      severity: 'high',
      category: 'authentication',
      serverName: name,
      remediation: 'Move credentials to environment variables or a secrets manager. Use token-based authentication instead.',
      references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure', 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  // Check for base64 encoded strings (potential obfuscation)
  const knownPrefixes = ['sk-', 'ghp_', 'gho_', 'github_pat_', 'glpat-', 'xoxb-', 'xoxp-'];
  const base64PatternShort = /[A-Za-z0-9+/]{20,}={0,2}/;
  for (const [key, value] of Object.entries(env)) {
    if (knownPrefixes.some(p => value.startsWith(p))) continue;
    if (base64PatternShort.test(value)) {
      findings.push(createFinding({
        title: 'Potentially Obfuscated Value',
        description: `Environment variable "${key}" contains a base64-like string. This could be obfuscated malicious data.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: `Review the value of "${key}" to ensure it's a legitimate credential and not obfuscated malicious content.`,
        references: [OWASP_MCP_URL, 'MCP02:2025 - Tool Poisoning'],
      }));
    }
  }

  // Check for hex-encoded strings in environment values (potential obfuscation)
  const hexPattern = /[0-9a-fA-F]{32,}/;
  for (const [key, value] of Object.entries(env)) {
    if (knownPrefixes.some(p => value.startsWith(p))) continue;
    if (hexPattern.test(value)) {
      findings.push(createFinding({
        title: 'Hex-Encoded String Detected',
        description: `Environment variable "${key}" contains a long hex-encoded string. This could be obfuscated data or a hidden payload.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: `Review the value of "${key}" to ensure it's legitimate and not obfuscated malicious content.`,
        references: [OWASP_MCP_URL, 'MCP02:2025 - Tool Poisoning'],
      }));
    }
  }

  // Check for URL-encoded payloads in environment values
  const percentEncodedPattern = /%[0-9A-Fa-f]{2}/;
  const suspiciousDecodedPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /data:text\/html/i,
    /eval\s*\(/i,
    /expression\s*\(/i,
    /import\s/i,
  ];
  for (const [key, value] of Object.entries(env)) {
    if (knownPrefixes.some(p => value.startsWith(p))) continue;
    if (percentEncodedPattern.test(value)) {
      try {
        const decoded = decodeURIComponent(value);
        for (const suspicious of suspiciousDecodedPatterns) {
          if (suspicious.test(decoded)) {
            findings.push(createFinding({
              title: 'URL-Encoded Suspicious Payload Detected',
              description: `Environment variable "${key}" contains a URL-encoded string that decodes to a suspicious pattern ("${suspicious.source}"). This could be an attempt to bypass static security checks.`,
              severity: 'medium',
              category: 'configuration',
              serverName: name,
              remediation: `Review the value of "${key}" to ensure it's legitimate and not an obfuscated payload.`,
              references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
            }));
            break;
          }
        }
      } catch {
        // Invalid percent encoding, skip
      }
    }
  }

  // Check for reverse shell patterns in args and command
  const reverseShellPatterns = [
    /nc\s+-l/,
    /ncat\s+-l/,
    /socat\s+TCP-LISTEN/,
    /\/dev\/tcp\//,
    /\/dev\/udp\//,
    /bash\s+-i\s+>&/,
    /sh\s+-i\s+>&/,
  ];
  const combinedCmdArgs = `${cmd} ${args}`;
  for (const rsp of reverseShellPatterns) {
    if (rsp.test(combinedCmdArgs)) {
      findings.push(createFinding({
        title: 'Reverse Shell Pattern Detected',
        description: `Found a reverse shell pattern ("${rsp.source}") in the server configuration. This is a critical security threat.`,
        severity: 'critical',
        category: 'configuration',
        serverName: name,
        remediation: 'Remove this server immediately. Reverse shell patterns indicate a backdoor or remote access trojan.',
        references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution', 'MCP02:2025 - Tool Poisoning'],
      }));
    }
  }

  // Check for cwd pointing to sensitive directories
  if (config.cwd) {
    const sensitiveDirs = ['/etc', '/root', '/var/log', '/boot'];
    for (const dir of sensitiveDirs) {
      if (config.cwd.startsWith(dir)) {
        findings.push(createFinding({
          title: 'Sensitive Working Directory',
          description: `Server's working directory is "${config.cwd}" which is a sensitive system directory.`,
          severity: 'medium',
          category: 'permissions',
          serverName: name,
          remediation: 'Change the working directory to a non-sensitive location specific to this server\'s purpose.',
          references: [OWASP_MCP_URL],
        }));
      }
    }
  }

  return findings;
}
