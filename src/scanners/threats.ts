import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';
import { getSuspiciousPatterns } from '../data/index.js';

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
      for (const { original, pattern } of getCompiledTyposquatPatterns()) {
        if (pattern.test(arg) && !arg.includes(original)) {
          findings.push(createFinding({
            title: 'Potential Typosquat',
            description: `Package "${arg}" looks similar to the trusted package "${original}" but is NOT the same. This may be a typosquatting attack.`,
            severity: 'critical',
            category: 'supply-chain',
            serverName: name,
            remediation: `Verify this is the intended package. The trusted package is "${original}".`,
            references: ['MCP09:2025 - Shadow MCP Servers', 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
          }));
        }
      }
    }
  }

  // Check for suspicious URLs in arguments, env, or url field
  const urlField = config.url || '';
  const headerValues = config.headers ? Object.values(config.headers).join(' ') : '';
  const allText = `${args} ${Object.values(env).join(' ')} ${urlField} ${headerValues}`;
  for (const pattern of getCompiledSuspiciousUrlPatterns()) {
    if (pattern.test(allText)) {
      findings.push(createFinding({
        title: 'Suspicious URL Detected',
        description: `Found a URL matching a suspicious pattern (${pattern.source}). This could indicate data exfiltration or command-and-control communication.`,
        severity: 'critical',
        category: 'data-exposure',
        serverName: name,
        remediation: 'Investigate this URL immediately. Remove the server if the destination is suspicious.',
        references: ['MCP07:2025 - Insufficient Authentication & Authorization'],
      }));
    }
  }

  // Check for base64 encoded strings (potential obfuscation)
  const base64Pattern = /[A-Za-z0-9+/]{40,}={0,2}/;
  for (const [key, value] of Object.entries(env)) {
    if (base64Pattern.test(value) && !value.startsWith('sk-') && !value.startsWith('ghp_')) {
      findings.push(createFinding({
        title: 'Potentially Obfuscated Value',
        description: `Environment variable "${key}" contains a base64-like string. This could be obfuscated malicious data.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: `Review the value of "${key}" to ensure it's a legitimate credential and not obfuscated malicious content.`,
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
        }));
      }
    }
  }

  return findings;
}
