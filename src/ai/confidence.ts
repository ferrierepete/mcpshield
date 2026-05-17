import { Finding, MCPServerConfig } from '../types/index.js';
import { isTrustedPackage } from '../data/index.js';

interface ConfidenceRule {
  match: (finding: Finding, serverConfig?: MCPServerConfig) => boolean;
  adjust: number; // negative = lower confidence (more likely false positive)
  reason: string;
}

const CONFIDENCE_RULES: ConfidenceRule[] = [
  // --- Lower confidence (likely false positives) ---
  {
    match: (f) => f.title === 'Unpinned Package Version' && !!f.description.match(/@modelcontextprotocol\//),
    adjust: -0.3,
    reason: 'Official MCP package — low supply chain risk even unpinned',
  },
  {
    match: (f, config) => {
      if (f.title !== 'Unpinned Package Version') return false;
      const pkg = config?.args?.find(a => a.startsWith('@') || (!a.startsWith('-') && a !== 'npx' && a !== 'bunx' && a !== '-y'));
      return !!pkg && isTrustedPackage(pkg);
    },
    adjust: -0.25,
    reason: 'Trusted package — lower risk even without pinned version',
  },
  {
    match: (f) => f.title === 'Sensitive Credentials in Config' && !!f.description.match(/\b1\b sensitive/),
    adjust: -0.1,
    reason: 'Single credential exposure — may be intentional for local dev',
  },
  {
    match: (f, config) => {
      if (f.title !== 'Sensitive Credentials in Config') return false;
      const env = config?.env || {};
      const values = Object.values(env);
      return values.every(v => v.startsWith('${') || v.startsWith('$'));
    },
    adjust: -0.4,
    reason: 'Env vars use variable references — not actually hardcoded',
  },
  {
    match: (f) => f.title === 'Insecure HTTP Transport' && !!f.description.match(/localhost|127\.0\.0\.1/),
    adjust: -0.4,
    reason: 'HTTP to localhost is standard and safe',
  },
  {
    match: (f) => f.title === 'IP-Based Server URL' && !!f.description.match(/192\.168\.|10\.\d|172\.(1[6-9]|2\d|3[01])\./),
    adjust: -0.3,
    reason: 'Private/internal IP address — not a C2 indicator',
  },
  {
    match: (f) => f.title === 'Remote Server Without Authentication Headers' && !!f.description.match(/github|anthropic|openai/i),
    adjust: -0.2,
    reason: 'Well-known provider URL — may handle auth differently',
  },
  {
    match: (f) => f.title === 'Unverified Third-Party Package' && !!f.description.match(/@(microsoft|google|aws|github|anthropic|openai)\//),
    adjust: -0.35,
    reason: 'Package from a well-known organization scope',
  },
  {
    match: (f) => f.title === 'Potentially Obfuscated Value' && !!f.description.match(/TOKEN|KEY|SECRET/i),
    adjust: -0.25,
    reason: 'Base64-like value in a credential field — likely a legitimate token',
  },
  {
    match: (f) => f.title === 'Docker Port Exposed to All Interfaces' && !!f.description.match(/localhost|127\.0\.0\.1/),
    adjust: -0.3,
    reason: 'Port mapping includes localhost binding',
  },
  {
    match: (f) => f.title === 'Local Executable Path' && !!f.description.match(/\/(usr\/local\/bin|opt\/homebrew|nix\/store)\//),
    adjust: -0.3,
    reason: 'System-managed executable path — unlikely to be tampered',
  },
  {
    match: (f) => f.title === 'Disabled Server',
    adjust: -0.2,
    reason: 'Server is disabled — no active risk',
  },
  {
    match: (f) => f.title === 'Empty or Wildcard Environment Variable',
    adjust: -0.15,
    reason: 'Low-impact misconfiguration',
  },

  // --- Higher confidence (likely true positives) ---
  {
    match: (f) => f.title === 'Known Risky Package',
    adjust: 0.1,
    reason: 'Matches known-risky package list',
  },
  {
    match: (f) => f.title === 'Potential Typosquat',
    adjust: 0.1,
    reason: 'Typosquatting is a high-confidence attack vector',
  },
  {
    match: (f) => f.title === 'Suspicious URL Detected',
    adjust: 0.1,
    reason: 'Known exfiltration/C2 URL pattern',
  },
  {
    match: (f) => f.title === 'Dangerous Docker Flag' && !!f.description.match(/--privileged/),
    adjust: 0.1,
    reason: '--privileged grants full host access',
  },
  {
    match: (f) => f.title === 'Dynamic Code Execution Pattern',
    adjust: 0.1,
    reason: 'eval/exec in server args is almost always dangerous',
  },
  {
    match: (f) => f.title === 'Shell Metacharacter in Arguments',
    adjust: 0.05,
    reason: 'Shell metacharacters indicate injection risk',
  },
  {
    match: (f) => f.title === 'Broad Filesystem Access' && !!f.description.match(/path "\/"/),
    adjust: 0.1,
    reason: 'Root filesystem access is always critical',
  },
  {
    match: (f) => f.title === 'HTTP Client as MCP Server',
    adjust: 0.1,
    reason: 'curl/wget as MCP command is almost always suspicious',
  },

  {
    match: (f) => !!f.title.match(/Shell Interpreter/),
    adjust: 0.15,
    reason: 'Shell interpreter access increases command injection risk',
  },
  {
    match: (f) => !!f.title.match(/Direct Code Execution/) || !!f.description.match(/node -e/),
    adjust: 0.2,
    reason: 'Direct code execution is a high-risk pattern',
  },
  {
    match: (f) => !!f.title.match(/Reverse Shell/),
    adjust: 0.25,
    reason: 'Reverse shell patterns are almost always malicious',
  },
  {
    match: (f) => !!f.description.match(/--security-opt/),
    adjust: 0.15,
    reason: 'Docker security option manipulation weakens container isolation',
  },
  {
    match: (f) => !!f.description.match(/--user root/),
    adjust: 0.15,
    reason: 'Running as root in a container is a privilege escalation risk',
  },
  {
    match: (f) => !!f.title.match(/sudo/) || !!f.description.match(/sudo/),
    adjust: 0.2,
    reason: 'sudo usage in MCP server config is a privilege escalation indicator',
  },
  {
    match: (f) => !!f.title.match(/Docker Compose/),
    adjust: -0.2,
    reason: 'Docker Compose references cannot be fully analyzed statically',
  },
  {
    match: (f) => !!f.description.match(/ws:\/\//),
    adjust: 0.1,
    reason: 'WebSocket connection increases data exfiltration surface',
  },
  {
    match: (f) => !!f.title.match(/Credentials in URL/),
    adjust: 0.15,
    reason: 'Credentials embedded in URLs are a clear secret exposure',
  },
  {
    match: (f) => !!f.title.match(/Unpinned/) && !!f.description.match(/semver range/),
    adjust: 0.1,
    reason: 'Semver range with unpinned version allows unexpected updates',
  },
  {
    match: (f) => !!f.title.match(/Typosquat/) && !!f.description.match(/scope extension/),
    adjust: 0.1,
    reason: 'Typosquat with scope extension is a strong attack indicator',
  },
];

const BASE_CONFIDENCE: Record<string, number> = {
  'critical': 0.9,
  'high': 0.8,
  'medium': 0.65,
  'low': 0.5,
  'info': 0.4,
};

export function computeConfidence(
  finding: Finding,
  serverConfig?: MCPServerConfig
): number {
  let confidence = BASE_CONFIDENCE[finding.severity] ?? 0.7;

  for (const rule of CONFIDENCE_RULES) {
    try {
      if (rule.match(finding, serverConfig)) {
        confidence += rule.adjust;
      }
    } catch {
      // Rule errors should never crash the scan
    }
  }

  return Math.max(0, Math.min(1, parseFloat(confidence.toFixed(2))));
}

export function applyConfidenceScores(
  findings: Finding[],
  serverConfigs: Record<string, MCPServerConfig>
): Finding[] {
  return findings.map(f => ({
    ...f,
    confidence: computeConfidence(f, serverConfigs[f.serverName]),
  }));
}

export function filterByConfidence(findings: Finding[], minConfidence: number): Finding[] {
  return findings.filter(f => (f.confidence ?? 1) >= minConfidence);
}
