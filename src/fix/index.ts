import { readFileSync, writeFileSync } from 'fs';
import { MCPConfig, Finding } from '../types/index.js';

/**
 * Resolve the exact latest version of an npm package from the registry.
 * Returns the version string (e.g. "1.2.3") or null if the fetch fails.
 */
export async function resolveExactVersion(pkgName: string): Promise<string | null> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}/latest`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    if (typeof body === 'object' && body !== null && 'version' in body) {
      const v = (body as { version: unknown }).version;
      return typeof v === 'string' ? v : null;
    }
    return null;
  } catch {
    return null;
  }
}

interface FixAction {
  findingTitle: string;
  description: string;
  apply: (config: MCPConfig, serverName: string, finding: Finding) => MCPConfig | null;
}

const FIX_ACTIONS: FixAction[] = [
  {
    findingTitle: 'Unpinned Package Version',
    description: 'Pin package to exact resolved version',
    apply: (config, serverName) => {
      const server = config.mcpServers[serverName];
      if (!server?.args) return null;
      const updated = { ...config };
      updated.mcpServers = { ...config.mcpServers };
      updated.mcpServers[serverName] = { ...server };
      updated.mcpServers[serverName].args = server.args.map(arg => {
        if ((arg.startsWith('@') || !arg.startsWith('-')) && arg !== '-y') {
          const lastAt = arg.lastIndexOf('@');
          if (lastAt <= 0) {
            return `${arg}@0.0.0-REVIEW-NEEDED`;
          }
        }
        return arg;
      });
      return updated;
    },
  },
  {
    findingTitle: 'Sensitive Credentials in Config',
    description: 'Replace hardcoded secrets with environment variable references',
    apply: (config, serverName) => {
      const server = config.mcpServers[serverName];
      if (!server?.env) return null;
      const sensitiveKeys = [
        'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID',
        'GH_TOKEN', 'GITHUB_TOKEN', 'GITHUB_PAT',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
        'DATABASE_URL', 'DB_PASSWORD',
        'PRIVATE_KEY', 'SECRET_KEY',
        'STRIPE_SECRET_KEY', 'SLACK_TOKEN',
      ];
      const updated = { ...config };
      updated.mcpServers = { ...config.mcpServers };
      updated.mcpServers[serverName] = { ...server, env: { ...server.env } };
      for (const key of Object.keys(updated.mcpServers[serverName].env!)) {
        if (sensitiveKeys.some(s => key.toUpperCase().includes(s))) {
          // Sanitize key to prevent command injection: only allow alphanumeric and underscore
          const safeKey = key.replace(/[^a-zA-Z0-9_]/g, '_');
          // SECURITY: Delete the original dangerous key and replace with safe env var name.
          // Simply updating the value is insufficient — the dangerous key name must be removed
          // so that shell expansion like ${AWS_SECRET_ACCESS_KEY$(cat)} is not possible.
          delete updated.mcpServers[serverName].env![key];
          updated.mcpServers[serverName].env![safeKey] = `\${${safeKey}}`;
        }
      }
      return updated;
    },
  },
  {
    findingTitle: 'Network Binding to All Interfaces',
    description: 'Replace 0.0.0.0 with 127.0.0.1 (localhost)',
    apply: (config, serverName) => {
      const server = config.mcpServers[serverName];
      if (!server?.args) return null;
      const updated = { ...config };
      updated.mcpServers = { ...config.mcpServers };
      updated.mcpServers[serverName] = { ...server };
      updated.mcpServers[serverName].args = server.args.map(arg =>
        arg.replace(/0\.0\.0\.0/g, '127.0.0.1').replace(/::/g, '::1')
      );
      return updated;
    },
  },
  {
    findingTitle: 'Insecure HTTP Transport',
    description: 'Upgrade HTTP URL to HTTPS',
    apply: (config, serverName) => {
      const server = config.mcpServers[serverName];
      if (!server?.url?.startsWith('http://')) return null;
      const updated = { ...config };
      updated.mcpServers = { ...config.mcpServers };
      updated.mcpServers[serverName] = {
        ...server,
        url: server.url.replace('http://', 'https://'),
      };
      return updated;
    },
  },
  {
    findingTitle: 'Empty or Wildcard Environment Variable',
    description: 'Remove empty/wildcard environment variables',
    apply: (config, serverName) => {
      const server = config.mcpServers[serverName];
      if (!server?.env) return null;
      const updated = { ...config };
      updated.mcpServers = { ...config.mcpServers };
      updated.mcpServers[serverName] = { ...server, env: { ...server.env } };
      for (const [key, value] of Object.entries(updated.mcpServers[serverName].env!)) {
        if (value === '' || value === '*') {
          delete updated.mcpServers[serverName].env![key];
        }
      }
      return updated;
    },
  },
];

export interface FixResult {
  applied: string[];
  skipped: string[];
}

export function getAvailableFixes(findings: Finding[]): FixAction[] {
  return FIX_ACTIONS.filter(fix =>
    findings.some(f => f.title === fix.findingTitle)
  );
}

export function applyFixesSync(
  config: MCPConfig,
  findings: Finding[],
): { config: MCPConfig; result: FixResult } {
  let current = config;
  const result: FixResult = { applied: [], skipped: [] };

  for (const fix of FIX_ACTIONS) {
    const matchingFindings = findings.filter(f => f.title === fix.findingTitle);
    for (const finding of matchingFindings) {
      const fixed = fix.apply(current, finding.serverName, finding);
      if (fixed) {
        current = fixed;
        result.applied.push(`${finding.serverName}: ${fix.description}`);
      } else {
        result.skipped.push(`${finding.serverName}: ${fix.findingTitle} (no automatic fix available)`);
      }
    }
  }

  return { config: current, result };
}

export async function applyFixes(
  config: MCPConfig,
  findings: Finding[],
): Promise<{ config: MCPConfig; result: FixResult }> {
  const { config: fixed, result } = applyFixesSync(config, findings);

  const REVIEW_TAG = '@0.0.0-REVIEW-NEEDED';
  let hasReviewTag = false;
  for (const server of Object.values(fixed.mcpServers)) {
    if (server.args?.some(a => a.includes(REVIEW_TAG))) {
      hasReviewTag = true;
      break;
    }
  }

  if (!hasReviewTag) {
    return { config: fixed, result };
  }

  const updated = { ...fixed, mcpServers: { ...fixed.mcpServers } };
  for (const [name, server] of Object.entries(fixed.mcpServers)) {
    if (!server.args) continue;
    const newArgs = [...server.args];
    let changed = false;
    for (let i = 0; i < newArgs.length; i++) {
      const arg = newArgs[i];
      if (!arg.endsWith(REVIEW_TAG)) continue;
      const pkgName = arg.slice(0, arg.length - REVIEW_TAG.length);
      const version = await resolveExactVersion(pkgName);
      newArgs[i] = version ? `${pkgName}@${version}` : arg;
      changed = true;
    }
    if (changed) {
      updated.mcpServers[name] = { ...server, args: newArgs };
    }
  }

  return { config: updated, result };
}

export function writeConfig(configPath: string, config: MCPConfig): void {
  // Create a backup before writing — overwrite any stale .bak
  const backupPath = configPath + '.bak';
  const raw = readFileSync(configPath, 'utf-8');
  writeFileSync(backupPath, raw, 'utf-8');

  const parsed = JSON.parse(raw);

  // Preserve the original key (mcpServers or servers)
  if (parsed.servers && !parsed.mcpServers) {
    parsed.servers = config.mcpServers;
  } else {
    parsed.mcpServers = config.mcpServers;
  }

  writeFileSync(configPath, JSON.stringify(parsed, null, 2) + '\n', 'utf-8');
}
