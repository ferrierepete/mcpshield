import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';
import { isTrustedPackage, isRiskyPackage } from '../data/index.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

/**
 * Extract package name and version from a package argument.
 * Handles scoped packages like @scope/pkg@1.2.3 and regular packages like pkg@1.2.3.
 */
function extractPackageVersion(pkgArg: string): { pkg: string; version: string | null } {
  if (pkgArg.startsWith('@')) {
    // Scoped package: @scope/pkg@1.2.3 — version is after the SECOND @
    const secondAt = pkgArg.indexOf('@', 1);
    if (secondAt > 0) {
      return { pkg: pkgArg.substring(0, secondAt), version: pkgArg.substring(secondAt + 1) };
    }
    return { pkg: pkgArg, version: null };
  }
  // Regular package: pkg@1.2.3
  const atIdx = pkgArg.indexOf('@');
  if (atIdx > 0) {
    return { pkg: pkgArg.substring(0, atIdx), version: pkgArg.substring(atIdx + 1) };
  }
  return { pkg: pkgArg, version: null };
}

/**
 * Check if a version string is an exact pinned semver (X.Y.Z).
 * Rejects ranges like ^1.0.0, ~1.0.0, >=1.0.0, *, latest, x-ranges, etc.
 */
function isExactSemver(version: string): boolean {
  return /^\d+\.\d+\.\d+$/.test(version);
}

/**
 * Check if a Python package argument is pinned with ==X.Y.Z format.
 */
function isPythonPinned(pkgArg: string): boolean {
  const eqIdx = pkgArg.indexOf('==');
  if (eqIdx < 0) return false;
  const version = pkgArg.substring(eqIdx + 2);
  return /^\d+\.\d+\.\d+$/.test(version);
}

/**
 * Run Node.js package supply-chain checks (unpinned, risky, unverified).
 */
function checkNodePackage(pkgArg: string, name: string, findings: Finding[]): void {
  const { version } = extractPackageVersion(pkgArg);

  if (!version || !isExactSemver(version)) {
    findings.push(createFinding({
      title: 'Unpinned Package Version',
      description: `Package "${pkgArg}" is used without a pinned version. This allows supply chain attacks via dependency confusion or typosquatting.`,
      severity: 'high',
      category: 'supply-chain',
      serverName: name,
      remediation: `Pin the package version: "${extractPackageVersion(pkgArg).pkg}@<exact-version>" or use a lockfile.`,
      references: ['https://owasp.org/www-project-mcp-top-10/', 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
    }));
  }

  if (isRiskyPackage(pkgArg)) {
    findings.push(createFinding({
      title: 'Known Risky Package',
      description: `Package "${pkgArg}" is in the known-risky list. It may be a typosquat or has been associated with suspicious activity.`,
      severity: 'critical',
      category: 'supply-chain',
      serverName: name,
      remediation: `Remove this package and find a trusted alternative. Check npm for the package details.`,
      references: [OWASP_MCP_URL, 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
    }));
  }

  if (!isTrustedPackage(pkgArg)) {
    findings.push(createFinding({
      title: 'Unverified Third-Party Package',
      description: `Package "${pkgArg}" is not in the verified list. Third-party MCP servers can execute arbitrary code on your machine.`,
      severity: 'medium',
      category: 'supply-chain',
      serverName: name,
      remediation: `Verify the package source, check its npm page, review its GitHub repo, and confirm the author is legitimate before trusting.`,
      references: [OWASP_MCP_URL, 'MCP09:2025 - Shadow MCP Servers', 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
    }));
  }
}

export function scanSupplyChain(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command?.toLowerCase() || '';
  const args = config.args || [];

  // ── Node.js package runners ──

  // Single-word runners
  const singleRunners = ['npx', 'bunx'];

  // Multi-word runners: command → expected first arg (subcommand)
  const multiWordRunners: Record<string, string> = {
    'npm': 'exec',
    'pnpm': 'dlx',
    'yarn': 'dlx',
    'bun': 'x',
  };

  let pkgArg: string | undefined;

  if (singleRunners.includes(cmd)) {
    pkgArg = args.find(a => a.startsWith('@') || (!a.startsWith('-') && a !== cmd));
  } else if (multiWordRunners[cmd] && args[0]?.toLowerCase() === multiWordRunners[cmd]) {
    // For multi-word runners, find package arg after the subcommand
    pkgArg = args.find((a, i) => i > 0 && (a.startsWith('@') || !a.startsWith('-')));
  }

  if (pkgArg) {
    checkNodePackage(pkgArg, name, findings);
  }

  // ── Python package runners ──

  const pythonDirectRunners = ['uvx'];
  const pythonPipRunners: Record<string, string> = {
    'python': 'pip',
    'python3': 'pip',
  };

  let pythonPkg: string | undefined;

  if (pythonDirectRunners.includes(cmd)) {
    pythonPkg = args.find(a => !a.startsWith('-') && a !== cmd);
    if (pythonPkg && pythonPkg.startsWith('/')) pythonPkg = undefined;
  } else if (pythonPipRunners[cmd]) {
    // python -m pip install pkg or python3 -m pip install pkg
    const mIdx = args.indexOf('-m');
    if (mIdx >= 0 && args[mIdx + 1] === pythonPipRunners[cmd]) {
      const installIdx = args.indexOf('install');
      if (installIdx >= 0) {
        pythonPkg = args.find((a, i) => i > installIdx && !a.startsWith('-'));
      }
    }
  }

  if (pythonPkg) {
    if (!isPythonPinned(pythonPkg)) {
      const pkgName = pythonPkg.split('==')[0].split('@')[0];
      findings.push(createFinding({
        title: 'Unpinned Python Package Version',
        description: `Python package "${pythonPkg}" is used without a pinned version (==X.Y.Z). This allows supply chain attacks via dependency confusion or typosquatting.`,
        severity: 'high',
        category: 'supply-chain',
        serverName: name,
        remediation: `Pin the package version: "${pkgName}==<X.Y.Z>".`,
        references: [OWASP_MCP_URL, 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
      }));
    }
  }

  return findings;
}
