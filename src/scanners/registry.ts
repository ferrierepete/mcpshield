import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';
import { getServerType } from './config-loader.js';

interface NpmPackageInfo {
  name: string;
  version?: string;
  time?: Record<string, string>;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, unknown>;
  maintainers?: Array<{ name: string; email?: string }>;
  homepage?: string;
  repository?: { url?: string };
  description?: string;
}

interface RegistryCheckResult {
  exists: boolean;
  packageInfo?: NpmPackageInfo;
  error?: string;
}

const REGISTRY_TIMEOUT_MS = 5000;

async function fetchNpmPackageInfo(packageName: string): Promise<RegistryCheckResult> {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (response.status === 404) {
      return { exists: false };
    }
    if (!response.ok) {
      return { exists: true, error: `HTTP ${response.status}` };
    }

    const data = (await response.json()) as NpmPackageInfo;
    return { exists: true, packageInfo: data };
  } catch (e: any) {
    return { exists: false, error: e.message };
  }
}

async function fetchPypiPackageInfo(packageName: string): Promise<RegistryCheckResult> {
  try {
    const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REGISTRY_TIMEOUT_MS);

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    if (response.status === 404) {
      return { exists: false };
    }
    if (!response.ok) {
      return { exists: false, error: `HTTP ${response.status}` };
    }

    return { exists: true };
  } catch (e: any) {
    return { exists: false, error: e.message };
  }
}

function extractPackageName(args: string[], cmd: string): string | null {
  const pkgArg = args.find(a => a.startsWith('@') || (!a.startsWith('-') && a !== cmd && a !== '-y'));
  if (!pkgArg) return null;
  // Strip version suffix / version range for lookup
  const atIdx = pkgArg.lastIndexOf('@');
  let name = atIdx > 0 ? pkgArg.substring(0, atIdx) : pkgArg;
  // Strip npm version range prefixes: ^1.0.0, ~2.0.0, >=3.0.0, >=4.0.0 <5.0.0, etc.
  name = name.replace(/^[\^~>=<]+/, '');
  return name;
}

export async function scanRegistry(name: string, config: MCPServerConfig): Promise<Finding[]> {
  const findings: Finding[] = [];
  const cmd = config.command?.toLowerCase() || '';
  const args = config.args || [];
  const serverType = getServerType(config);

  if (serverType === 'npm') {
    const pkgName = extractPackageName(args, cmd);
    if (!pkgName) return findings;

    const result = await fetchNpmPackageInfo(pkgName);

    if (!result.exists) {
      findings.push(createFinding({
        title: 'Package Not Found on npm',
        description: result.error
          ? `Could not verify package "${pkgName}" on npm (${result.error}). Treating as unverified.`
          : `Package "${pkgName}" does not exist on the npm registry. This could be a typo, a private package, or a dependency confusion attack vector.`,
        severity: result.error ? 'medium' : 'critical',
        category: 'supply-chain',
        serverName: name,
        remediation: result.error
          ? `Resolve the network error: ${result.error}. If offline, registry checks are unavailable.`
          : 'Verify the package name is correct. If this is a private package, ensure your npm configuration is set up correctly.',
        references: result.error ? [] : ['MCP-10: Dependency Confusion', 'MCP-01: Malicious Server Distribution'],
      }));
      return findings;
    }

    if (result.packageInfo && !result.error) {
      const info = result.packageInfo;

      // Check for very new packages (< 30 days old)
      if (info.time?.created) {
        const createdDate = new Date(info.time.created);
        const daysSinceCreation = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceCreation < 30) {
          findings.push(createFinding({
            title: 'Recently Published Package',
            description: `Package "${pkgName}" was first published ${Math.floor(daysSinceCreation)} day(s) ago. New packages have less community review and may pose higher supply chain risk.`,
            severity: 'medium',
            category: 'supply-chain',
            serverName: name,
            remediation: 'Carefully review the source code, check the maintainer history, and verify this is the intended package.',
            references: ['MCP-01: Malicious Server Distribution'],
          }));
        }
      }

      // Check for packages with very few versions (potential placeholder/squat)
      if (info.versions) {
        const versionCount = Object.keys(info.versions).length;
        if (versionCount <= 1) {
          findings.push(createFinding({
            title: 'Single-Version Package',
            description: `Package "${pkgName}" has only ${versionCount} published version(s). This could indicate a placeholder or abandoned package.`,
            severity: 'low',
            category: 'supply-chain',
            serverName: name,
            remediation: 'Verify the package is actively maintained and has a legitimate purpose.',
          }));
        }
      }

      // Check for missing repository information
      if (!info.repository?.url && !info.homepage) {
        findings.push(createFinding({
          title: 'Package Missing Source Repository',
          description: `Package "${pkgName}" has no linked source repository or homepage. Legitimate packages typically link to their source code.`,
          severity: 'low',
          category: 'supply-chain',
          serverName: name,
          remediation: 'Check for the package source code manually. Be cautious of packages without transparent source.',
        }));
      }

      // Check for single maintainer with no other packages
      if (info.maintainers && info.maintainers.length === 1) {
        findings.push(createFinding({
          title: 'Single Maintainer Package',
          description: `Package "${pkgName}" has only one maintainer (${info.maintainers[0].name}). Single-maintainer packages are more vulnerable to account takeover.`,
          severity: 'info',
          category: 'supply-chain',
          serverName: name,
          remediation: 'This is informational. Consider the maintainer\'s reputation and other published packages.',
        }));
      }
    }
  }

  if (serverType === 'pypi') {
    const pkgName = extractPackageName(args, cmd);
    if (!pkgName) return findings;

    const result = await fetchPypiPackageInfo(pkgName);

    if (!result.exists) {
      findings.push(createFinding({
        title: 'Package Not Found on PyPI',
        description: result.error
          ? `Could not verify package "${pkgName}" on PyPI (${result.error}). Treating as unverified.`
          : `Package "${pkgName}" does not exist on PyPI. This could be a typo, a private package, or a dependency confusion attack vector.`,
        severity: result.error ? 'medium' : 'critical',
        category: 'supply-chain',
        serverName: name,
        remediation: result.error
          ? `Resolve the network error: ${result.error}. If offline, registry checks are unavailable.`
          : 'Verify the package name is correct. If this is a private package, ensure your pip configuration is set up correctly.',
        references: result.error ? [] : ['MCP-10: Dependency Confusion'],
      }));
    }
  }

  return findings;
}
