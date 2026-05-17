import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';
import { getServerType } from './config-loader.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

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

interface PypiPackageInfo {
  info: {
    author?: string;
    author_email?: string;
    project_urls?: Record<string, string>;
  };
  releases: Record<string, Array<{ upload_time?: string }>>;
}

interface NpmRegistryCheckResult {
  exists: boolean;
  packageInfo?: NpmPackageInfo;
  error?: string;
}

interface PypiRegistryCheckResult {
  exists: boolean;
  packageInfo?: PypiPackageInfo;
  error?: string;
}

const REGISTRY_TIMEOUT_MS = 5000;

async function fetchNpmPackageInfo(packageName: string): Promise<NpmRegistryCheckResult> {
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
      return { exists: false, error: `HTTP ${response.status}` };
    }

    const data = (await response.json()) as NpmPackageInfo;
    return { exists: true, packageInfo: data };
  } catch (e: any) {
    return { exists: false, error: e.message };
  }
}

async function fetchPypiPackageInfo(packageName: string): Promise<PypiRegistryCheckResult> {
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

    const data = (await response.json()) as PypiPackageInfo;
    return { exists: true, packageInfo: data };
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

function getEarliestUploadTime(data: PypiPackageInfo): string | null {
  let earliest: string | null = null;
  for (const files of Object.values(data.releases)) {
    for (const file of files) {
      if (file.upload_time) {
        if (!earliest || file.upload_time < earliest) {
          earliest = file.upload_time;
        }
      }
    }
  }
  return earliest;
}

function pypiHasSourceRepo(data: PypiPackageInfo): boolean {
  const urls = data.info.project_urls;
  if (!urls) return false;
  return 'Repository' in urls || 'Source' in urls;
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
        references: result.error ? [OWASP_MCP_URL] : [OWASP_MCP_URL, 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering', 'MCP09:2025 - Shadow MCP Servers'],
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
            references: [OWASP_MCP_URL, 'MCP09:2025 - Shadow MCP Servers'],
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
            references: [OWASP_MCP_URL],
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
          references: [OWASP_MCP_URL],
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
          references: [OWASP_MCP_URL],
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
        references: result.error ? [OWASP_MCP_URL] : [OWASP_MCP_URL, 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering'],
      }));
      return findings;
    }

    if (result.packageInfo && !result.error) {
      const data = result.packageInfo;
      const OWASP_SUPPLY_CHAIN = 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering';
      const earliestUpload = getEarliestUploadTime(data);
      if (earliestUpload) {
        const firstReleaseDate = new Date(earliestUpload);
        const daysSinceFirstRelease = (Date.now() - firstReleaseDate.getTime()) / (1000 * 60 * 60 * 24);
        if (daysSinceFirstRelease < 30) {
          findings.push(createFinding({
            title: 'Recently Published PyPI Package',
            description: `Package "${pkgName}" was first released ${Math.floor(daysSinceFirstRelease)} day(s) ago. New packages have less community review and may pose higher supply chain risk.`,
            severity: 'medium',
            category: 'supply-chain',
            serverName: name,
            remediation: 'Carefully review the source code, check the maintainer history, and verify this is the intended package.',
            references: [OWASP_MCP_URL, OWASP_SUPPLY_CHAIN],
          }));
        }
      }

      const versionCount = Object.keys(data.releases).length;
      if (versionCount <= 1) {
        findings.push(createFinding({
          title: 'Single-Version PyPI Package',
          description: `Package "${pkgName}" has only ${versionCount} published version(s). This could indicate a placeholder or abandoned package.`,
          severity: 'low',
          category: 'supply-chain',
          serverName: name,
          remediation: 'Verify the package is actively maintained and has a legitimate purpose.',
          references: [OWASP_MCP_URL, OWASP_SUPPLY_CHAIN],
        }));
      }

      if (!pypiHasSourceRepo(data)) {
        findings.push(createFinding({
          title: 'PyPI Package Missing Source Repository',
          description: `Package "${pkgName}" has no linked source repository (no Repository or Source URL in project_urls). Legitimate packages typically link to their source code.`,
          severity: 'low',
          category: 'supply-chain',
          serverName: name,
          remediation: 'Check for the package source code manually. Be cautious of packages without transparent source.',
          references: [OWASP_MCP_URL, OWASP_SUPPLY_CHAIN],
        }));
      }

      if (data.info.author && !pypiHasSourceRepo(data)) {
        findings.push(createFinding({
          title: 'Single Author PyPI Package Without Source Repo',
          description: `Package "${pkgName}" has a single author ("${data.info.author}") and no linked source repository. This combination increases supply chain risk.`,
          severity: 'medium',
          category: 'supply-chain',
          serverName: name,
          remediation: 'Verify the author\'s identity and review any available source code before trusting this package.',
          references: [OWASP_MCP_URL, OWASP_SUPPLY_CHAIN],
        }));
      }
    }
  }

  return findings;
}
