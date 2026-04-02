import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

// Known risky packages that have been associated with supply chain attacks or are common typosquat targets
const KNOWN_RISKY_PACKAGES = new Set([
  'mcptools', 'mcp-server-tools', 'mcp-toolkit',
  'ai-tools-mcp', 'mcp-all-in-one',
]);

// Packages that are well-known and trusted
const TRUSTED_PACKAGES = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-sqlite',
  '@anthropic/mcp-server',
]);

export function scanSupplyChain(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command?.toLowerCase() || '';
  const args = config.args || [];

  // Check for npx/bunx usage without pinned versions
  if (cmd === 'npx' || cmd === 'bunx') {
    const pkgArg = args.find(a => a.startsWith('@') || (!a.startsWith('-') && a !== cmd));
    if (pkgArg) {
      // Check if version is pinned
      const hasVersion = pkgArg.includes('@') && pkgArg.lastIndexOf('@') > 0;
      if (!hasVersion) {
        findings.push(createFinding({
          title: 'Unpinned Package Version',
          description: `Package "${pkgArg}" is used without a pinned version. This allows supply chain attacks via dependency confusion or typosquatting.`,
          severity: 'high',
          category: 'supply-chain',
          serverName: name,
          remediation: `Pin the package version: "${pkgArg}@<exact-version>" or use a lockfile.`,
          references: ['https://owasp.org/www-project-mcp-top/', 'MCP-10: Dependency Confusion'],
        }));
      }

      // Check against known risky packages
      if (KNOWN_RISKY_PACKAGES.has(pkgArg)) {
        findings.push(createFinding({
          title: 'Known Risky Package',
          description: `Package "${pkgArg}" is in the known-risky list. It may be a typosquat or has been associated with suspicious activity.`,
          severity: 'critical',
          category: 'supply-chain',
          serverName: name,
          remediation: `Remove this package and find a trusted alternative. Check npm for the package details.`,
        }));
      }

      // Warn about unverified packages
      if (!TRUSTED_PACKAGES.has(pkgArg) && !pkgArg.startsWith('@modelcontextprotocol/')) {
        findings.push(createFinding({
          title: 'Unverified Third-Party Package',
          description: `Package "${pkgArg}" is not in the verified list. Third-party MCP servers can execute arbitrary code on your machine.`,
          severity: 'medium',
          category: 'supply-chain',
          serverName: name,
          remediation: `Verify the package source, check its npm page, review its GitHub repo, and confirm the author is legitimate before trusting.`,
          references: ['MCP-01: Malicious Server Distribution', 'MCP-03: Rug Pull Attacks'],
        }));
      }
    }
  }

  // Check for uvx/pypi packages
  if (cmd === 'uvx' || cmd === 'python' || cmd === 'python3') {
    const pkgArg = args.find(a => !a.startsWith('-') && a !== cmd);
    if (pkgArg && !pkgArg.startsWith('/')) {
      findings.push(createFinding({
        title: 'Python Package Supply Chain Risk',
        description: `Python package "${pkgArg}" is used via "${cmd}". PyPI packages can execute arbitrary setup code.`,
        severity: 'medium',
        category: 'supply-chain',
        serverName: name,
        remediation: 'Pin the package version, verify the PyPI page, and check for known vulnerabilities.',
        references: ['MCP-10: Dependency Confusion'],
      }));
    }
  }

  return findings;
}
