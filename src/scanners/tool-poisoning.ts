import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

export function scanToolPoisoning(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];

  findings.push(createFinding({
    title: 'Runtime Tool Poisoning Cannot Be Verified',
    description: `Static analysis cannot verify tool behavior at runtime. Tool poisoning (MCP02:2025) requires runtime analysis. Consider using MCPShield's watch mode for ongoing monitoring.`,
    severity: 'info',
    category: 'configuration',
    serverName: name,
    remediation: 'Use MCPShield watch mode and monitor tool descriptions for unexpected changes.',
    references: [OWASP_MCP_URL, 'MCP02:2025 - Tool Poisoning'],
  }));

  const autoApproved = config.autoApprove || config.alwaysAllow;

  if (autoApproved && Array.isArray(autoApproved) && autoApproved.length > 0) {
    findings.push(createFinding({
      title: 'Auto-Approved Tools Without User Confirmation',
      description: `Server has ${autoApproved.length} auto-approved tool(s): ${autoApproved.join(', ')}. These tools bypass user confirmation.`,
      severity: 'medium',
      category: 'configuration',
      serverName: name,
      remediation: 'Review auto-approved tools and restrict to only those that are safe to run without confirmation.',
      references: [OWASP_MCP_URL, 'MCP02:2025 - Tool Poisoning'],
    }));
  }

  if (
    config.url
    && !config.url.includes('localhost')
    && !config.url.includes('127.0.0.1')
    && (!config.headers || Object.keys(config.headers).length === 0)
  ) {
    findings.push(createFinding({
      title: 'Remote Server Without Authentication May Serve Poisoned Tool Definitions',
      description: `Remote server at ${config.url} has no authentication headers. An attacker could serve modified tool definitions.`,
      severity: 'medium',
      category: 'authentication',
      serverName: name,
      remediation: 'Add authentication headers to verify server identity.',
      references: [OWASP_MCP_URL, 'MCP02:2025 - Tool Poisoning'],
    }));
  }

  return findings;
}
