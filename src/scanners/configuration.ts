import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

export function scanConfiguration(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command || '';

  // Check if server is disabled
  if (config.disabled) {
    findings.push(createFinding({
      title: 'Disabled Server',
      description: `Server "${name}" is disabled in the configuration.`,
      severity: 'info',
      category: 'configuration',
      serverName: name,
      remediation: 'No action needed. This server is not active.',
    }));
    return findings;
  }

  // Check for missing command
  if (!cmd) {
    findings.push(createFinding({
      title: 'Missing Command',
      description: `Server "${name}" has no command specified.`,
      severity: 'high',
      category: 'configuration',
      serverName: name,
      remediation: 'Add a valid command to the server configuration.',
    }));
    return findings;
  }

  // Check for absolute path to local executables (potential tampering)
  if (cmd.startsWith('/') || cmd.startsWith('~')) {
    findings.push(createFinding({
      title: 'Local Executable Path',
      description: `Server uses a local executable at "${cmd}". If this path is user-writable, an attacker could replace the binary.`,
      severity: 'medium',
      category: 'configuration',
      serverName: name,
      remediation: 'Ensure the executable path is not user-writable. Consider using a package manager instead.',
    }));
  }

  // Check for shell metacharacters in arguments (potential injection)
  const args = config.args || [];
  const dangerousChars = [';', '|', '&', '$(', '`', '&&', '||', '>'];
  for (const arg of args) {
    for (const char of dangerousChars) {
      if (arg.includes(char)) {
        findings.push(createFinding({
          title: 'Shell Metacharacter in Arguments',
          description: `Argument "${arg}" contains shell metacharacter "${char}". This could indicate or enable command injection.`,
          severity: 'high',
          category: 'configuration',
          serverName: name,
          remediation: 'Review this argument carefully. Avoid shell metacharacters in MCP server arguments.',
          references: ['MCP-05: Prompt Injection via Tools'],
        }));
      }
    }
  }

  // Check for curl/wget usage (data exfil risk)
  if (cmd === 'curl' || cmd === 'wget') {
    findings.push(createFinding({
      title: 'HTTP Client as MCP Server',
      description: `Server command is "${cmd}" which is an HTTP client. This could be used for data exfiltration.`,
      severity: 'high',
      category: 'data-exposure',
      serverName: name,
      remediation: 'Review the arguments carefully. Ensure no sensitive data is being sent to external endpoints.',
      references: ['MCP-07: Data Exfiltration'],
    }));
  }

  // Check for eval/exec patterns in Python servers
  if ((cmd === 'python' || cmd === 'python3') && args.some(a => a.includes('eval') || a.includes('exec'))) {
    findings.push(createFinding({
      title: 'Dynamic Code Execution Pattern',
      description: 'Python server arguments contain eval/exec patterns which could lead to code injection.',
      severity: 'critical',
      category: 'configuration',
      serverName: name,
      remediation: 'Avoid eval/exec in MCP server configurations. Use static imports and configurations.',
    }));
  }

  return findings;
}
