import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

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
      references: [OWASP_MCP_URL],
    }));
    return findings;
  }

  // Check for missing command (skip if url is present — transport-only servers)
  if (!cmd && !config.url) {
    findings.push(createFinding({
      title: 'Missing Command',
      description: `Server "${name}" has no command specified.`,
      severity: 'high',
      category: 'configuration',
      serverName: name,
      remediation: 'Add a valid command to the server configuration.',
      references: [OWASP_MCP_URL],
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
      references: [OWASP_MCP_URL],
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
          references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
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
      references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
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
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // --- Shell interpreter & metacharacter detection rules (T5) ---

  const cmdBase = cmd.split('/').pop() || cmd;

  // Rule 1: Shell interpreters (bash, sh, zsh, dash, ksh, csh, tcsh) as command
  const shellInterpreters = ['bash', 'sh', 'zsh', 'dash', 'ksh', 'csh', 'tcsh'];
  if (shellInterpreters.includes(cmdBase)) {
    findings.push(createFinding({
      title: 'Shell Interpreter Used as Command',
      description: `Server command is "${cmd}", a shell interpreter. This grants the server direct shell access, increasing command injection risk.`,
      severity: 'high',
      category: 'configuration',
      serverName: name,
      remediation: 'Avoid using shell interpreters as MCP server commands. Use the target runtime directly (e.g., npx, node, python).',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 2: Shell -c/-e flags on interpreters (node, python, perl, ruby, php)
  const codeInterpreters = ['node', 'python', 'python3', 'perl', 'ruby', 'php'];
  if (codeInterpreters.includes(cmdBase) && args.some(a => a === '-c' || a === '-e')) {
    findings.push(createFinding({
      title: 'Direct Code Execution via Interpreter Flag',
      description: `Server uses "${cmd}" with a command execution flag (-c or -e), enabling arbitrary code execution from arguments.`,
      severity: 'critical',
      category: 'configuration',
      serverName: name,
      remediation: 'Avoid command execution flags (-c, -e) in MCP server configurations. Use script files instead.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 3: Newline injection (\n or \r in args)
  for (const arg of args) {
    if (arg.includes('\n') || arg.includes('\r')) {
      const sanitized = arg.replace(/\n/g, '\\n').replace(/\r/g, '\\r');
      findings.push(createFinding({
        title: 'Newline Injection in Arguments',
        description: `Argument "${sanitized}" contains newline characters. This could be used to inject additional commands or bypass argument parsing.`,
        severity: 'high',
        category: 'configuration',
        serverName: name,
        remediation: 'Remove newline characters from arguments. They may indicate command injection attempts.',
        references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
      }));
    }
  }

  // Rule 4: Input redirect (< standalone token in args)
  if (args.some(a => a === '<')) {
    findings.push(createFinding({
      title: 'Input Redirect in Arguments',
      description: 'Arguments contain a standalone input redirect ("<"). This could be used to read arbitrary files into the command.',
      severity: 'high',
      category: 'configuration',
      serverName: name,
      remediation: 'Remove input redirect operators from MCP server arguments.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 5: Append redirect (>> in args)
  for (const arg of args) {
    if (arg.includes('>>')) {
      findings.push(createFinding({
        title: 'Append Redirect in Arguments',
        description: `Argument "${arg}" contains an append redirect (">>"). This could be used to append data to arbitrary files.`,
        severity: 'high',
        category: 'configuration',
        serverName: name,
        remediation: 'Remove append redirect operators from MCP server arguments.',
        references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
      }));
    }
  }

  // Rule 6: $VAR expansion (dollar + alphanum NOT inside $(...))
  for (const arg of args) {
    // Strip $(...) command substitution blocks before checking for $VAR
    const stripped = arg.replace(/\$\([^)]*\)/g, '');
    const varMatches = stripped.match(/\$[A-Za-z_][A-Za-z0-9_]*/g);
    if (varMatches) {
      findings.push(createFinding({
        title: 'Shell Variable Expansion in Arguments',
        description: `Argument "${arg}" contains shell variable reference(s) (${varMatches.join(', ')}). This could be used to exfiltrate environment variables.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: 'Review shell variable references in arguments. Ensure they cannot leak sensitive environment variables.',
        references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
      }));
    }
  }

  // Rule 7: bash -c / sh -c specifically
  if ((cmdBase === 'bash' || cmdBase === 'sh') && args.includes('-c')) {
    findings.push(createFinding({
      title: 'Shell Interpreter with Command Flag',
      description: `Server uses "${cmd} -c", which allows direct shell command execution from arguments. This is a critical command injection vector.`,
      severity: 'critical',
      category: 'configuration',
      serverName: name,
      remediation: 'Never use "bash -c" or "sh -c" in MCP server configurations. Use the intended runtime directly.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 8: /usr/bin/env wrapper
  if (cmdBase === 'env' || cmd === '/usr/bin/env') {
    findings.push(createFinding({
      title: 'Environment Wrapper Used as Command',
      description: `Server command is "${cmd}", which uses the env wrapper. This can be used to bypass command restrictions or modify the execution environment.`,
      severity: 'medium',
      category: 'configuration',
      serverName: name,
      remediation: 'Avoid using env wrappers in MCP server configurations. Specify the target command directly.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 9: node -e / node --eval
  if (cmdBase === 'node' && args.some(a => a === '-e' || a === '--eval')) {
    findings.push(createFinding({
      title: 'Direct Code Execution via Node.js Eval',
      description: `Server uses "node" with -e or --eval flag, enabling direct JavaScript code execution from arguments.`,
      severity: 'critical',
      category: 'configuration',
      serverName: name,
      remediation: 'Avoid using "node -e" or "node --eval" in MCP server configurations. Use script files instead.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Rule 10: node --require / -r preload
  if (cmdBase === 'node' && args.some(a => a === '-r' || a === '--require')) {
    findings.push(createFinding({
      title: 'Node.js Module Preload',
      description: `Server uses "node" with -r or --require flag, which preloads modules before the main script. This could be used to inject malicious code.`,
      severity: 'high',
      category: 'configuration',
      serverName: name,
      remediation: 'Review the preloaded module carefully. Ensure it comes from a trusted source.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
    }));
  }

  // Check for ${input:...} dynamic input patterns (VS Code variable substitution)
  const inputPattern = /\$\{input:[^}]+\}/;
  for (const arg of args) {
    if (inputPattern.test(arg)) {
      const matches = arg.match(/\$\{input:[^}]+\}/g) || [];
      findings.push(createFinding({
        title: 'Dynamic Input from VS Code Variables',
        description: `Argument "${arg}" contains dynamic input variable(s) (${matches.join(', ')}). Dynamic input from VS Code variables cannot be statically analyzed for security risks.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: 'Review dynamic input variables manually. Ensure they cannot be used to inject malicious values at runtime.',
        references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution'],
      }));
      break;
    }
  }

  return findings;
}
