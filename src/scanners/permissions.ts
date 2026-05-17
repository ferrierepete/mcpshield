import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

const DANGEROUS_PATHS = [
  '/', '/home', '/etc', '/var', '/usr', '/root', '/boot', '/sys', '/proc',
  '/tmp', '/dev', '/var/run', '/run', '/opt',
  '~', '$HOME', '${HOME}',
];

const SENSITIVE_ENV_KEYS = [
  'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID',
  'GH_TOKEN', 'GITHUB_TOKEN', 'GITHUB_PAT',
  'OPENAI_API_KEY', 'ANTHROPIC_API_KEY',
  'DATABASE_URL', 'DB_PASSWORD',
  'PRIVATE_KEY', 'SECRET_KEY',
  'STRIPE_SECRET_KEY', 'SLACK_TOKEN',
  'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID',
  'HEROKU_API_KEY',
  'TWILIO_AUTH_TOKEN',
  'SENDGRID_API_KEY',
  'MAILGUN_API_KEY',
  'CLOUDFLARE_API_TOKEN',
  'DIGITALOCEAN_TOKEN',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'NPM_TOKEN', 'PYPI_API_TOKEN',
  'VAULT_TOKEN',
  'KUBERNETES_TOKEN', 'SERVICE_ACCOUNT_KEY',
  'JWT_SECRET', 'ENCRYPTION_KEY',
];

const SECRET_VALUE_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /^AKIA[A-Z0-9]{16}$/, name: 'AWS Access Key' },
  { pattern: /^ghp_[a-zA-Z0-9]{36}$/, name: 'GitHub Personal Access Token' },
  { pattern: /^gho_[a-zA-Z0-9]{36}$/, name: 'GitHub OAuth Token' },
  { pattern: /^xox[bpors]-[a-zA-Z0-9-]+/, name: 'Slack Token' },
  { pattern: /^sk_(live|test)_[a-zA-Z0-9]+/, name: 'Stripe Secret Key' },
];


export function scanPermissions(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const args = (config.args || []).join(' ');
  const env = config.env || {};

  // Check for filesystem access to dangerous paths
  // Use word-boundary matching to avoid false positives from normal paths like /home/user/docs
  for (const dangerousPath of DANGEROUS_PATHS) {
    // Match dangerousPath as a standalone arg or ending at word boundary
    const pattern = dangerousPath === '/'
      ? /(?:^|\s)\/(?:$|\s)/  // bare "/" as its own arg
      : new RegExp(`(?:^|\\s)${dangerousPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|\\s)`);
    if (pattern.test(args)) {
      findings.push(createFinding({
        title: 'Broad Filesystem Access',
        description: `Server has access to path "${dangerousPath}". This grants read/write access to sensitive system directories.`,
        severity: 'critical',
        category: 'permissions',
        serverName: name,
        remediation: `Restrict filesystem access to only the specific directories this server needs. Replace "${dangerousPath}" with a scoped path.`,
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
      }));
      break; // One finding per server for this category
    }
  }

  // Check for exposed secrets in environment variables
  const exposedSecrets = Object.keys(env).filter(key =>
    SENSITIVE_ENV_KEYS.some(s => key.toUpperCase().includes(s) || s.includes(key.toUpperCase()))
  );

  if (exposedSecrets.length > 0) {
    findings.push(createFinding({
      title: 'Sensitive Credentials in Config',
      description: `Found ${exposedSecrets.length} sensitive environment variable(s): ${exposedSecrets.join(', ')}. These are stored in plaintext in the MCP config file.`,
      severity: 'high',
      category: 'authentication',
      serverName: name,
      remediation: 'Use a secrets manager or environment variable injection instead of hardcoding credentials in the config file.',
      references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure'],
    }));
  }

  // Check env values against known secret patterns
  for (const [key, value] of Object.entries(env)) {
    if (!value || value.includes('${')) continue;
    for (const { pattern, name } of SECRET_VALUE_PATTERNS) {
      if (pattern.test(value)) {
        findings.push(createFinding({
          title: 'Secret Value Pattern Detected',
          description: `Environment variable "${key}" contains a value matching ${name}. Hardcoded secrets in config files are a security risk.`,
          severity: 'high',
          category: 'authentication',
          serverName: name,
          remediation: 'Use a secrets manager or environment variable injection instead of hardcoding credentials in the config file.',
          references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure'],
        }));
        break;
      }
    }
  }

  // Check for environment variables with overly permissive values
  for (const [key, value] of Object.entries(env)) {
    if (value === '' || value === '*') {
      findings.push(createFinding({
        title: 'Empty or Wildcard Environment Variable',
        description: `Environment variable "${key}" has a "${value === '' ? 'empty' : 'wildcard'}" value, which may indicate misconfiguration.`,
        severity: 'low',
        category: 'configuration',
        serverName: name,
        remediation: `Set a specific value for "${key}" or remove it if unused.`,
        references: [OWASP_MCP_URL],
      }));
    }
  }

  // Check for network-accessible configurations
  if (args.includes('0.0.0.0') || args.includes('::') || args.includes(':::') || args.includes('--host 0.0.0.0')) {
    findings.push(createFinding({
      title: 'Network Binding to All Interfaces',
      description: 'Server is configured to bind to all network interfaces (0.0.0.0, ::, or :::). This exposes the server to all network connections.',
      severity: 'high',
      category: 'network',
      serverName: name,
      remediation: 'Bind to localhost (127.0.0.1) unless remote access is explicitly needed. Use authentication if binding to non-localhost.',
      references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  // Check for IPv6 ::: binding with port (e.g. [::]:8080) — any-address with explicit port
  if (args.includes(':::')) {
    findings.push(createFinding({
      title: 'IPv6 Any-Address Binding with Port',
      description: 'Server is configured to bind to IPv6 any-address (:::) with a port. This exposes the server to all IPv6 and often IPv4 connections.',
      severity: 'critical',
      category: 'network',
      serverName: name,
      remediation: 'Bind to localhost (::1) unless remote access is explicitly needed. Use authentication if binding to non-localhost.',
      references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  // Check for --allow-all or overly permissive flags
  const permissiveFlags = ['--allow-all', '--no-sandbox', '--disable-sandbox', '--unsafe'];
  for (const flag of permissiveFlags) {
    if (args.includes(flag)) {
      findings.push(createFinding({
        title: 'Overly Permissive Runtime Flag',
        description: `Server uses "${flag}" which disables security sandboxing or grants blanket permissions.`,
        severity: 'high',
        category: 'permissions',
        serverName: name,
        remediation: `Remove "${flag}" and use specific, scoped permissions instead.`,
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep'],
      }));
    }
  }

  const cmdParts = (config.args || []);
  if (config.command === 'sudo' || cmdParts.some(a => a === 'sudo')) {
    findings.push(createFinding({
      title: 'Privilege Escalation via sudo',
      description: 'Server executes commands with sudo, granting root-level privileges. This is a severe security risk.',
      severity: 'critical',
      category: 'permissions',
      serverName: name,
      remediation: 'Remove sudo and run the MCP server with the minimum required privileges instead.',
      references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  const ownershipCmds = ['chmod', 'chown'];
  for (const ownershipCmd of ownershipCmds) {
    if (cmdParts.some(a => a === ownershipCmd)) {
      findings.push(createFinding({
        title: `Permission Modification via ${ownershipCmd}`,
        description: `Server uses "${ownershipCmd}" to modify file permissions or ownership, which can lead to privilege escalation.`,
        severity: 'high',
        category: 'permissions',
        serverName: name,
        remediation: `Remove "${ownershipCmd}" from the server configuration. Use pre-configured file permissions instead.`,
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep'],
      }));
    }
  }

  const pathTraversalPatterns = ['/..',  '/./', '//'];
  for (const pattern of pathTraversalPatterns) {
    if (cmdParts.some(a => a.includes(pattern))) {
      findings.push(createFinding({
        title: 'Path Traversal Pattern Detected',
        description: `Server arguments contain path traversal pattern "${pattern}". This can be used to escape intended directory boundaries.`,
        severity: 'high',
        category: 'permissions',
        serverName: name,
        remediation: 'Use absolute, normalized paths without traversal sequences. Validate and sanitize all path arguments.',
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep'],
      }));
      break;
    }
  }

  // Check for auto-approved tools combined with broad permissions
  const hasAutoApprove = (config.autoApprove?.length ?? 0) > 0;
  const hasAlwaysAllow = (config.alwaysAllow?.length ?? 0) > 0;
  if (hasAutoApprove || hasAlwaysAllow) {
    const hasBroadFilesystem = DANGEROUS_PATHS.some(dangerousPath => {
      const pattern = dangerousPath === '/'
        ? /(?:^|\s)\/(?:$|\s)/
        : new RegExp(`(?:^|\\s)${dangerousPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:$|\\s)`);
      return pattern.test(args);
    });
    const hasBroadNetwork = args.includes('0.0.0.0') || args.includes('::') || args.includes(':::');
    if (hasBroadFilesystem || hasBroadNetwork) {
      const toolList = hasAutoApprove ? config.autoApprove! : config.alwaysAllow!;
      findings.push(createFinding({
        title: 'Auto-Approved Tools with Broad Permissions',
        description: `Server has auto-approved tools (${toolList.join(', ')}) combined with broad filesystem access or network binding. This bypasses user confirmation for sensitive operations.`,
        severity: 'high',
        category: 'permissions',
        serverName: name,
        remediation: 'Remove auto-approve/alwaysAllow for tools that access sensitive resources, or restrict filesystem and network access to specific scoped paths.',
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep'],
      }));
    }
  }

  return findings;
}
