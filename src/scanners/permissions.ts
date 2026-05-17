import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const DANGEROUS_PATHS = [
  '/', '/home', '/etc', '/var', '/usr', '/root', '/boot', '/sys', '/proc',
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
        references: ['MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
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
      references: ['MCP01:2025 - Token Mismanagement & Secret Exposure'],
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
          references: ['MCP01:2025 - Token Mismanagement & Secret Exposure'],
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
      }));
    }
  }

  // Check for network-accessible configurations
  if (args.includes('0.0.0.0') || args.includes('::') || args.includes('--host 0.0.0.0')) {
    findings.push(createFinding({
      title: 'Network Binding to All Interfaces',
      description: 'Server is configured to bind to all network interfaces (0.0.0.0 or ::). This exposes the server to all network connections.',
      severity: 'high',
      category: 'network',
      serverName: name,
      remediation: 'Bind to localhost (127.0.0.1) unless remote access is explicitly needed. Use authentication if binding to non-localhost.',
      references: ['MCP07:2025 - Insufficient Authentication & Authorization'],
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
        references: ['MCP03:2025 - Privilege Escalation via Scope Creep'],
      }));
    }
  }

  return findings;
}
