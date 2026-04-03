import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const DANGEROUS_DOCKER_FLAGS = [
  '--privileged',
  '--cap-add=ALL',
  '--cap-add=SYS_ADMIN',
  '--net=host',
  '--network=host',
  '--pid=host',
  '--ipc=host',
];

const SENSITIVE_DOCKER_MOUNTS = [
  '/:/host',
  '/etc:/etc',
  '/var/run/docker.sock',
  '/root',
  '/home',
];

export function scanTransport(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command?.toLowerCase() || '';
  const args = config.args || [];
  const argsStr = args.join(' ');

  // --- Docker-specific checks ---
  if (cmd === 'docker' || cmd.includes('docker')) {
    findings.push(...scanDockerConfig(name, args, argsStr));
  }

  // --- HTTP/SSE transport checks ---
  if (config.url) {
    findings.push(...scanHttpTransport(name, config));
  }

  return findings;
}

function scanDockerConfig(name: string, args: string[], argsStr: string): Finding[] {
  const findings: Finding[] = [];

  // Check for dangerous Docker flags
  for (const flag of DANGEROUS_DOCKER_FLAGS) {
    if (argsStr.includes(flag)) {
      findings.push(createFinding({
        title: 'Dangerous Docker Flag',
        description: `Docker container uses "${flag}" which grants elevated privileges and weakens container isolation.`,
        severity: 'critical',
        category: 'permissions',
        serverName: name,
        remediation: `Remove "${flag}" and use the minimum required capabilities. Prefer --cap-add with specific capabilities.`,
        references: ['MCP-06: Unauthorized Tool Access'],
      }));
    }
  }

  // Check for sensitive volume mounts
  for (const mount of SENSITIVE_DOCKER_MOUNTS) {
    if (argsStr.includes(mount)) {
      findings.push(createFinding({
        title: 'Sensitive Docker Volume Mount',
        description: `Docker container mounts "${mount}" which exposes sensitive host paths inside the container.`,
        severity: 'high',
        category: 'permissions',
        serverName: name,
        remediation: 'Mount only the specific directories the server needs. Avoid mounting system directories or the Docker socket.',
        references: ['MCP-06: Unauthorized Tool Access', 'MCP-07: Data Exfiltration'],
      }));
    }
  }

  // Check for unsigned/unverified images
  const runIdx = args.indexOf('run');
  if (runIdx !== -1) {
    // Skip flags and their values to find the actual image name
    const postRunArgs = args.slice(runIdx + 1);
    let imageArg: string | undefined;
    const flagsWithValues = new Set(['-p', '--publish', '-v', '--volume', '-e', '--env', '--name', '-w', '--workdir', '--network', '--net', '-m', '--memory']);
    for (let i = 0; i < postRunArgs.length; i++) {
      const a = postRunArgs[i];
      if (a.startsWith('-')) {
        // If this flag takes a value and isn't using = syntax, skip next arg too
        if (flagsWithValues.has(a) && !a.includes('=')) {
          i++; // skip the value
        }
        continue;
      }
      imageArg = a;
      break;
    }
    if (imageArg) {
      // No tag pinned (using :latest implicitly)
      if (!imageArg.includes(':') || imageArg.endsWith(':latest')) {
        findings.push(createFinding({
          title: 'Unpinned Docker Image Tag',
          description: `Docker image "${imageArg}" is not pinned to a specific version/digest. The :latest tag can change without notice.`,
          severity: 'high',
          category: 'supply-chain',
          serverName: name,
          remediation: `Pin the Docker image to a specific version or SHA256 digest, e.g. "${imageArg.split(':')[0]}@sha256:<digest>".`,
          references: ['MCP-01: Malicious Server Distribution', 'MCP-03: Rug Pull Attacks'],
        }));
      }
    }
  }

  // Check for exposed ports
  const portFlags = ['-p', '--publish'];
  for (let i = 0; i < args.length; i++) {
    if (portFlags.includes(args[i]) && args[i + 1]) {
      const portMapping = args[i + 1];
      if (portMapping.startsWith('0.0.0.0:') || !portMapping.includes('127.0.0.1')) {
        const isBroadBind = !portMapping.includes('127.0.0.1') && !portMapping.includes('localhost');
        if (isBroadBind) {
          findings.push(createFinding({
            title: 'Docker Port Exposed to All Interfaces',
            description: `Port mapping "${portMapping}" exposes the container to all network interfaces.`,
            severity: 'medium',
            category: 'network',
            serverName: name,
            remediation: `Bind to localhost: "127.0.0.1:${portMapping.split(':').pop()}" instead.`,
            references: ['MCP-04: Cross-Origin Resource Sharing'],
          }));
        }
      }
    }
  }

  return findings;
}

function scanHttpTransport(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const url = config.url || '';

  // Check for insecure HTTP (not HTTPS)
  if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
    findings.push(createFinding({
      title: 'Insecure HTTP Transport',
      description: `Server connects via unencrypted HTTP to "${url}". Data in transit (including credentials) can be intercepted.`,
      severity: 'high',
      category: 'network',
      serverName: name,
      remediation: 'Use HTTPS for all remote MCP server connections.',
      references: ['MCP-09: Token/Secret Exposure', 'MCP-07: Data Exfiltration'],
    }));
  }

  // Check for missing authentication headers on remote servers
  const isRemote = !url.includes('localhost') && !url.includes('127.0.0.1');
  if (isRemote && (!config.headers || Object.keys(config.headers).length === 0)) {
    findings.push(createFinding({
      title: 'Remote Server Without Authentication Headers',
      description: `Remote server at "${url}" has no authentication headers configured. Anyone who discovers this endpoint could use it.`,
      severity: 'medium',
      category: 'authentication',
      serverName: name,
      remediation: 'Add authentication headers (e.g., Authorization, X-API-Key) for remote MCP servers.',
      references: ['MCP-08: Identity Spoofing'],
    }));
  }

  // Check for IP-based URLs (potential C2 indicators)
  const ipPattern = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
  if (ipPattern.test(url) && !url.includes('127.0.0.1')) {
    findings.push(createFinding({
      title: 'IP-Based Server URL',
      description: `Server URL "${url}" uses a raw IP address instead of a domain name. This can indicate a temporary or malicious server.`,
      severity: 'medium',
      category: 'network',
      serverName: name,
      remediation: 'Use a domain name with valid TLS certificates instead of raw IP addresses.',
    }));
  }

  return findings;
}
