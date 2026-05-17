import { MCPServerConfig, Finding } from '../types/index.js';
import { createFinding } from '../utils/helpers.js';

const OWASP_MCP_URL = 'https://owasp.org/www-project-mcp-top-10/';

const DANGEROUS_DOCKER_FLAGS = [
  '--privileged',
  '--cap-add=ALL',
  '--cap-add=SYS_ADMIN',
  '--cap-add=NET_ADMIN',
  '--cap-add=CHOWN',
  '--cap-add=DAC_OVERRIDE',
  '--cap-add=SETUID',
  '--cap-add=SETGID',
  '--net=host',
  '--network=host',
  '--pid=host',
  '--ipc=host',
  '--security-opt seccomp=unconfined',
  '--security-opt apparmor=unconfined',
  '--security-opt label=disable',
  '--user root',
  '--userns=host',
  '--uts=host',
  '--cgroupns=host',
  '--device',
  '--dns',
  '--add-host',
  '--entrypoint',
];

const DANGEROUS_CAP_ADD_VALUES = ['ALL', 'NET_ADMIN', 'SYS_ADMIN', 'CHOWN', 'DAC_OVERRIDE', 'SETUID', 'SETGID'];

const SENSITIVE_DOCKER_MOUNTS = [
  '/:/host',
  '/etc:/etc',
  '/var/run/docker.sock',
  '/root',
  '/home',
  '/proc',
  '/sys',
  '/dev',
  '/tmp',
  '/var',
  '/run',
];

const SENSITIVE_MOUNT_TARGETS = ['/', '/proc', '/sys', '/dev', '/tmp', '/var', '/run', '/etc', '/root', '/home'];

export function scanTransport(name: string, config: MCPServerConfig): Finding[] {
  const findings: Finding[] = [];
  const cmd = config.command?.toLowerCase() || '';
  const args = config.args || [];
  const argsStr = args.join(' ');

  // --- Docker-specific checks ---
  if (cmd === 'docker' || cmd.includes('docker')) {
    findings.push(...scanDockerConfig(name, cmd, args, argsStr));
  }

  // --- HTTP/SSE transport checks ---
  if (config.url) {
    findings.push(...scanHttpTransport(name, config));
  }

  // --- Transport type validation ---
  if (config.type === 'http' || config.type === 'sse') {
    if (!config.url) {
      findings.push(createFinding({
        title: 'Transport Type Specified Without URL',
        description: `Server has type "${config.type}" but no "url" field configured. The transport type requires a URL to connect to.`,
        severity: 'medium',
        category: 'configuration',
        serverName: name,
        remediation: `Add a "url" field for the ${config.type} transport, or remove the "type" field if not needed.`,
        references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
      }));
    }
  }

  if (config.type === 'stdio' && config.url) {
    findings.push(createFinding({
      title: 'URL Field Ignored for stdio Transport',
      description: `Server has type "stdio" with a "url" field. The URL is ignored for stdio transport and may indicate a misconfiguration.`,
      severity: 'info',
      category: 'configuration',
      serverName: name,
      remediation: 'Remove the "url" field when using stdio transport, or change the transport type.',
      references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  return findings;
}

function scanDockerConfig(name: string, cmd: string, args: string[], argsStr: string): Finding[] {
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
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP05:2025 - Command Injection & Execution'],
      }));
    }
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--cap-add' && args[i + 1]) {
      const capValue = args[i + 1].toUpperCase();
      if (DANGEROUS_CAP_ADD_VALUES.includes(capValue)) {
        findings.push(createFinding({
          title: 'Dangerous Docker Capability',
          description: `Docker container uses "--cap-add ${capValue}" which grants elevated privileges and weakens container isolation.`,
          severity: 'critical',
          category: 'permissions',
          serverName: name,
          remediation: `Remove "--cap-add ${capValue}" and use the minimum required capabilities.`,
          references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP05:2025 - Command Injection & Execution'],
        }));
      }
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
        references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
      }));
    }
  }

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--mount' && args[i + 1]) {
      const mountSpec = args[i + 1];
      const sourceMatch = mountSpec.match(/source=([^,]+)/);
      const targetMatch = mountSpec.match(/target=([^,]+)/);
      if (sourceMatch) {
        const source = sourceMatch[1];
        for (const sensitive of SENSITIVE_MOUNT_TARGETS) {
          if (source === sensitive || source.startsWith(sensitive + '/')) {
            findings.push(createFinding({
              title: 'Sensitive Docker Mount Path',
              description: `Docker --mount binds sensitive host path "${source}" into the container.`,
              severity: 'high',
              category: 'permissions',
              serverName: name,
              remediation: 'Mount only the specific directories the server needs. Avoid mounting system directories.',
              references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
            }));
            break;
          }
        }
      }
      if (targetMatch) {
        const target = targetMatch[1];
        if (target === '/') {
          findings.push(createFinding({
            title: 'Sensitive Docker Mount Target',
            description: `Docker --mount targets "/" which could overwrite critical container paths.`,
            severity: 'high',
            category: 'permissions',
            serverName: name,
            remediation: 'Use a specific mount target instead of "/".',
            references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP05:2025 - Command Injection & Execution'],
          }));
        }
      }
    }
  }

  for (let i = 0; i < args.length; i++) {
    if ((args[i] === '-v' || args[i] === '--volume') && args[i + 1]) {
      const volSpec = args[i + 1];
      const parts = volSpec.split(':');
      if (parts.length >= 2 && parts[1] === '/') {
        findings.push(createFinding({
          title: 'Sensitive Docker Volume Mount',
          description: `Docker container mounts "${volSpec}" which targets the container root filesystem.`,
          severity: 'high',
          category: 'permissions',
          serverName: name,
          remediation: 'Mount only the specific directories the server needs. Avoid mounting to container root "/".',
          references: [OWASP_MCP_URL, 'MCP03:2025 - Privilege Escalation via Scope Creep', 'MCP07:2025 - Insufficient Authentication & Authorization'],
      }));
      }
    }
  }

  const hasComposeArg = args.some(a => a === 'compose');
  if (hasComposeArg || cmd === 'docker-compose') {
    findings.push(createFinding({
      title: 'Docker Compose Usage Detected',
      description: 'Docker Compose is used which may orchestrate multiple containers with shared networks and volumes, increasing the attack surface.',
      severity: 'medium',
      category: 'configuration',
      serverName: name,
      remediation: 'Review the Docker Compose configuration for security best practices. Ensure no sensitive mounts or privileged containers are used.',
      references: [OWASP_MCP_URL, 'MCP05:2025 - Command Injection & Execution', 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  // Check for unsigned/unverified images
  const runIdx = args.indexOf('run');
  if (runIdx !== -1) {
    // Skip flags and their values to find the actual image name
    const postRunArgs = args.slice(runIdx + 1);
    let imageArg: string | undefined;
    const flagsWithValues = new Set(['-p', '--publish', '-v', '--volume', '-e', '--env', '--name', '-w', '--workdir', '--network', '--net', '-m', '--memory', '--mount', '--cap-add', '--device', '--dns', '--add-host', '--entrypoint']);
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
          references: [OWASP_MCP_URL, 'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering', 'MCP09:2025 - Shadow MCP Servers'],
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
            references: [OWASP_MCP_URL, 'MCP07:2025 - Insufficient Authentication & Authorization'],
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
      references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure', 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  if (url.startsWith('ws://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
    findings.push(createFinding({
      title: 'Insecure WebSocket Transport',
      description: `Server connects via unencrypted WebSocket (ws://) to "${url}". WebSocket traffic can be intercepted.`,
      severity: 'high',
      category: 'network',
      serverName: name,
      remediation: 'Use secure WebSockets (wss://) for all remote MCP server connections.',
      references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure', 'MCP07:2025 - Insufficient Authentication & Authorization'],
    }));
  }

  const credentialPattern = /:\/\/[^:]+:[^@]+@/;
  if (credentialPattern.test(url)) {
    findings.push(createFinding({
      title: 'URL Contains Embedded Credentials',
      description: `Server URL "${url}" contains embedded credentials (user:pass@). Credentials in URLs are exposed in logs and config files.`,
      severity: 'high',
      category: 'data-exposure',
      serverName: name,
      remediation: 'Move credentials to environment variables or a secrets manager instead of embedding in the URL.',
      references: [OWASP_MCP_URL, 'MCP01:2025 - Token Mismanagement & Secret Exposure', 'MCP07:2025 - Insufficient Authentication & Authorization'],
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
      references: [OWASP_MCP_URL, 'MCP09:2025 - Shadow MCP Servers'],
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
      references: [OWASP_MCP_URL],
    }));
  }

  return findings;
}
