import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { scanTransport } from '../src/scanners/transport.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import type { MCPServerConfig } from '../src/types/index.js';
import * as path from 'path';

const DOCKER_FIXTURE = path.join(__dirname, 'fixtures', 'docker-config.json');
const HTTP_FIXTURE = path.join(__dirname, 'fixtures', 'http-config.json');
const DOCKER_HARDENED_FIXTURE = path.join(__dirname, 'fixtures', 'docker-hardened-config.json');
const HTTP_HARDENED_FIXTURE = path.join(__dirname, 'fixtures', 'http-hardened-config.json');

describe('Transport Scanner', () => {
  describe('Docker scanning', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_FIXTURE);
    });

    it('should scan all docker servers', () => {
      expect(result.servers).toHaveLength(4);
    });

    it('should detect --privileged flag', () => {
      const server = result.servers.find(s => s.name === 'docker-privileged');
      expect(server).toBeDefined();
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('should detect sensitive volume mounts', () => {
      const server = result.servers.find(s => s.name === 'docker-privileged');
      const finding = server!.findings.find(f => f.title === 'Sensitive Docker Volume Mount');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect unpinned Docker image tag', () => {
      const server = result.servers.find(s => s.name === 'docker-exposed-port');
      const finding = server!.findings.find(f => f.title === 'Unpinned Docker Image Tag');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect Docker socket mount', () => {
      const server = result.servers.find(s => s.name === 'docker-socket');
      const finding = server!.findings.find(f => f.title === 'Sensitive Docker Volume Mount');
      expect(finding).toBeDefined();
    });

    it('should detect port exposed to all interfaces', () => {
      const server = result.servers.find(s => s.name === 'docker-exposed-port');
      const finding = server!.findings.find(f => f.title === 'Docker Port Exposed to All Interfaces');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });
  });

  describe('HTTP/SSE scanning', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(HTTP_FIXTURE);
      result = scanAllServers(config.mcpServers, HTTP_FIXTURE);
    });

    it('should detect insecure HTTP transport', () => {
      const server = result.servers.find(s => s.name === 'http-insecure');
      const finding = server!.findings.find(f => f.title === 'Insecure HTTP Transport');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should not flag HTTPS as insecure', () => {
      const server = result.servers.find(s => s.name === 'https-safe');
      const finding = server!.findings.find(f => f.title === 'Insecure HTTP Transport');
      expect(finding).toBeUndefined();
    });

    it('should detect remote server without auth headers', () => {
      const server = result.servers.find(s => s.name === 'remote-no-auth');
      const finding = server!.findings.find(f => f.title === 'Remote Server Without Authentication Headers');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should not flag remote server with auth headers', () => {
      const server = result.servers.find(s => s.name === 'https-safe');
      const finding = server!.findings.find(f => f.title === 'Remote Server Without Authentication Headers');
      expect(finding).toBeUndefined();
    });

    it('should detect IP-based server URL', () => {
      const server = result.servers.find(s => s.name === 'ip-based');
      const finding = server!.findings.find(f => f.title === 'IP-Based Server URL');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should not flag localhost HTTP as insecure', () => {
      const server = result.servers.find(s => s.name === 'localhost-http');
      const finding = server!.findings.find(f => f.title === 'Insecure HTTP Transport');
      expect(finding).toBeUndefined();
    });
  });

  describe('Docker security options', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_HARDENED_FIXTURE);
    });

    it('should detect --security-opt seccomp=unconfined', () => {
      const server = result.servers.find(s => s.name === 'docker-security-opt-seccomp');
      expect(server).toBeDefined();
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('seccomp=unconfined');
      expect(finding!.severity).toBe('critical');
    });

    it('should detect --security-opt apparmor=unconfined', () => {
      const server = result.servers.find(s => s.name === 'docker-security-opt-apparmor');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('apparmor=unconfined');
    });

    it('should detect --security-opt label=disable', () => {
      const server = result.servers.find(s => s.name === 'docker-security-opt-label');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('label=disable');
    });

    it('should detect --user root', () => {
      const server = result.servers.find(s => s.name === 'docker-user-root');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--user root');
    });

    it('should detect --userns=host', () => {
      const server = result.servers.find(s => s.name === 'docker-userns-host');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--userns=host');
    });

    it('should detect --uts=host', () => {
      const server = result.servers.find(s => s.name === 'docker-uts-host');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--uts=host');
    });

    it('should detect --cgroupns=host', () => {
      const server = result.servers.find(s => s.name === 'docker-cgroupns-host');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--cgroupns=host');
    });

    it('should detect --device', () => {
      const server = result.servers.find(s => s.name === 'docker-device');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--device');
    });

    it('should detect --dns', () => {
      const server = result.servers.find(s => s.name === 'docker-dns');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--dns');
    });

    it('should detect --add-host', () => {
      const server = result.servers.find(s => s.name === 'docker-add-host');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--add-host');
    });

    it('should detect --entrypoint', () => {
      const server = result.servers.find(s => s.name === 'docker-entrypoint');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('--entrypoint');
    });

    it('should include MCP05:2025 reference in Docker flag findings', () => {
      const server = result.servers.find(s => s.name === 'docker-user-root');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(finding).toBeDefined();
      expect(finding!.references).toEqual(
        expect.arrayContaining(['MCP05:2025 - Command Injection & Execution'])
      );
    });
  });

  describe('--cap-add space syntax', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_HARDENED_FIXTURE);
    });

    it('should detect --cap-add ALL (space-separated)', () => {
      const server = result.servers.find(s => s.name === 'docker-cap-add-space-all');
      expect(server).toBeDefined();
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Capability');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('ALL');
      expect(finding!.severity).toBe('critical');
    });

    it('should detect --cap-add NET_ADMIN (space-separated)', () => {
      const server = result.servers.find(s => s.name === 'docker-cap-add-space-net-admin');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Capability');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('NET_ADMIN');
    });

    it('should detect --cap-add CHOWN (space-separated)', () => {
      const server = result.servers.find(s => s.name === 'docker-cap-add-space-chown');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Capability');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('CHOWN');
    });

    it('should include MCP05:2025 reference in cap-add findings', () => {
      const server = result.servers.find(s => s.name === 'docker-cap-add-space-all');
      const finding = server!.findings.find(f => f.title === 'Dangerous Docker Capability');
      expect(finding!.references).toEqual(
        expect.arrayContaining(['MCP05:2025 - Command Injection & Execution'])
      );
    });
  });

  describe('--mount syntax', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_HARDENED_FIXTURE);
    });

    it('should detect --mount with sensitive source path', () => {
      const server = result.servers.find(s => s.name === 'docker-mount-sensitive');
      const finding = server!.findings.find(f => f.title === 'Sensitive Docker Mount Path');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('/proc');
      expect(finding!.severity).toBe('high');
    });

    it('should detect --mount targeting "/"', () => {
      const server = result.servers.find(s => s.name === 'docker-mount-target-root');
      const finding = server!.findings.find(f => f.title === 'Sensitive Docker Mount Target');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain('targets "/"');
      expect(finding!.severity).toBe('high');
    });

    it('should not flag --mount with safe paths', () => {
      const server = result.servers.find(s => s.name === 'docker-mount-safe');
      const mountFinding = server!.findings.find(f => f.title === 'Sensitive Docker Mount Path');
      expect(mountFinding).toBeUndefined();
    });
  });

  describe('Docker compose detection', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_HARDENED_FIXTURE);
    });

    it('should detect docker compose command', () => {
      const server = result.servers.find(s => s.name === 'docker-compose-cmd');
      const finding = server!.findings.find(f => f.title === 'Docker Compose Usage Detected');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should detect docker-compose hyphenated command', () => {
      const server = result.servers.find(s => s.name === 'docker-compose-hyphen');
      const finding = server!.findings.find(f => f.title === 'Docker Compose Usage Detected');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('medium');
    });

    it('should include MCP05:2025 and MCP07:2025 references in compose findings', () => {
      const server = result.servers.find(s => s.name === 'docker-compose-cmd');
      const finding = server!.findings.find(f => f.title === 'Docker Compose Usage Detected');
      expect(finding!.references).toEqual(
        expect.arrayContaining([
          'MCP05:2025 - Command Injection & Execution',
          'MCP07:2025 - Insufficient Authentication & Authorization',
        ])
      );
    });
  });

  describe('-v targeting root', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(DOCKER_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, DOCKER_HARDENED_FIXTURE);
    });

    it('should detect -v mount targeting container root "/"', () => {
      const server = result.servers.find(s => s.name === 'docker-v-target-root');
      const finding = server!.findings.find(f => f.title === 'Sensitive Docker Volume Mount');
      expect(finding).toBeDefined();
      expect(finding!.description).toContain(':/');
    });

    it('should not flag safe hardened Docker config', () => {
      const server = result.servers.find(s => s.name === 'docker-safe-hardened');
      const dangerousFinding = server!.findings.find(f => f.title === 'Dangerous Docker Flag');
      expect(dangerousFinding).toBeUndefined();
    });
  });

  describe('WebSocket and URL credentials', () => {
    let result: ReturnType<typeof scanAllServers>;

    beforeEach(() => {
      resetCounter();
      const config = loadConfig(HTTP_HARDENED_FIXTURE);
      result = scanAllServers(config.mcpServers, HTTP_HARDENED_FIXTURE);
    });

    it('should detect ws:// as insecure WebSocket', () => {
      const server = result.servers.find(s => s.name === 'ws-insecure');
      const finding = server!.findings.find(f => f.title === 'Insecure WebSocket Transport');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should not flag wss:// as insecure', () => {
      const server = result.servers.find(s => s.name === 'wss-safe');
      const finding = server!.findings.find(f => f.title === 'Insecure WebSocket Transport');
      expect(finding).toBeUndefined();
    });

    it('should not flag ws:// localhost as insecure', () => {
      const server = result.servers.find(s => s.name === 'ws-localhost');
      const finding = server!.findings.find(f => f.title === 'Insecure WebSocket Transport');
      expect(finding).toBeUndefined();
    });

    it('should detect URL with embedded credentials (https)', () => {
      const server = result.servers.find(s => s.name === 'url-credentials');
      const finding = server!.findings.find(f => f.title === 'URL Contains Embedded Credentials');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should detect URL with embedded credentials (http)', () => {
      const server = result.servers.find(s => s.name === 'url-credentials-http');
      const finding = server!.findings.find(f => f.title === 'URL Contains Embedded Credentials');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('should include MCP07:2025 reference in credential findings', () => {
      const server = result.servers.find(s => s.name === 'url-credentials');
      const finding = server!.findings.find(f => f.title === 'URL Contains Embedded Credentials');
      expect(finding!.references).toEqual(
        expect.arrayContaining(['MCP07:2025 - Insufficient Authentication & Authorization'])
      );
    });
  });

  describe('Transport type validation', () => {
    beforeEach(() => {
      resetCounter();
    });

    it('should detect http type without url', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'], type: 'http' };
      const findings = scanTransport('test', config);
      const f = findings.find(f => f.title === 'Transport Type Specified Without URL');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
      expect(f!.category).toBe('configuration');
      expect(f!.references).toContain('MCP07:2025 - Insufficient Authentication & Authorization');
      expect(f!.description).toContain('http');
    });

    it('should detect sse type without url', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'], type: 'sse' };
      const findings = scanTransport('test', config);
      expect(findings.some(f => f.title === 'Transport Type Specified Without URL')).toBe(true);
    });

    it('should not flag http type with url', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'], type: 'http', url: 'https://example.com/mcp' };
      const findings = scanTransport('test', config);
      expect(findings.some(f => f.title === 'Transport Type Specified Without URL')).toBe(false);
    });

    it('should detect stdio type with url', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'], type: 'stdio', url: 'https://example.com/mcp' };
      const findings = scanTransport('test', config);
      const f = findings.find(f => f.title === 'URL Field Ignored for stdio Transport');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('info');
      expect(f!.category).toBe('configuration');
      expect(f!.references).toContain('MCP07:2025 - Insufficient Authentication & Authorization');
    });

    it('should not flag stdio type without url', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'], type: 'stdio' };
      const findings = scanTransport('test', config);
      expect(findings.some(f => f.title === 'URL Field Ignored for stdio Transport')).toBe(false);
    });

    it('should not flag config without type field', () => {
      const config: MCPServerConfig = { command: 'npx', args: ['some-pkg'] };
      const findings = scanTransport('test', config);
      expect(findings.some(f => f.title === 'Transport Type Specified Without URL')).toBe(false);
      expect(findings.some(f => f.title === 'URL Field Ignored for stdio Transport')).toBe(false);
    });
  });
});
