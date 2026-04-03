import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import * as path from 'path';

const DOCKER_FIXTURE = path.join(__dirname, 'fixtures', 'docker-config.json');
const HTTP_FIXTURE = path.join(__dirname, 'fixtures', 'http-config.json');

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
});
