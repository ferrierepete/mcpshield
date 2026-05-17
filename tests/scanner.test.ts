import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import * as path from 'path';
import { resetCounter } from '../src/utils/helpers.js';

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-config.json');

describe('MCPShield Scanner', () => {
  let result: ReturnType<typeof scanAllServers>;

  beforeEach(() => {
    resetCounter();
    const config = loadConfig(FIXTURE_PATH);
    result = scanAllServers(config.mcpServers, FIXTURE_PATH);
  });

  it('should scan all servers', () => {
    expect(result.servers).toHaveLength(6);
  });

  it('should give filesystem-safe a good score', () => {
    const server = result.servers.find(s => s.name === 'filesystem-safe');
    expect(server).toBeDefined();
    const nonInfoFindings = server!.findings.filter(f => f.severity !== 'info');
    expect(nonInfoFindings.length).toBe(0);
    expect(server!.score).toBe(100);
  });

  it('should include tool-poisoning info finding in pipeline', () => {
    const server = result.servers.find(s => s.name === 'filesystem-safe');
    const tpFinding = server!.findings.find(f => f.title === 'Runtime Tool Poisoning Cannot Be Verified');
    expect(tpFinding).toBeDefined();
    expect(tpFinding!.severity).toBe('info');
    expect(tpFinding!.references).toContain('MCP02:2025 - Tool Poisoning');
  });

  it('should detect root filesystem access', () => {
    const server = result.servers.find(s => s.name === 'filesystem-dangerous');
    expect(server).toBeDefined();
    const rootFinding = server!.findings.find(f => f.title === 'Broad Filesystem Access');
    expect(rootFinding).toBeDefined();
    expect(rootFinding!.severity).toBe('critical');
  });

  it('should detect exposed secrets', () => {
    const server = result.servers.find(s => s.name === 'filesystem-dangerous');
    const secretFinding = server!.findings.find(f => f.title === 'Sensitive Credentials in Config');
    expect(secretFinding).toBeDefined();
    expect(secretFinding!.severity).toBe('high');
  });

  it('should detect unpinned versions', () => {
    const server = result.servers.find(s => s.name === 'filesystem-dangerous');
    const unpinFinding = server!.findings.find(f => f.title === 'Unpinned Package Version');
    expect(unpinFinding).toBeDefined();
    expect(unpinFinding!.severity).toBe('high');
  });

  it('should detect known risky packages', () => {
    const server = result.servers.find(s => s.name === 'suspicious-package');
    const riskyFinding = server!.findings.find(f => f.title === 'Known Risky Package');
    expect(riskyFinding).toBeDefined();
    expect(riskyFinding!.severity).toBe('critical');
  });

  it('should detect typosquats', () => {
    const server = result.servers.find(s => s.name === 'typosquat');
    const typoFinding = server!.findings.find(f => f.title === 'Potential Typosquat');
    expect(typoFinding).toBeDefined();
    expect(typoFinding!.severity).toBe('critical');
  });

  it('should flag local executables', () => {
    const server = result.servers.find(s => s.name === 'local-safe');
    const localFinding = server!.findings.find(f => f.title === 'Local Executable Path');
    expect(localFinding).toBeDefined();
    expect(localFinding!.severity).toBe('medium');
  });

  it('should calculate overall summary', () => {
    expect(result.summary.total).toBeGreaterThan(0);
    expect(result.summary.critical).toBeGreaterThanOrEqual(2); // risky package + typosquat + root access
    expect(result.summary.high).toBeGreaterThanOrEqual(1); // secrets + unpinned
    expect(result.summary.score).toBeLessThan(100);
  });

  it('should have unique finding IDs', () => {
    const allFindings = result.servers.flatMap(s => s.findings);
    const ids = allFindings.map(f => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('Dormant server handling', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should prefix non-info findings with [Dormant] for disabled servers', () => {
    const servers = {
      'dormant-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
        disabled: true,
        env: { AWS_SECRET_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
      },
    };
    const result = scanAllServers(servers, 'test');
    const server = result.servers[0];
    const nonInfoFindings = server.findings.filter(f => f.severity !== 'info');
    expect(nonInfoFindings.length).toBeGreaterThan(0);
    for (const f of nonInfoFindings) {
      expect(f.description).toMatch(/^\[Dormant\]/);
    }
  });

  it('should NOT prefix info findings with [Dormant]', () => {
    const servers = {
      'dormant-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
        disabled: true,
      },
    };
    const result = scanAllServers(servers, 'test');
    const server = result.servers[0];
    const infoFindings = server.findings.filter(f => f.severity === 'info');
    for (const f of infoFindings) {
      expect(f.description).not.toMatch(/^\[Dormant\]/);
    }
  });

  it('should give disabled servers a score of 100 since dormant findings are excluded', () => {
    const servers = {
      'dormant-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
        disabled: true,
        env: { AWS_SECRET_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
      },
    };
    const result = scanAllServers(servers, 'test');
    const server = result.servers[0];
    expect(server.score).toBe(100);
  });

  it('should NOT prefix findings for enabled servers', () => {
    const servers = {
      'active-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
        env: { AWS_SECRET_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE' },
      },
    };
    const result = scanAllServers(servers, 'test');
    const server = result.servers[0];
    for (const f of server.findings) {
      expect(f.description).not.toMatch(/^\[Dormant\]/);
    }
  });
});
