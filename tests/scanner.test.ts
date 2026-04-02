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
    expect(server!.findings.length).toBe(0); // pinned version + verified package
    expect(server!.score).toBe(100);
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
