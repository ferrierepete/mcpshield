import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import * as path from 'path';

const EDGE_FIXTURE = path.join(__dirname, 'fixtures', 'edge-cases.json');

describe('Threats & Edge Cases Scanner', () => {
  let result: ReturnType<typeof scanAllServers>;

  beforeEach(() => {
    resetCounter();
    const config = loadConfig(EDGE_FIXTURE);
    result = scanAllServers(config.mcpServers, EDGE_FIXTURE);
  });

  it('should handle disabled server', () => {
    const server = result.servers.find(s => s.name === 'disabled-server');
    expect(server).toBeDefined();
    const disabledFinding = server!.findings.find(f => f.title === 'Disabled Server');
    expect(disabledFinding).toBeDefined();
    expect(disabledFinding!.severity).toBe('info');
    // Configuration scanner returns early, but supply-chain/threats scanners still run
    expect(server!.findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect missing command', () => {
    const server = result.servers.find(s => s.name === 'no-command');
    expect(server).toBeDefined();
    const finding = server!.findings.find(f => f.title === 'Missing Command');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect shell injection in arguments', () => {
    const server = result.servers.find(s => s.name === 'shell-injection');
    const finding = server!.findings.find(f => f.title === 'Shell Metacharacter in Arguments');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect suspicious URL in env vars', () => {
    const server = result.servers.find(s => s.name === 'suspicious-url-env');
    const finding = server!.findings.find(f => f.title === 'Suspicious URL Detected');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('critical');
  });

  it('should detect base64 obfuscated values', () => {
    const server = result.servers.find(s => s.name === 'base64-obfuscated');
    const finding = server!.findings.find(f => f.title === 'Potentially Obfuscated Value');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('should detect sensitive working directory', () => {
    const server = result.servers.find(s => s.name === 'sensitive-cwd');
    const finding = server!.findings.find(f => f.title === 'Sensitive Working Directory');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('should detect curl/wget as MCP server', () => {
    const server = result.servers.find(s => s.name === 'curl-server');
    const finding = server!.findings.find(f => f.title === 'HTTP Client as MCP Server');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect python eval patterns', () => {
    const server = result.servers.find(s => s.name === 'python-eval');
    const finding = server!.findings.find(f => f.title === 'Dynamic Code Execution Pattern');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('critical');
  });

  it('should detect permissive runtime flags', () => {
    const server = result.servers.find(s => s.name === 'permissive-flags');
    const findings = server!.findings.filter(f => f.title === 'Overly Permissive Runtime Flag');
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it('should detect network binding to all interfaces', () => {
    const server = result.servers.find(s => s.name === 'network-bind-all');
    const finding = server!.findings.find(f => f.title === 'Network Binding to All Interfaces');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });
});
