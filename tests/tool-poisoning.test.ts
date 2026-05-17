import { describe, it, expect, beforeEach } from 'vitest';
import { scanToolPoisoning } from '../src/scanners/tool-poisoning.js';
import { MCPServerConfig } from '../src/types/index.js';
import { resetCounter } from '../src/utils/helpers.js';

describe('scanToolPoisoning', () => {
  beforeEach(() => {
    resetCounter();
  });

  const baseConfig: MCPServerConfig = {
    command: 'npx',
    args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
  };

  it('should emit an info finding for every server', () => {
    const findings = scanToolPoisoning('test-server', baseConfig);
    const info = findings.find(f => f.title === 'Runtime Tool Poisoning Cannot Be Verified');
    expect(info).toBeDefined();
    expect(info!.severity).toBe('info');
    expect(info!.references).toContain('MCP02:2025 - Tool Poisoning');
  });

  it('should detect auto-approved tools via autoApprove', () => {
    const config = {
      ...baseConfig,
      autoApprove: ['read_file', 'write_file'],
    } as unknown as MCPServerConfig;
    const findings = scanToolPoisoning('auto-server', config);
    const autoFinding = findings.find(f => f.title === 'Auto-Approved Tools Without User Confirmation');
    expect(autoFinding).toBeDefined();
    expect(autoFinding!.severity).toBe('medium');
    expect(autoFinding!.description).toContain('2 auto-approved tool(s)');
    expect(autoFinding!.description).toContain('read_file');
  });

  it('should detect auto-approved tools via alwaysAllow', () => {
    const config = {
      ...baseConfig,
      alwaysAllow: ['search'],
    } as unknown as MCPServerConfig;
    const findings = scanToolPoisoning('always-server', config);
    const autoFinding = findings.find(f => f.title === 'Auto-Approved Tools Without User Confirmation');
    expect(autoFinding).toBeDefined();
    expect(autoFinding!.description).toContain('search');
  });

  it('should flag remote server without auth headers', () => {
    const config: MCPServerConfig = {
      command: '',
      url: 'https://mcp.example.com/sse',
    };
    const findings = scanToolPoisoning('remote-server', config);
    const remoteFinding = findings.find(f => f.title === 'Remote Server Without Authentication May Serve Poisoned Tool Definitions');
    expect(remoteFinding).toBeDefined();
    expect(remoteFinding!.severity).toBe('medium');
    expect(remoteFinding!.description).toContain('https://mcp.example.com/sse');
  });

  it('should NOT flag local server without auth headers', () => {
    const config: MCPServerConfig = {
      command: '',
      url: 'http://localhost:3000/sse',
    };
    const findings = scanToolPoisoning('local-server', config);
    const remoteFinding = findings.find(f => f.title === 'Remote Server Without Authentication May Serve Poisoned Tool Definitions');
    expect(remoteFinding).toBeUndefined();
  });

  it('should NOT flag 127.0.0.1 server without auth headers', () => {
    const config: MCPServerConfig = {
      command: '',
      url: 'http://127.0.0.1:8080/sse',
    };
    const findings = scanToolPoisoning('loopback-server', config);
    const remoteFinding = findings.find(f => f.title === 'Remote Server Without Authentication May Serve Poisoned Tool Definitions');
    expect(remoteFinding).toBeUndefined();
  });

  it('should have no medium findings when server has no autoApprove or remote URL', () => {
    const findings = scanToolPoisoning('plain-server', baseConfig);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('info');
  });

  it('should NOT flag remote server that has auth headers', () => {
    const config: MCPServerConfig = {
      command: '',
      url: 'https://mcp.example.com/sse',
      headers: { Authorization: 'Bearer token123' },
    };
    const findings = scanToolPoisoning('authed-remote', config);
    const remoteFinding = findings.find(f => f.title === 'Remote Server Without Authentication May Serve Poisoned Tool Definitions');
    expect(remoteFinding).toBeUndefined();
  });
});
