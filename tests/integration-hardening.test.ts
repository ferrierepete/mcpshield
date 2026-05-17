import { describe, it, expect, beforeEach, vi } from 'vitest';
import { scanAllServers, scanServer } from '../src/scanners/index.js';
import { resetCounter } from '../src/utils/helpers.js';
import { toSarif } from '../src/formatters/sarif.js';
import { applyFixesSync } from '../src/fix/index.js';
import type { MCPServerConfig, MCPConfig, Finding } from '../src/types/index.js';

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

const CONFIG_PATH = '/tmp/test-integration.json';

function makeConfig(servers: Record<string, MCPServerConfig>): MCPConfig {
  return { mcpServers: { ...servers } };
}

// Unpinned-finding fixture for fix tests
const unpinnedFinding: Finding = {
  id: 'MCPS-TEST',
  title: 'Unpinned Package Version',
  description: 'Unpinned',
  severity: 'high',
  category: 'supply-chain',
  serverName: 'fix-test',
  remediation: 'Pin it',
};

// -------------------------------------------------------------------------------------------------
// Scenario 1 — Malicious config with ALL bypass vectors in a single scan
// -------------------------------------------------------------------------------------------------

describe('Scenario 1: all bypass vectors detected in single scan', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('detects bash -c, newline injection, scope-extension typosquat, semver range pinning, --security-opt, and Discord webhook', () => {
    const servers: Record<string, MCPServerConfig> = {
      'malicious-all': {
        command: 'npx',
        args: [
          '-y',
          '@anthropic-ai/fake-server@^1.0.0',          // scope-extension typosquat + semver range
          'arg-with-newline\ninjected-cmd',             // newline injection
        ],
        env: {
          EXFIL_URL: 'https://discord.com/api/webhooks/12345/token', // Discord webhook
        },
      },
      'shell-injection': {
        command: 'bash',
        args: ['-c', 'echo hello'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);

    const npxServer = result.servers.find(s => s.name === 'malicious-all')!;
    const npxTitles = npxServer.findings.map(f => f.title);

    expect(npxTitles).toContain('Newline Injection in Arguments');
    expect(npxTitles).toContain('Potential Typosquat');
    expect(npxTitles).toContain('Unpinned Package Version');
    expect(npxTitles).toContain('Suspicious URL Detected');

    const shellServer = result.servers.find(s => s.name === 'shell-injection')!;
    const shellTitles = shellServer.findings.map(f => f.title);
    expect(shellTitles.some(t => t.includes('Shell Interpreter'))).toBe(true);
  });

  it('detects Docker --security-opt when command is docker', () => {
    const servers: Record<string, MCPServerConfig> = {
      'docker-malicious': {
        command: 'docker',
        args: [
          'run',
          '--security-opt', 'seccomp=unconfined',
          'alpine',
        ],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const findings = result.servers[0].findings;
    const titles = findings.map(f => f.title);

    expect(titles).toContain('Dangerous Docker Flag');
  });

  it('all findings have OWASP references', () => {
    const servers: Record<string, MCPServerConfig> = {
      'malicious-all': {
        command: 'bash',
        args: ['-c', 'echo hi', 'line\nbreak'],
        env: {
          WEBHOOK: 'https://discord.com/api/webhooks/999/bad',
        },
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const findings = result.servers[0].findings;

    for (const f of findings) {
      expect(f.references).toBeDefined();
      expect(f.references!.length).toBeGreaterThan(0);
      // At least one reference should be an OWASP URL or OWASP category
      const hasOwasp = f.references!.some(
        r => r.includes('owasp.org') || r.startsWith('MCP')
      );
      expect(hasOwasp).toBe(true);
    }
  });

  it('produces a low security score for heavily misconfigured server', () => {
    const servers: Record<string, MCPServerConfig> = {
      'malicious-all': {
        command: 'bash',
        args: ['-c', 'rm -rf /', 'line\nbreak'],
        env: {
          DISCORD: 'https://discord.com/api/webhooks/1/t',
          AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        },
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    expect(result.summary.score).toBeLessThan(50);
  });
});

// -------------------------------------------------------------------------------------------------
// Scenario 2 — Disabled server with malicious config
// -------------------------------------------------------------------------------------------------

describe('Scenario 2: disabled server with malicious config', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('labels non-info findings with [Dormant] prefix', () => {
    const servers: Record<string, MCPServerConfig> = {
      'dormant-bad': {
        command: 'npx',
        args: ['-y', '@anthropic-ai/fake@latest'],
        env: {
          AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        },
        disabled: true,
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const serverResult = result.servers[0];

    // Non-info findings should have [Dormant] prefix
    const nonInfo = serverResult.findings.filter(f => f.severity !== 'info');
    for (const f of nonInfo) {
      expect(f.description).toMatch(/^\[Dormant\]/);
    }
  });

  it('info-level findings do not get [Dormant] prefix', () => {
    const servers: Record<string, MCPServerConfig> = {
      'dormant-simple': {
        command: 'node',
        args: ['server.js'],
        disabled: true,
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const serverResult = result.servers[0];
    const infoFindings = serverResult.findings.filter(f => f.severity === 'info');

    for (const f of infoFindings) {
      expect(f.description).not.toMatch(/^\[Dormant\]/);
    }
  });

  it('disabled server scores 100 (findings are dormant)', () => {
    const servers: Record<string, MCPServerConfig> = {
      'dormant-bad': {
        command: 'npx',
        args: ['-y', '@anthropic-ai/fake@latest'],
        env: { AWS_SECRET_ACCESS_KEY: 'secret123' },
        disabled: true,
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const serverResult = result.servers[0];

    // calculateScore filters out [Dormant] findings, so score should be 100
    expect(serverResult.score).toBe(100);
  });

  it('scanServer single also applies dormant prefix', () => {
    const config: MCPServerConfig = {
      command: 'bash',
      args: ['-c', 'echo pwned'],
      disabled: true,
    };

    const server = scanServer('dormant-shell', config);
    const nonInfo = server.findings.filter(f => f.severity !== 'info');
    for (const f of nonInfo) {
      expect(f.description).toMatch(/^\[Dormant\]/);
    }
  });
});

// -------------------------------------------------------------------------------------------------
// Scenario 3 — Multi-config scan with different client formats
// -------------------------------------------------------------------------------------------------

describe('Scenario 3: multi-config scan', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('scans servers from multiple config sources simultaneously', () => {
    const servers: Record<string, MCPServerConfig> = {
      // Claude Desktop style (npx)
      'claude-filesystem': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp/safe-dir'],
      },
      // Docker style
      'docker-mcp': {
        command: 'docker',
        args: ['run', '--privileged', '-v', '/:/host', 'mcp-server:latest'],
      },
      // HTTP/SSE transport
      'remote-sse': {
        command: 'node',
        args: ['client.js'],
        url: 'http://remote-server.example.com/mcp',
        type: 'sse',
      },
      // Python style
      'python-mcp': {
        command: 'uvx',
        args: ['mcp-server-git'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);

    // Should have 4 servers
    expect(result.servers).toHaveLength(4);

    const names = result.servers.map(s => s.name);
    expect(names).toContain('claude-filesystem');
    expect(names).toContain('docker-mcp');
    expect(names).toContain('remote-sse');
    expect(names).toContain('python-mcp');

    // Docker server should have critical findings (privileged + sensitive mount)
    const dockerServer = result.servers.find(s => s.name === 'docker-mcp')!;
    expect(dockerServer.findings.length).toBeGreaterThan(0);
    const dockerTitles = dockerServer.findings.map(f => f.title);
    expect(dockerTitles).toContain('Dangerous Docker Flag');

    // Remote SSE should flag insecure HTTP
    const remoteServer = result.servers.find(s => s.name === 'remote-sse')!;
    const remoteTitles = remoteServer.findings.map(f => f.title);
    expect(remoteTitles).toContain('Insecure HTTP Transport');

    // Summary should aggregate all findings
    expect(result.summary.total).toBeGreaterThan(0);
  });

  it('summary aggregates critical/high/medium/low counts correctly', () => {
    const servers: Record<string, MCPServerConfig> = {
      'critical-only': {
        command: 'docker',
        args: ['run', '--privileged', 'alpine'],
      },
      'clean-server': {
        command: 'node',
        args: ['server.js'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);

    const allFindings = result.servers.flatMap(s => s.findings);
    const expectedCritical = allFindings.filter(f => f.severity === 'critical').length;
    const expectedHigh = allFindings.filter(f => f.severity === 'high').length;

    expect(result.summary.critical).toBe(expectedCritical);
    expect(result.summary.high).toBe(expectedHigh);
  });
});

// -------------------------------------------------------------------------------------------------
// Scenario 4 — Clean config with all new checks
// -------------------------------------------------------------------------------------------------

describe('Scenario 4: clean config produces minimal findings', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('well-configured server has high score and no critical/high findings', () => {
    const servers: Record<string, MCPServerConfig> = {
      'safe-server': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem@1.0.0', '/home/user/projects/safe'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const server = result.servers[0];

    // No critical or high findings
    const criticalHigh = server.findings.filter(
      f => f.severity === 'critical' || f.severity === 'high'
    );
    expect(criticalHigh).toHaveLength(0);

    // Score should be high (80+)
    expect(server.score).toBeGreaterThanOrEqual(80);
  });

  it('server with pinned Docker image, no privileged flags, localhost binding has minimal issues', () => {
    const servers: Record<string, MCPServerConfig> = {
      'safe-docker': {
        command: 'docker',
        args: ['run', '-p', '127.0.0.1:8080:8080', 'mcp-server:1.2.3'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const server = result.servers[0];

    // No critical findings
    const critical = server.findings.filter(f => f.severity === 'critical');
    expect(critical).toHaveLength(0);

    // No exposed port warning (bound to localhost)
    const portFindings = server.findings.filter(
      f => f.title === 'Docker Port Exposed to All Interfaces'
    );
    expect(portFindings).toHaveLength(0);
  });

  it('server with HTTPS URL and auth headers has no transport issues', () => {
    const servers: Record<string, MCPServerConfig> = {
      'safe-remote': {
        command: 'node',
        args: ['client.js'],
        url: 'https://mcp.example.com/api',
        headers: { Authorization: 'Bearer ${TOKEN}' },
        type: 'http',
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const server = result.servers[0];

    // No insecure transport findings
    const transportIssues = server.findings.filter(
      f => f.title === 'Insecure HTTP Transport' ||
           f.title === 'Remote Server Without Authentication Headers'
    );
    expect(transportIssues).toHaveLength(0);
  });
});

// -------------------------------------------------------------------------------------------------
// Scenario 5 — SARIF output validation
// -------------------------------------------------------------------------------------------------

describe('Scenario 5: SARIF output with valid helpUri URLs', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('all SARIF rules have valid https:// helpUri', () => {
    const servers: Record<string, MCPServerConfig> = {
      'sarah': {
        command: 'npx',
        args: ['-y', '@anthropic-ai/fake@latest'],
        env: { AWS_SECRET_ACCESS_KEY: 'secret123' },
      },
      'docker-bad': {
        command: 'docker',
        args: ['run', '--privileged', 'alpine'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const sarif = toSarif(result, '0.2.0');

    // Verify SARIF structure
    expect(sarif.$schema).toContain('sarif-schema');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);

    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBeGreaterThan(0);

    // Every rule must have a helpUri starting with https://
    for (const rule of rules) {
      expect(rule.helpUri).toBeDefined();
      expect(rule.helpUri).toMatch(/^https:\/\//);
    }
  });

  it('SARIF results reference valid ruleIndices', () => {
    const servers: Record<string, MCPServerConfig> = {
      'test': {
        command: 'bash',
        args: ['-c', 'echo hi'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const sarif = toSarif(result, '0.2.0');

    const rules = sarif.runs[0].tool.driver.rules;
    const results = sarif.runs[0].results;

    expect(results.length).toBeGreaterThan(0);

    for (const r of results) {
      expect(r.ruleIndex).toBeGreaterThanOrEqual(0);
      expect(r.ruleIndex).toBeLessThan(rules.length);
      expect(rules[r.ruleIndex].id).toBe(r.ruleId);
    }
  });

  it('SARIF tool information is correct', () => {
    const servers: Record<string, MCPServerConfig> = {
      'test': {
        command: 'node',
        args: ['server.js'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const sarif = toSarif(result, '0.2.0');

    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe('MCPShield');
    expect(driver.version).toBe('0.2.0');
    expect(driver.informationUri).toContain('github.com');
  });

  it('SARIF severity mapping is correct', () => {
    const servers: Record<string, MCPServerConfig> = {
      'test': {
        command: 'docker',
        args: ['run', '--privileged', 'alpine'],
      },
    };

    const result = scanAllServers(servers, CONFIG_PATH);
    const sarif = toSarif(result, '0.2.0');

    const validLevels = new Set(['error', 'warning', 'note']);
    for (const r of sarif.runs[0].results) {
      expect(validLevels.has(r.level)).toBe(true);
    }
  });
});

// -------------------------------------------------------------------------------------------------
// Scenario 6 — Fix command integration: exact version pins
// -------------------------------------------------------------------------------------------------

describe('Scenario 6: auto-fix produces exact version pins', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('applyFixesSync pins unpinned package with @0.0.0-REVIEW-NEEDED (no network)', () => {
    const config: MCPConfig = {
      mcpServers: {
        'fix-test': {
          command: 'npx',
          args: ['-y', 'some-unpinned-package'],
        },
      },
    };

    const { config: fixed } = applyFixesSync(config, [unpinnedFinding]);
    const args = fixed.mcpServers['fix-test'].args!;

    // Should NOT contain @latest
    expect(args).not.toContain('some-unpinned-package@latest');

    // Should contain a pinned version indicator
    expect(args.some(a => a.includes('@0.0.0-REVIEW-NEEDED'))).toBe(true);
  });

  it('applyFixesSync does not modify already-pinned packages', () => {
    const config: MCPConfig = {
      mcpServers: {
        'pinned-test': {
          command: 'npx',
          args: ['-y', 'my-package@1.2.3'],
        },
      },
    };

    const { config: fixed } = applyFixesSync(config, [unpinnedFinding]);
    const args = fixed.mcpServers['pinned-test'].args!;

    // Already-pinned package should remain unchanged
    expect(args).toContain('my-package@1.2.3');
    expect(args).not.toContain('my-package@latest');
  });

  it('async applyFixes resolves exact version when registry reachable', async () => {
    // Mock fetch to simulate registry
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ version: '4.5.6' }),
    });

    try {
      const { applyFixes } = await import('../src/fix/index.js');
      const config: MCPConfig = {
        mcpServers: {
          'async-fix': {
            command: 'npx',
            args: ['-y', 'resolve-me'],
          },
        },
      };

      const { config: fixed } = await applyFixes(config, [
        { ...unpinnedFinding, serverName: 'async-fix' },
      ]);

      const args = fixed.mcpServers['async-fix'].args!;
      expect(args).toContain('resolve-me@4.5.6');
      expect(args).not.toContain('resolve-me@latest');
      expect(args).not.toContain('resolve-me@0.0.0-REVIEW-NEEDED');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('applyFixesSync handles multiple servers', () => {
    const config: MCPConfig = {
      mcpServers: {
        'server-a': {
          command: 'npx',
          args: ['-y', 'pkg-a'],
        },
        'server-b': {
          command: 'npx',
          args: ['-y', 'pkg-b'],
        },
      },
    };

    const findings: Finding[] = [
      { ...unpinnedFinding, serverName: 'server-a' },
      { ...unpinnedFinding, serverName: 'server-b' },
    ];

    const { config: fixed } = applyFixesSync(config, findings);

    expect(
      fixed.mcpServers['server-a'].args!.some(a => a.includes('@0.0.0-REVIEW-NEEDED'))
    ).toBe(true);
    expect(
      fixed.mcpServers['server-b'].args!.some(a => a.includes('@0.0.0-REVIEW-NEEDED'))
    ).toBe(true);
  });
});
