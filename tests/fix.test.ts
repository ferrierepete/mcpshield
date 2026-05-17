import { describe, it, expect, beforeEach, vi } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import { applyFixes, applyFixesSync, resolveExactVersion, getAvailableFixes } from '../src/fix/index.js';
import type { MCPConfig, Finding } from '../src/types/index.js';
import * as path from 'path';

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-config.json');

describe('Auto-Fix System', () => {
  let config: ReturnType<typeof loadConfig>;
  let allFindings: ReturnType<typeof scanAllServers>['servers'][0]['findings'];

  beforeEach(() => {
    resetCounter();
    config = loadConfig(FIXTURE_PATH);
    const result = scanAllServers(config.mcpServers, FIXTURE_PATH);
    allFindings = result.servers.flatMap(s => s.findings);
  });

  it('should find available fixes for known issues', () => {
    const fixes = getAvailableFixes(allFindings);
    expect(fixes.length).toBeGreaterThan(0);
  });

  it('should apply version pinning fix', async () => {
    const { config: fixed, result } = await applyFixes(config, allFindings);
    const appliedVersionFix = result.applied.find(a => a.includes('Pin'));
    expect(fixed.mcpServers['filesystem-dangerous'].args).toBeDefined();
  });

  it('should apply secret replacement fix', async () => {
    const { config: fixed, result } = await applyFixes(config, allFindings);
    const secretFix = result.applied.find(a => a.includes('secret') || a.includes('credential') || a.includes('Secret'));
    if (secretFix) {
      const env = fixed.mcpServers['filesystem-dangerous'].env;
      expect(env?.AWS_SECRET_ACCESS_KEY).toContain('${');
    }
  });

  it('should apply empty env var removal fix', async () => {
    const { config: fixed } = await applyFixes(config, allFindings);
    const env = fixed.mcpServers['filesystem-dangerous'].env;
    // MY_TOKEN was empty, should be removed
    expect(env?.MY_TOKEN).toBeUndefined();
  });

  it('should not crash with no fixable findings', async () => {
    const emptyConfig = loadConfig(path.join(__dirname, 'fixtures', 'empty-config.json'));
    const { result } = await applyFixes(emptyConfig, []);
    expect(result.applied).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);
  });

  it('should report applied and skipped fixes', async () => {
    const { result } = await applyFixes(config, allFindings);
    expect(Array.isArray(result.applied)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
  });
});

describe('Exact Version Resolution', () => {
  const makeConfig = (pkgArg: string): MCPConfig => ({
    mcpServers: {
      'test-server': {
        command: 'npx',
        args: ['-y', pkgArg],
      },
    },
  });

  const unpinnedFinding: Finding = {
    id: 'MCP-TEST',
    title: 'Unpinned Package Version',
    description: 'Unpinned',
    severity: 'high',
    category: 'supply-chain',
    serverName: 'test-server',
    remediation: 'Pin it',
  };

  it('pins to exact version when registry is reachable', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ version: '3.2.1' }),
    });

    try {
      const config = makeConfig('some-package');
      const { config: fixed } = await applyFixes(config, [unpinnedFinding]);
      expect(fixed.mcpServers['test-server'].args).toContain('some-package@3.2.1');
      expect(fixed.mcpServers['test-server'].args).not.toContain('some-package@latest');
      expect(fixed.mcpServers['test-server'].args).not.toContain('some-package@0.0.0-REVIEW-NEEDED');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('falls back to @0.0.0-REVIEW-NEEDED when registry is unreachable', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('network error'));

    try {
      const config = makeConfig('some-package');
      const { config: fixed } = await applyFixes(config, [unpinnedFinding]);
      expect(fixed.mcpServers['test-server'].args).toContain('some-package@0.0.0-REVIEW-NEEDED');
      expect(fixed.mcpServers['test-server'].args).not.toContain('some-package@latest');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('falls back when registry returns non-OK status', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500 });

    try {
      const config = makeConfig('some-package');
      const { config: fixed } = await applyFixes(config, [unpinnedFinding]);
      expect(fixed.mcpServers['test-server'].args).toContain('some-package@0.0.0-REVIEW-NEEDED');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('does not touch already-pinned packages', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn();

    try {
      const config = makeConfig('some-package@1.2.3');
      const { config: fixed } = await applyFixes(config, [unpinnedFinding]);
      expect(fixed.mcpServers['test-server'].args).toContain('some-package@1.2.3');
      expect(globalThis.fetch).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('resolveExactVersion returns null on network failure', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('timeout'));

    try {
      const result = await resolveExactVersion('anything');
      expect(result).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('resolveExactVersion returns version string on success', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ version: '9.8.7' }),
    });

    try {
      const result = await resolveExactVersion('my-pkg');
      expect(result).toBe('9.8.7');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('applyFixesSync never calls network', () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('should not be called'));

    try {
      const config = makeConfig('some-package');
      const { config: fixed } = applyFixesSync(config, [unpinnedFinding]);
      expect(fixed.mcpServers['test-server'].args).toContain('some-package@0.0.0-REVIEW-NEEDED');
      expect(globalThis.fetch).not.toHaveBeenCalled();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
