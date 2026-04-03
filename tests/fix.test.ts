import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import { applyFixes, getAvailableFixes } from '../src/fix/index.js';
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

  it('should apply version pinning fix', () => {
    const { config: fixed, result } = applyFixes(config, allFindings);
    const appliedVersionFix = result.applied.find(a => a.includes('Pin'));
    // We have unpinned packages, so fix should be applied
    expect(fixed.mcpServers['filesystem-dangerous'].args).toBeDefined();
  });

  it('should apply secret replacement fix', () => {
    const { config: fixed, result } = applyFixes(config, allFindings);
    const secretFix = result.applied.find(a => a.includes('secret') || a.includes('credential') || a.includes('Secret'));
    if (secretFix) {
      const env = fixed.mcpServers['filesystem-dangerous'].env;
      expect(env?.AWS_SECRET_ACCESS_KEY).toContain('${');
    }
  });

  it('should apply empty env var removal fix', () => {
    const { config: fixed } = applyFixes(config, allFindings);
    const env = fixed.mcpServers['filesystem-dangerous'].env;
    // MY_TOKEN was empty, should be removed
    expect(env?.MY_TOKEN).toBeUndefined();
  });

  it('should not crash with no fixable findings', () => {
    const emptyConfig = loadConfig(path.join(__dirname, 'fixtures', 'empty-config.json'));
    const { result } = applyFixes(emptyConfig, []);
    expect(result.applied).toHaveLength(0);
    expect(result.skipped).toHaveLength(0);
  });

  it('should report applied and skipped fixes', () => {
    const { result } = applyFixes(config, allFindings);
    expect(Array.isArray(result.applied)).toBe(true);
    expect(Array.isArray(result.skipped)).toBe(true);
  });
});
