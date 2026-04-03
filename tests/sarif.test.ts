import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { resetCounter } from '../src/utils/helpers.js';
import { toSarif } from '../src/formatters/sarif.js';
import * as path from 'path';

const FIXTURE_PATH = path.join(__dirname, 'fixtures', 'test-config.json');

describe('SARIF Formatter', () => {
  let sarif: ReturnType<typeof toSarif>;

  beforeEach(() => {
    resetCounter();
    const config = loadConfig(FIXTURE_PATH);
    const result = scanAllServers(config.mcpServers, FIXTURE_PATH);
    sarif = toSarif(result, '0.1.0');
  });

  it('should have valid SARIF schema', () => {
    expect(sarif.$schema).toContain('sarif-schema');
    expect(sarif.version).toBe('2.1.0');
  });

  it('should have one run', () => {
    expect(sarif.runs).toHaveLength(1);
  });

  it('should contain tool information', () => {
    const tool = sarif.runs[0].tool.driver;
    expect(tool.name).toBe('MCPShield');
    expect(tool.version).toBe('0.1.0');
  });

  it('should contain rules', () => {
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });

  it('should contain results', () => {
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });

  it('should map severity to SARIF levels', () => {
    const levels = sarif.runs[0].results.map(r => r.level);
    const validLevels = ['error', 'warning', 'note'];
    for (const level of levels) {
      expect(validLevels).toContain(level);
    }
  });

  it('should include fix descriptions where available', () => {
    const withFixes = sarif.runs[0].results.filter(r => r.fixes && r.fixes.length > 0);
    expect(withFixes.length).toBeGreaterThan(0);
  });

  it('should include artifact', () => {
    expect(sarif.runs[0].artifacts).toHaveLength(1);
    expect(sarif.runs[0].artifacts[0].location.uri).toBe(FIXTURE_PATH);
  });
});
