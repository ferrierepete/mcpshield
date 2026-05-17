import { describe, it, expect } from 'vitest';
import { computeConfidence, applyConfidenceScores, filterByConfidence } from '../src/ai/confidence.js';
import type { Finding, MCPServerConfig } from '../src/types/index.js';

function makeFinding(overrides: Partial<Finding> & { title: string; severity: Finding['severity'] }): Finding {
  return {
    id: 'MCPS-001',
    description: 'test',
    category: 'configuration',
    serverName: 'test-server',
    remediation: 'fix it',
    ...overrides,
  };
}

describe('Confidence Scoring', () => {
  describe('computeConfidence', () => {
    it('should return base confidence for findings with no matching rules', () => {
      const f = makeFinding({ title: 'Some Unknown Finding', severity: 'high' });
      const conf = computeConfidence(f);
      expect(conf).toBe(0.8); // base for 'high'
    });

    it('should return base confidence by severity level', () => {
      expect(computeConfidence(makeFinding({ title: 'Unknown', severity: 'critical' }))).toBe(0.9);
      expect(computeConfidence(makeFinding({ title: 'Unknown', severity: 'high' }))).toBe(0.8);
      expect(computeConfidence(makeFinding({ title: 'Unknown', severity: 'medium' }))).toBe(0.65);
      expect(computeConfidence(makeFinding({ title: 'Unknown', severity: 'low' }))).toBe(0.5);
      expect(computeConfidence(makeFinding({ title: 'Unknown', severity: 'info' }))).toBe(0.4);
    });

    it('should lower confidence for trusted MCP package unpinned version', () => {
      const f = makeFinding({
        title: 'Unpinned Package Version',
        severity: 'high',
        description: 'Package "@modelcontextprotocol/server-github" is used without a pinned version.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.8);
    });

    it('should lower confidence for env vars using variable references', () => {
      const f = makeFinding({
        title: 'Sensitive Credentials in Config',
        severity: 'high',
        description: 'Found 1 sensitive environment variable(s): OPENAI_API_KEY.',
      });
      const config: MCPServerConfig = {
        command: 'npx',
        env: { OPENAI_API_KEY: '${OPENAI_API_KEY}' },
      };
      const conf = computeConfidence(f, config);
      expect(conf).toBeLessThan(0.8);
    });

    it('should NOT lower confidence for hardcoded env vars', () => {
      const f = makeFinding({
        title: 'Sensitive Credentials in Config',
        severity: 'high',
        description: 'Found 2 sensitive environment variable(s): OPENAI_API_KEY, AWS_SECRET_ACCESS_KEY.',
      });
      const config: MCPServerConfig = {
        command: 'npx',
        env: { OPENAI_API_KEY: 'sk-real-key-here', AWS_SECRET_ACCESS_KEY: 'AKIA...' },
      };
      const conf = computeConfidence(f, config);
      // Should not get the -0.4 adjustment since values are hardcoded
      expect(conf).toBeGreaterThanOrEqual(0.7);
    });

    it('should lower confidence for private IP addresses', () => {
      const f = makeFinding({
        title: 'IP-Based Server URL',
        severity: 'medium',
        description: 'Server URL "http://192.168.1.100:8080" uses a raw IP address.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.65);
    });

    it('should raise confidence for known risky packages', () => {
      const f = makeFinding({
        title: 'Known Risky Package',
        severity: 'critical',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0); // 0.9 base + 0.1 = 1.0 (clamped)
    });

    it('should raise confidence for typosquat detection', () => {
      const f = makeFinding({
        title: 'Potential Typosquat',
        severity: 'critical',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0);
    });

    it('should raise confidence for suspicious URLs', () => {
      const f = makeFinding({
        title: 'Suspicious URL Detected',
        severity: 'critical',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0);
    });

    it('should raise confidence for --privileged Docker flag', () => {
      const f = makeFinding({
        title: 'Dangerous Docker Flag',
        severity: 'critical',
        description: 'Docker container uses "--privileged" which grants elevated privileges.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0);
    });

    it('should raise confidence for dynamic code execution', () => {
      const f = makeFinding({
        title: 'Dynamic Code Execution Pattern',
        severity: 'critical',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0);
    });

    it('should lower confidence for disabled server finding', () => {
      const f = makeFinding({
        title: 'Disabled Server',
        severity: 'info',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.4);
    });

    it('should lower confidence for well-known org unverified package', () => {
      const f = makeFinding({
        title: 'Unverified Third-Party Package',
        severity: 'medium',
        description: 'Package "@microsoft/mcp-server-playwright" is not in the verified list.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.65);
    });

    it('should lower confidence for system-managed executable path', () => {
      const f = makeFinding({
        title: 'Local Executable Path',
        severity: 'medium',
        description: 'Server uses a local executable at "/usr/local/bin/my-server".',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.65);
    });

    it('should raise confidence for root filesystem access', () => {
      const f = makeFinding({
        title: 'Broad Filesystem Access',
        severity: 'critical',
        description: 'Server has access to path "/".',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(1.0);
    });

    it('should raise confidence for curl/wget as MCP server', () => {
      const f = makeFinding({
        title: 'HTTP Client as MCP Server',
        severity: 'high',
      });
      const conf = computeConfidence(f);
      expect(conf).toBe(0.9); // 0.8 + 0.1
    });

    it('should clamp confidence to 0-1 range', () => {
      // Multiple positive adjustments should not exceed 1.0
      const f = makeFinding({
        title: 'Known Risky Package',
        severity: 'critical',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThanOrEqual(1.0);
      expect(conf).toBeGreaterThanOrEqual(0);
    });

    it('should lower confidence for well-known provider missing auth', () => {
      const f = makeFinding({
        title: 'Remote Server Without Authentication Headers',
        severity: 'medium',
        description: 'Remote server at "https://api.github.com/mcp" has no authentication headers.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.65);
    });

    it('should lower confidence for base64-like token in credential field', () => {
      const f = makeFinding({
        title: 'Potentially Obfuscated Value',
        severity: 'medium',
        description: 'Environment variable "GITHUB_TOKEN" contains a base64-like string.',
      });
      const conf = computeConfidence(f);
      expect(conf).toBeLessThan(0.65);
    });
  });

  describe('applyConfidenceScores', () => {
    it('should add confidence to all findings', () => {
      const findings: Finding[] = [
        makeFinding({ title: 'Test 1', severity: 'high' }),
        makeFinding({ title: 'Test 2', severity: 'low' }),
      ];
      const configs: Record<string, MCPServerConfig> = {
        'test-server': { command: 'npx' },
      };
      const result = applyConfidenceScores(findings, configs);
      expect(result).toHaveLength(2);
      expect(result[0].confidence).toBeDefined();
      expect(result[1].confidence).toBeDefined();
    });
  });

  describe('filterByConfidence', () => {
    it('should filter out findings below threshold', () => {
      const findings: Finding[] = [
        { ...makeFinding({ title: 'High', severity: 'critical' }), confidence: 0.9 },
        { ...makeFinding({ title: 'Low', severity: 'info' }), confidence: 0.3 },
        { ...makeFinding({ title: 'Mid', severity: 'medium' }), confidence: 0.6 },
      ];
      const result = filterByConfidence(findings, 0.5);
      expect(result).toHaveLength(2);
      expect(result.map(f => f.title)).toEqual(['High', 'Mid']);
    });

    it('should include findings without confidence (default to 1)', () => {
      const findings: Finding[] = [
        makeFinding({ title: 'No confidence', severity: 'high' }),
      ];
      const result = filterByConfidence(findings, 0.5);
      expect(result).toHaveLength(1);
    });

    it('should return all findings with threshold 0', () => {
      const findings: Finding[] = [
        { ...makeFinding({ title: 'Low', severity: 'info' }), confidence: 0.1 },
      ];
      const result = filterByConfidence(findings, 0);
      expect(result).toHaveLength(1);
    });
  });
});
