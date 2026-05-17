import { describe, it, expect } from 'vitest';
import {
  ScanContext,
  createFinding,
  resetCounter,
  calculateScore,
  severityIcon,
  scoreColor,
} from '../src/utils/helpers.js';

describe('Helpers', () => {
  describe('ScanContext', () => {
    it('should generate sequential finding IDs', () => {
      const ctx = new ScanContext();
      const f1 = ctx.createFinding({
        title: 'Test 1', description: 'desc', severity: 'high',
        category: 'configuration', serverName: 'test', remediation: 'fix it',
      });
      const f2 = ctx.createFinding({
        title: 'Test 2', description: 'desc', severity: 'medium',
        category: 'configuration', serverName: 'test', remediation: 'fix it',
      });
      expect(f1.id).toBe('MCPS-001');
      expect(f2.id).toBe('MCPS-002');
    });

    it('should track count', () => {
      const ctx = new ScanContext();
      expect(ctx.count).toBe(0);
      ctx.createFinding({
        title: 'Test', description: 'desc', severity: 'low',
        category: 'configuration', serverName: 'test', remediation: 'fix it',
      });
      expect(ctx.count).toBe(1);
    });

    it('should be isolated from other contexts', () => {
      const ctx1 = new ScanContext();
      const ctx2 = new ScanContext();
      ctx1.createFinding({
        title: 'Test', description: 'desc', severity: 'low',
        category: 'configuration', serverName: 'test', remediation: 'fix it',
      });
      const f = ctx2.createFinding({
        title: 'Test', description: 'desc', severity: 'low',
        category: 'configuration', serverName: 'test', remediation: 'fix it',
      });
      expect(f.id).toBe('MCPS-001'); // Independent counter
    });
  });

  describe('Legacy createFinding / resetCounter', () => {
    it('should reset and generate sequential IDs', () => {
      resetCounter();
      const f1 = createFinding({
        title: 'A', description: 'd', severity: 'low',
        category: 'configuration', serverName: 's', remediation: 'r',
      });
      const f2 = createFinding({
        title: 'B', description: 'd', severity: 'low',
        category: 'configuration', serverName: 's', remediation: 'r',
      });
      expect(f1.id).toBe('MCPS-001');
      expect(f2.id).toBe('MCPS-002');

      resetCounter();
      const f3 = createFinding({
        title: 'C', description: 'd', severity: 'low',
        category: 'configuration', serverName: 's', remediation: 'r',
      });
      expect(f3.id).toBe('MCPS-001');
    });
  });

  describe('calculateScore', () => {
    it('should return 100 for no findings', () => {
      expect(calculateScore([])).toBe(100);
    });

    it('should deduct for critical findings', () => {
      const findings = [
        { id: '1', title: 'T', description: 'D', severity: 'critical' as const, category: 'configuration' as const, serverName: 's', remediation: 'r' },
      ];
      expect(calculateScore(findings)).toBe(75); // 100 - 25
    });

    it('should not go below 0', () => {
      const findings = Array.from({ length: 10 }, (_, i) => ({
        id: `${i}`, title: 'T', description: 'D', severity: 'critical' as const,
        category: 'configuration' as const, serverName: 's', remediation: 'r',
      }));
      expect(calculateScore(findings)).toBe(0);
    });

    it('should handle mixed severities', () => {
      const findings = [
        { id: '1', title: 'T', description: 'D', severity: 'high' as const, category: 'configuration' as const, serverName: 's', remediation: 'r' },
        { id: '2', title: 'T', description: 'D', severity: 'medium' as const, category: 'configuration' as const, serverName: 's', remediation: 'r' },
        { id: '3', title: 'T', description: 'D', severity: 'info' as const, category: 'configuration' as const, serverName: 's', remediation: 'r' },
      ];
      expect(calculateScore(findings)).toBe(100 - 15 - 8 - 0); // 77
    });
  });

  describe('severityIcon', () => {
    it('should return correct icons', () => {
      expect(severityIcon('critical')).toBe('🔴');
      expect(severityIcon('high')).toBe('🟠');
      expect(severityIcon('medium')).toBe('🟡');
      expect(severityIcon('low')).toBe('🔵');
      expect(severityIcon('info')).toBe('⚪');
    });
  });

  describe('scoreColor', () => {
    it('should return green for good scores', () => {
      expect(scoreColor(80)).toBe('green');
      expect(scoreColor(100)).toBe('green');
    });

    it('should return yellow for warning scores', () => {
      expect(scoreColor(60)).toBe('yellow');
      expect(scoreColor(79)).toBe('yellow');
    });

    it('should return red for bad scores', () => {
      expect(scoreColor(40)).toBe('red');
      expect(scoreColor(59)).toBe('red');
    });

    it('should return bgRed for critical scores', () => {
      expect(scoreColor(0)).toBe('bgRed');
      expect(scoreColor(39)).toBe('bgRed');
    });
  });
});
