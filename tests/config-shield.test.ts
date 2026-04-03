import { describe, it, expect } from 'vitest';
import { severityMeetsThreshold, filterResultsBySeverity } from '../src/config/index.js';
import type { Severity } from '../src/types/index.js';

describe('MCPShield Config', () => {
  describe('severityMeetsThreshold', () => {
    it('should pass critical for all thresholds', () => {
      expect(severityMeetsThreshold('critical', 'critical')).toBe(true);
      expect(severityMeetsThreshold('critical', 'info')).toBe(true);
    });

    it('should filter low when threshold is high', () => {
      expect(severityMeetsThreshold('low', 'high')).toBe(false);
      expect(severityMeetsThreshold('medium', 'high')).toBe(false);
      expect(severityMeetsThreshold('high', 'high')).toBe(true);
      expect(severityMeetsThreshold('critical', 'high')).toBe(true);
    });

    it('should pass info for info threshold', () => {
      expect(severityMeetsThreshold('info', 'info')).toBe(true);
    });
  });

  describe('filterResultsBySeverity', () => {
    const findings = [
      { severity: 'critical' as Severity, title: 'crit' },
      { severity: 'high' as Severity, title: 'high' },
      { severity: 'medium' as Severity, title: 'med' },
      { severity: 'low' as Severity, title: 'low' },
      { severity: 'info' as Severity, title: 'info' },
    ];

    it('should return all for info threshold', () => {
      expect(filterResultsBySeverity(findings, 'info')).toHaveLength(5);
    });

    it('should filter to critical+high for high threshold', () => {
      expect(filterResultsBySeverity(findings, 'high')).toHaveLength(2);
    });

    it('should return only critical for critical threshold', () => {
      const result = filterResultsBySeverity(findings, 'critical');
      expect(result).toHaveLength(1);
      expect(result[0].title).toBe('crit');
    });
  });
});
