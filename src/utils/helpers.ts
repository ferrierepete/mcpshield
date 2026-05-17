import { Finding, FindingCategory, Severity } from '../types/index.js';

export class ScanContext {
  private findingCounter = 0;

  createFinding(opts: {
    title: string;
    description: string;
    severity: Severity;
    category: FindingCategory;
    serverName: string;
    remediation: string;
    references?: string[];
  }): Finding {
    this.findingCounter++;
    return {
      id: `MCPS-${String(this.findingCounter).padStart(3, '0')}`,
      ...opts,
    };
  }

  get count(): number {
    return this.findingCounter;
  }
}

// Legacy helpers kept for backward compatibility
let _legacyCtx = new ScanContext();

export function createFinding(opts: {
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  serverName: string;
  remediation: string;
  references?: string[];
}): Finding {
  return _legacyCtx.createFinding(opts);
}

export function resetCounter(): void {
  _legacyCtx = new ScanContext();
}

const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function calculateScore(findings: Finding[]): number {
  const activeFindings = findings.filter(f => !f.description.startsWith('[Dormant]'));
  const totalPenalty = activeFindings.reduce((sum, f) => sum + SEVERITY_SCORES[f.severity], 0);
  return Math.max(0, 100 - totalPenalty);
}

export function severityIcon(s: Severity): string {
  const icons: Record<Severity, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: '⚪',
  };
  return icons[s];
}

export function scoreColor(score: number): string {
  if (score >= 80) return 'green';
  if (score >= 60) return 'yellow';
  if (score >= 40) return 'red';
  return 'bgRed';
}
