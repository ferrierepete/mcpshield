import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { Severity } from '../types/index.js';

export interface MCPShieldConfig {
  /** Minimum severity to display (filters output) */
  severityThreshold?: Severity;
  /** Finding IDs or titles to ignore */
  ignore?: string[];
  /** Default output format */
  format?: 'pretty' | 'json' | 'markdown' | 'sarif';
  /** Enable registry checks by default */
  registry?: boolean;
  /** Additional trusted packages */
  trustedPackages?: string[];
  /** Additional risky packages */
  riskyPackages?: string[];
  /** Enable AI-based false positive reduction */
  ai?: boolean;
  /** AI provider: openai, anthropic, gemini */
  aiProvider?: string;
  /** AI model override */
  aiModel?: string;
  /** Custom base URL for OpenAI-compatible providers */
  aiBaseUrl?: string;
  /** Minimum confidence threshold (0.0–1.0) to display findings */
  minConfidence?: number;
}

const CONFIG_FILENAMES = [
  '.mcpshieldrc',
  '.mcpshieldrc.json',
  '.mcpshield.json',
];

const SEARCH_DIRS = [
  process.cwd(),
  homedir(),
];

export function loadMCPShieldConfig(): MCPShieldConfig {
  for (const dir of SEARCH_DIRS) {
    for (const filename of CONFIG_FILENAMES) {
      const filePath = join(dir, filename);
      if (existsSync(filePath)) {
        try {
          const raw = readFileSync(filePath, 'utf-8');
          return JSON.parse(raw) as MCPShieldConfig;
        } catch {
          // Silently skip malformed config files
        }
      }
    }
  }
  return {};
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function severityMeetsThreshold(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

export function filterResultsBySeverity<T extends { severity: Severity }>(
  findings: T[],
  threshold: Severity
): T[] {
  return findings.filter(f => severityMeetsThreshold(f.severity, threshold));
}
