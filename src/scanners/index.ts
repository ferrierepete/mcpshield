import { MCPServerConfig, ScanResult, ServerScanResult, Finding } from '../types/index.js';
import { resetCounter, calculateScore } from '../utils/helpers.js';
import { scanSupplyChain } from './supply-chain.js';
import { scanPermissions } from './permissions.js';
import { scanConfiguration } from './configuration.js';
import { scanThreats } from './threats.js';

export function scanServer(name: string, config: MCPServerConfig): ServerScanResult {
  const findings: Finding[] = [
    ...scanConfiguration(name, config),
    ...scanSupplyChain(name, config),
    ...scanPermissions(name, config),
    ...scanThreats(name, config),
  ];

  return {
    name,
    command: config.command || 'unknown',
    findings,
    score: calculateScore(findings),
  };
}

export function scanAllServers(
  servers: Record<string, MCPServerConfig>,
  targetPath: string
): ScanResult {
  resetCounter();

  const serverResults: ServerScanResult[] = [];
  for (const [name, config] of Object.entries(servers)) {
    serverResults.push(scanServer(name, config));
  }

  const allFindings = serverResults.flatMap(s => s.findings);
  const summary = {
    total: allFindings.length,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length,
    score: calculateScore(allFindings),
  };

  return {
    target: targetPath,
    timestamp: new Date().toISOString(),
    servers: serverResults,
    summary,
  };
}
