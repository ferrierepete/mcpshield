import { MCPServerConfig, ScanResult, ServerScanResult, Finding } from '../types/index.js';
import { resetCounter, calculateScore } from '../utils/helpers.js';
import { scanSupplyChain } from './supply-chain.js';
import { scanPermissions } from './permissions.js';
import { scanConfiguration } from './configuration.js';
import { scanThreats } from './threats.js';
import { scanTransport } from './transport.js';
import { scanRegistry } from './registry.js';
import { pluginRegistry } from '../plugins/index.js';

export function scanServer(name: string, config: MCPServerConfig): ServerScanResult {
  const findings: Finding[] = [
    ...scanConfiguration(name, config),
    ...scanSupplyChain(name, config),
    ...scanPermissions(name, config),
    ...scanThreats(name, config),
    ...scanTransport(name, config),
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
  // Create a fresh context for each scan run
  resetCounter();

  const serverResults: ServerScanResult[] = [];
  for (const [name, config] of Object.entries(servers)) {
    serverResults.push(scanServer(name, config));
  }

  return buildScanResult(serverResults, targetPath);
}

export async function scanAllServersWithRegistry(
  servers: Record<string, MCPServerConfig>,
  targetPath: string
): Promise<ScanResult> {
  resetCounter();

  const serverResults: ServerScanResult[] = [];
  for (const [name, config] of Object.entries(servers)) {
    const base = scanServer(name, config);
    try {
      const registryFindings = await scanRegistry(name, config);
      base.findings.push(...registryFindings);
    } catch {
      // Registry checks are best-effort; skip on network errors
    }
    // Run custom plugins
    try {
      const pluginFindings = await pluginRegistry.runAll(name, config);
      base.findings.push(...pluginFindings);
    } catch {
      // Plugin errors are non-fatal
    }
    base.score = calculateScore(base.findings);
    serverResults.push(base);
  }

  return buildScanResult(serverResults, targetPath);
}

function buildScanResult(serverResults: ServerScanResult[], targetPath: string): ScanResult {
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
