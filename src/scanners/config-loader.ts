import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { MCPConfig, MCPServerConfig } from '../types/index.js';

const CONFIG_PATHS = [
  // Claude Desktop
  path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
  path.join(os.homedir(), '.config', 'claude', 'config.json'),
  // VS Code / Cursor
  path.join(os.homedir(), '.vscode', 'mcp.json'),
  path.join(os.homedir(), '.cursor', 'mcp.json'),
  // Generic
  path.join(os.homedir(), '.mcp', 'config.json'),
  path.join(process.cwd(), 'mcp.json'),
  path.join(process.cwd(), '.mcp', 'config.json'),
];

export function discoverConfigs(): string[] {
  return CONFIG_PATHS.filter(p => {
    try { return fs.existsSync(p); } catch { return false; }
  });
}

export function loadConfig(configPath: string): MCPConfig {
  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = JSON.parse(raw);

  // Handle both { mcpServers: {} } and { servers: {} } formats
  const servers = parsed.mcpServers || parsed.servers || {};
  return { mcpServers: servers };
}

export function loadConfigFromPath(configPath: string): MCPConfig | null {
  try {
    const resolved = path.resolve(configPath);
    if (!fs.existsSync(resolved)) return null;
    return loadConfig(resolved);
  } catch {
    return null;
  }
}

export function autoDetectConfig(): { config: MCPConfig; path: string } | null {
  // Check environment variable first
  const envPath = process.env.MCP_CONFIG_PATH;
  if (envPath) {
    const config = loadConfigFromPath(envPath);
    if (config) return { config, path: envPath };
  }

  // Scan known locations
  for (const p of CONFIG_PATHS) {
    try {
      if (fs.existsSync(p)) {
        return { config: loadConfig(p), path: p };
      }
    } catch { continue; }
  }

  return null;
}

export function getServerType(config: MCPServerConfig): string {
  const cmd = config.command?.toLowerCase() || '';
  if (cmd === 'npx' || cmd === 'bunx') return 'npm';
  if (cmd === 'uvx' || cmd === 'python' || cmd === 'python3') return 'pypi';
  if (cmd === 'docker' || cmd.includes('docker')) return 'docker';
  if (cmd === 'node') return 'node';
  if (cmd.includes('/')) return 'local';
  return 'unknown';
}
