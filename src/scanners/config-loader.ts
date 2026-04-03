import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { MCPConfig, MCPServerConfig } from '../types/index.js';

const CONFIG_PATHS = [
  // Claude Desktop
  path.join(os.homedir(), 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'), // macOS
  path.join(os.homedir(), '.config', 'Claude', 'claude_desktop_config.json'), // Linux
  path.join(process.env.APPDATA || '', 'Claude', 'claude_desktop_config.json'), // Windows

  // Claude Code
  path.join(os.homedir(), '.claude.json'), // user/local scope
  path.join(process.cwd(), '.mcp.json'), // project scope
  path.join(process.cwd(), '.claude', 'settings.local.json'), // local scope

  // VS Code
  path.join(process.cwd(), '.vscode', 'mcp.json'), // workspace scope

  // Cursor
  path.join(os.homedir(), '.cursor', 'mcp.json'), // global
  path.join(process.cwd(), '.cursor', 'mcp.json'), // project scope

  // Windsurf
  path.join(os.homedir(), '.codeium', 'windsurf', 'mcp_config.json'),

  // Continue
  path.join(os.homedir(), '.continue', 'config.json'),

  // Zed
  path.join(os.homedir(), '.config', 'zed', 'settings.json'),
];

export function discoverConfigs(): string[] {
  return CONFIG_PATHS.filter(p => {
    try { return fs.existsSync(p); } catch { return false; }
  });
}

export function loadConfig(configPath: string): MCPConfig {
  const raw = fs.readFileSync(configPath, 'utf-8');
  const parsed = JSON.parse(raw);

  // 1. Standard format: { mcpServers: { name: config } }
  //    Used by Claude Desktop, Cursor, Windsurf, Claude Code (.mcp.json)
  if (parsed.mcpServers && !Array.isArray(parsed.mcpServers)) {
    return { mcpServers: parsed.mcpServers };
  }

  // 2. VS Code format: { servers: { name: config } }
  if (parsed.servers && typeof parsed.servers === 'object' && !Array.isArray(parsed.servers)) {
    return { mcpServers: parsed.servers };
  }

  // 3. Continue format: { mcpServers: [ { name: "x", command: "..." } ] }
  if (Array.isArray(parsed.mcpServers)) {
    const servers: Record<string, MCPServerConfig> = {};
    for (const entry of parsed.mcpServers) {
      if (entry.name) {
        const { name, ...config } = entry;
        servers[name] = config as MCPServerConfig;
      }
    }
    return { mcpServers: servers };
  }

  // 4. Zed format: { context_servers: { name: { command: { path, args, env } } } }
  if (parsed.context_servers && typeof parsed.context_servers === 'object') {
    const servers: Record<string, MCPServerConfig> = {};
    for (const [name, entry] of Object.entries(parsed.context_servers)) {
      const zedEntry = entry as { command?: { path?: string; args?: string[]; env?: Record<string, string> } };
      if (zedEntry.command) {
        servers[name] = {
          command: zedEntry.command.path || '',
          args: zedEntry.command.args,
          env: zedEntry.command.env,
        };
      }
    }
    return { mcpServers: servers };
  }

  return { mcpServers: {} };
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
