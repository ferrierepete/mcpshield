import { MCPServerConfig, Finding } from '../types/index.js';

/**
 * A plugin scanner function receives a server name and config,
 * and returns an array of findings (or empty array).
 */
export type PluginScanner = (name: string, config: MCPServerConfig) => Finding[] | Promise<Finding[]>;

export interface Plugin {
  /** Unique name for the plugin */
  name: string;
  /** Short description of what the plugin checks */
  description: string;
  /** The scanner function */
  scan: PluginScanner;
}

class PluginRegistry {
  private plugins: Map<string, Plugin> = new Map();

  register(plugin: Plugin): void {
    if (this.plugins.has(plugin.name)) {
      throw new Error(`Plugin "${plugin.name}" is already registered.`);
    }
    this.plugins.set(plugin.name, plugin);
  }

  unregister(name: string): boolean {
    return this.plugins.delete(name);
  }

  get(name: string): Plugin | undefined {
    return this.plugins.get(name);
  }

  getAll(): Plugin[] {
    return Array.from(this.plugins.values());
  }

  has(name: string): boolean {
    return this.plugins.has(name);
  }

  clear(): void {
    this.plugins.clear();
  }

  async runAll(serverName: string, config: MCPServerConfig): Promise<Finding[]> {
    const allFindings: Finding[] = [];
    for (const plugin of this.plugins.values()) {
      try {
        const findings = await plugin.scan(serverName, config);
        allFindings.push(...findings);
      } catch (e: any) {
        // Plugin errors should not crash the scan
        console.error(`Plugin "${plugin.name}" failed: ${e.message}`);
      }
    }
    return allFindings;
  }
}

// Singleton registry
export const pluginRegistry = new PluginRegistry();

/**
 * Helper to define a plugin with type safety.
 */
export function definePlugin(plugin: Plugin): Plugin {
  return plugin;
}
