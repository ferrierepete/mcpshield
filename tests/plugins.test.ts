import { describe, it, expect, beforeEach } from 'vitest';
import { pluginRegistry, definePlugin } from '../src/plugins/index.js';
import { createFinding, resetCounter } from '../src/utils/helpers.js';

describe('Plugin System', () => {
  beforeEach(() => {
    pluginRegistry.clear();
    resetCounter();
  });

  it('should register and retrieve a plugin', () => {
    const plugin = definePlugin({
      name: 'test-plugin',
      description: 'A test plugin',
      scan: () => [],
    });
    pluginRegistry.register(plugin);
    expect(pluginRegistry.has('test-plugin')).toBe(true);
    expect(pluginRegistry.get('test-plugin')).toBe(plugin);
  });

  it('should prevent duplicate registration', () => {
    pluginRegistry.register(definePlugin({
      name: 'dup', description: 'dup', scan: () => [],
    }));
    expect(() => pluginRegistry.register(definePlugin({
      name: 'dup', description: 'dup2', scan: () => [],
    }))).toThrow('already registered');
  });

  it('should unregister a plugin', () => {
    pluginRegistry.register(definePlugin({
      name: 'removable', description: 'test', scan: () => [],
    }));
    expect(pluginRegistry.unregister('removable')).toBe(true);
    expect(pluginRegistry.has('removable')).toBe(false);
  });

  it('should return all registered plugins', () => {
    pluginRegistry.register(definePlugin({ name: 'a', description: 'a', scan: () => [] }));
    pluginRegistry.register(definePlugin({ name: 'b', description: 'b', scan: () => [] }));
    expect(pluginRegistry.getAll()).toHaveLength(2);
  });

  it('should run all plugins and collect findings', async () => {
    pluginRegistry.register(definePlugin({
      name: 'finding-plugin',
      description: 'Generates a finding',
      scan: (name) => [
        createFinding({
          title: 'Custom Finding',
          description: 'Found by plugin',
          severity: 'medium',
          category: 'configuration',
          serverName: name,
          remediation: 'Fix it',
        }),
      ],
    }));

    const findings = await pluginRegistry.runAll('test-server', {
      command: 'node', args: ['server.js'],
    });
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe('Custom Finding');
  });

  it('should handle plugin errors gracefully', async () => {
    pluginRegistry.register(definePlugin({
      name: 'crashing-plugin',
      description: 'This plugin crashes',
      scan: () => { throw new Error('Plugin crash'); },
    }));
    pluginRegistry.register(definePlugin({
      name: 'working-plugin',
      description: 'This works',
      scan: () => [
        createFinding({
          title: 'Works', description: 'OK', severity: 'info',
          category: 'configuration', serverName: 'test', remediation: 'none',
        }),
      ],
    }));

    // Should not throw; crashing plugin's error is caught
    const findings = await pluginRegistry.runAll('test', { command: 'node' });
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe('Works');
  });

  it('should support async plugin scanners', async () => {
    pluginRegistry.register(definePlugin({
      name: 'async-plugin',
      description: 'Async scanner',
      scan: async (name) => {
        await new Promise(r => setTimeout(r, 10));
        return [createFinding({
          title: 'Async Finding', description: 'From async', severity: 'low',
          category: 'configuration', serverName: name, remediation: 'none',
        })];
      },
    }));

    const findings = await pluginRegistry.runAll('server', { command: 'node' });
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toBe('Async Finding');
  });
});
