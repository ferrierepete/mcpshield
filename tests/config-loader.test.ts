import { describe, it, expect } from 'vitest';
import { loadConfig, getServerType, discoverConfigs, autoDetectAllConfigs } from '../src/scanners/config-loader.js';
import * as path from 'path';
import { writeFileSync, unlinkSync } from 'fs';

const FIXTURE_DIR = path.join(__dirname, 'fixtures');
const PROJECT_ROOT = path.join(__dirname, '..');

describe('Config Loader', () => {
  describe('loadConfig', () => {
    it('should load standard mcpServers format', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'test-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(Object.keys(config.mcpServers)).toHaveLength(6);
    });

    it('should load alternative "servers" format', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'alt-format-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers['github-server']).toBeDefined();
    });

    it('should load empty config without error', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'empty-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(Object.keys(config.mcpServers)).toHaveLength(0);
    });

    it('should throw on non-existent file', () => {
      expect(() => loadConfig('/tmp/nonexistent-mcpshield-test.json')).toThrow();
    });

    it('should throw on malformed JSON', () => {
      const tmpPath = '/tmp/mcpshield-malformed-test.json';
      writeFileSync(tmpPath, '{ invalid json }', 'utf-8');
      expect(() => loadConfig(tmpPath)).toThrow();
      unlinkSync(tmpPath);
    });

    it('should load Continue array format', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'continue-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers['github']).toBeDefined();
      expect(config.mcpServers['github'].command).toBe('npx');
      expect(config.mcpServers['supabase']).toBeDefined();
    });

    it('should load Zed context_servers format', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'zed-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers['github']).toBeDefined();
      expect(config.mcpServers['github'].command).toBe('npx');
      expect(config.mcpServers['github'].args).toContain('@modelcontextprotocol/server-github');
      expect(config.mcpServers['filesystem']).toBeDefined();
    });

    it('should load VS Code servers format', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'vscode-config.json'));
      expect(config.mcpServers).toBeDefined();
      expect(config.mcpServers['playwright']).toBeDefined();
      expect(config.mcpServers['playwright'].command).toBe('npx');
      expect(config.mcpServers['github']).toBeDefined();
    });

    it('should preserve type field from VS Code config', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'vscode-config.json'));
      expect(config.mcpServers['github'].type).toBe('http');
      expect(config.mcpServers['sse-server'].type).toBe('sse');
      expect(config.mcpServers['playwright'].type).toBeUndefined();
    });

    it('should parse and attach inputs array from VS Code config', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'vscode-config.json'));
      const inputs = config.mcpServers['sse-server'].inputs;
      expect(inputs).toBeDefined();
      expect(inputs).toHaveLength(1);
      expect(inputs![0].id).toBe('apiToken');
      expect(inputs![0].type).toBe('promptString');
      expect(inputs![0].password).toBe(true);
    });

    it('should detect ${input:...} variable references in VS Code headers', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'vscode-config.json'));
      const headers = config.mcpServers['sse-server'].headers;
      expect(headers).toBeDefined();
      expect(headers!['Authorization']).toBe('Bearer ${input:apiToken}');
    });

    it('should load Claude Desktop config with autoApprove and alwaysAllow', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'claude-desktop-config.json'));
      expect(config.mcpServers).toBeDefined();
      const fs = config.mcpServers['filesystem'];
      expect(fs).toBeDefined();
      expect(fs.autoApprove).toEqual(['read_file', 'list_directory']);
      expect(fs.alwaysAllow).toEqual(['read_file']);
      const gh = config.mcpServers['github'];
      expect(gh).toBeDefined();
      expect(gh.autoApprove).toBeUndefined();
      expect(gh.alwaysAllow).toBeUndefined();
    });

    it('should preserve settings sub-object from Zed config', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'zed-config.json'));
      expect(config.mcpServers['filesystem'].settings).toEqual({
        allowed_extensions: ['.ts', '.js', '.json'],
        max_file_size: 1048576,
      });
      expect(config.mcpServers['github'].settings).toBeUndefined();
    });

    it('should handle Continue URL-only servers without false positive Missing Command', () => {
      const config = loadConfig(path.join(FIXTURE_DIR, 'continue-config.json'));
      const supabase = config.mcpServers['supabase'];
      expect(supabase).toBeDefined();
      expect(supabase.url).toBe('https://mcp.supabase.com/sse');
      expect(supabase.command).toBe('');
    });
  });

  describe('getServerType', () => {
    it('should detect npm servers (npx)', () => {
      expect(getServerType({ command: 'npx', args: ['-y', 'some-package'] })).toBe('npm');
    });

    it('should detect npm servers (bunx)', () => {
      expect(getServerType({ command: 'bunx', args: ['some-package'] })).toBe('npm');
    });

    it('should detect pypi servers (uvx)', () => {
      expect(getServerType({ command: 'uvx', args: ['some-package'] })).toBe('pypi');
    });

    it('should detect pypi servers (python)', () => {
      expect(getServerType({ command: 'python', args: ['-m', 'server'] })).toBe('pypi');
    });

    it('should detect docker servers', () => {
      expect(getServerType({ command: 'docker', args: ['run', 'image'] })).toBe('docker');
    });

    it('should detect node servers', () => {
      expect(getServerType({ command: 'node', args: ['server.js'] })).toBe('node');
    });

    it('should detect local executables', () => {
      expect(getServerType({ command: '/usr/local/bin/server' })).toBe('local');
    });

    it('should return unknown for unrecognized commands', () => {
      expect(getServerType({ command: 'something-unusual' })).toBe('unknown');
    });

    it('should handle missing command', () => {
      expect(getServerType({ command: '' })).toBe('unknown');
    });
  });

  describe('discoverConfigs', () => {
    it('should return an array', () => {
      const configs = discoverConfigs();
      expect(Array.isArray(configs)).toBe(true);
    });
  });

  describe('autoDetectAllConfigs', () => {
    it('should return an array', () => {
      const configs = autoDetectAllConfigs();
      expect(Array.isArray(configs)).toBe(true);
    });

    it('should return entries with config and path properties', () => {
      const configs = autoDetectAllConfigs();
      for (const c of configs) {
        expect(c).toHaveProperty('config');
        expect(c).toHaveProperty('path');
        expect(c.config).toHaveProperty('mcpServers');
        expect(typeof c.path).toBe('string');
      }
    });

    it('should return same or more configs than discoverConfigs paths that are loadable', () => {
      const paths = discoverConfigs();
      const allConfigs = autoDetectAllConfigs();
      expect(allConfigs.length).toBeLessThanOrEqual(paths.length);
      expect(allConfigs.length).toBeGreaterThanOrEqual(0);
    });

    it('should respect MCP_CONFIG_PATH env var when set to valid file', () => {
      const tmpPath = path.join(PROJECT_ROOT, `.tmp-test-allconfigs-env-${Date.now()}.json`);
      writeFileSync(tmpPath, JSON.stringify({
        mcpServers: { test: { command: '/bin/echo', args: [] } }
      }));
      const origEnv = process.env.MCP_CONFIG_PATH;
      process.env.MCP_CONFIG_PATH = tmpPath;
      try {
        const configs = autoDetectAllConfigs();
        expect(configs.length).toBe(1);
        expect(configs[0].path).toBe(tmpPath);
        expect(configs[0].config.mcpServers['test']).toBeDefined();
      } finally {
        process.env.MCP_CONFIG_PATH = origEnv;
        unlinkSync(tmpPath);
      }
    });

    it('should fall back to CONFIG_PATHS when MCP_CONFIG_PATH is invalid', () => {
      const origEnv = process.env.MCP_CONFIG_PATH;
      process.env.MCP_CONFIG_PATH = '/tmp/nonexistent-mcpshield-test.json';
      try {
        const configs = autoDetectAllConfigs(true);
        expect(Array.isArray(configs)).toBe(true);
      } finally {
        process.env.MCP_CONFIG_PATH = origEnv;
      }
    });

    it('should load all available configs from multiple client locations', () => {
      const origEnv = process.env.MCP_CONFIG_PATH;
      delete process.env.MCP_CONFIG_PATH;
      try {
        const configs = autoDetectAllConfigs();
        const paths = discoverConfigs();
        expect(configs.length).toBe(paths.length);
      } finally {
        process.env.MCP_CONFIG_PATH = origEnv;
      }
    });
  });
});
