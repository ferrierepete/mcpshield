import { describe, it, expect } from 'vitest';
import { loadConfig, getServerType, discoverConfigs } from '../src/scanners/config-loader.js';
import * as path from 'path';

const FIXTURE_DIR = path.join(__dirname, 'fixtures');

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
      const fs = require('fs');
      const tmpPath = '/tmp/mcpshield-malformed-test.json';
      fs.writeFileSync(tmpPath, '{ invalid json }', 'utf-8');
      expect(() => loadConfig(tmpPath)).toThrow();
      fs.unlinkSync(tmpPath);
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
});
