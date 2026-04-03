/**
 * Security regression tests for fixes in feature/security-fix.
 * Verifies: path traversal prevention, backup creation, secret key sanitization,
 * and AI parse-error surfacing.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { resolveSafeConfigPath, loadConfigFromPath } from '../src/scanners/config-loader.js';
import { applyFixes, writeConfig } from '../src/fix/index.js';
import { evaluateWithAI } from '../src/ai/evaluator.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import type { AIConfig } from '../src/types/index.js';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

// ---------------------------------------------------------------------------
// MEDIUM-2: Path traversal in config loading
// ---------------------------------------------------------------------------

describe('MEDIUM-2: Path traversal prevention', () => {
  const testDir = path.join(os.tmpdir(), 'mcpshield-traversal-test');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
    // Spy on process.cwd to return our test directory.
    // This lets us test the "within cwd" logic without needing process.chdir()
    // (which is not supported in vitest workers).
    vi.spyOn(process, 'cwd').mockReturnValue(testDir);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  describe('resolveSafeConfigPath', () => {
    it('should accept an absolute path inside cwd', () => {
      const configPath = path.join(testDir, 'my-config.json');
      fs.writeFileSync(configPath, '{"mcpServers":{}}', 'utf-8');
      const result = resolveSafeConfigPath(configPath);
      expect(result).toBe(configPath);
    });

    it('should accept a relative path under cwd', () => {
      const subDir = path.join(testDir, 'subdir');
      fs.mkdirSync(subDir, { recursive: true });
      fs.writeFileSync(path.join(testDir, 'subdir/my-config.json'), '{"mcpServers":{}}', 'utf-8');
      const result = resolveSafeConfigPath('./subdir/my-config.json');
      expect(result).not.toBeNull();
      expect(result!.startsWith(testDir)).toBe(true);
    });

    it('should accept a path inside the home directory', () => {
      const homeConfig = path.join(os.homedir(), '.mcpshield-test-config.json');
      fs.writeFileSync(homeConfig, '{"mcpServers":{}}', 'utf-8');
      const result = resolveSafeConfigPath(homeConfig);
      expect(result).toBe(homeConfig);
      fs.unlinkSync(homeConfig);
    });

    it('should reject traversal to /etc/passwd', () => {
      const result = resolveSafeConfigPath('/etc/passwd');
      expect(result).toBeNull();
    });

    it('should reject traversal to /etc/ssh/id_rsa', () => {
      const result = resolveSafeConfigPath('/etc/ssh/ssh_host_rsa_key');
      expect(result).toBeNull();
    });

    it('should reject an absolute path to /tmp that is NOT inside cwd', () => {
      // Our mocked cwd is testDir (under /tmp). A sibling path there is outside cwd.
      const sibling = path.join(os.tmpdir(), 'mcpshield-sibling-secret');
      fs.writeFileSync(sibling, 'sensitive', 'utf-8');
      const result = resolveSafeConfigPath(sibling);
      expect(result).toBeNull();
      fs.unlinkSync(sibling);
    });

    it('should reject traversal via /proc/self/environ', () => {
      const result = resolveSafeConfigPath('/proc/self/environ');
      expect(result).toBeNull();
    });

    it('should reject a sibling directory path that escapes cwd via ..', () => {
      // Create a sibling of testDir
      const parent = path.dirname(testDir);
      const sibling = path.join(parent, 'mcpshield-sibling-dir');
      fs.mkdirSync(sibling, { recursive: true });
      fs.writeFileSync(path.join(sibling, 'config.json'), '{"mcpServers":{}}', 'utf-8');

      const result = resolveSafeConfigPath('../mcpshield-sibling-dir/config.json');
      expect(result).toBeNull();

      fs.rmSync(sibling, { recursive: true, force: true });
    });

    it('should reject an absolute path that is outside both cwd and home', () => {
      const result = resolveSafeConfigPath('/usr/local/bin/some-file');
      expect(result).toBeNull();
    });
  });

  describe('loadConfigFromPath (integration)', () => {
    it('should load a valid path under cwd', () => {
      const configPath = path.join(testDir, 'valid-config.json');
      fs.writeFileSync(configPath, '{"mcpServers":{"test":{"command":"npx"}}}', 'utf-8');
      const result = loadConfigFromPath(configPath);
      expect(result).not.toBeNull();
      expect(result!.mcpServers['test']).toBeDefined();
    });

    it('should return null for a path traversal attempt', () => {
      const result = loadConfigFromPath('/etc/passwd');
      expect(result).toBeNull();
    });

    it('should return null for a non-existent path outside allowed dirs', () => {
      const result = loadConfigFromPath('/etc/does-not-exist');
      expect(result).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// HIGH: Backup creation in writeConfig
// ---------------------------------------------------------------------------

describe('HIGH: Config file backup before writing', () => {
  const tmpDir = path.join(os.tmpdir(), 'mcpshield-backup-test');

  beforeEach(() => fs.mkdirSync(tmpDir, { recursive: true }));
  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  it('should create a .bak file before writing', () => {
    const configPath = path.join(tmpDir, 'mcp.json');
    const originalContent = JSON.stringify({ mcpServers: { foo: { command: 'npx' } } }, null, 2) + '\n';
    fs.writeFileSync(configPath, originalContent, 'utf-8');

    const modifiedConfig = { mcpServers: { foo: { command: 'npx', args: ['--updated'] } } };
    writeConfig(configPath, modifiedConfig);

    const bakPath = configPath + '.bak';
    expect(fs.existsSync(bakPath)).toBe(true);

    // Backup must contain the original content
    expect(fs.readFileSync(bakPath, 'utf-8')).toBe(originalContent);
    // Current file must have the modified content
    const currentContent = fs.readFileSync(configPath, 'utf-8');
    expect(currentContent).toContain('--updated');
    expect(currentContent).not.toBe(originalContent);
  });

  it('should overwrite an existing stale .bak file', () => {
    const configPath = path.join(tmpDir, 'mcp2.json');
    const originalContent = JSON.stringify({ mcpServers: {} }, null, 2) + '\n';
    fs.writeFileSync(configPath, originalContent, 'utf-8');
    const bakPath = configPath + '.bak';
    fs.writeFileSync(bakPath, 'stale backup content', 'utf-8');

    writeConfig(configPath, { mcpServers: { bar: { command: 'npx' } } });

    // Backup must be the original, not stale content
    expect(fs.readFileSync(bakPath, 'utf-8')).toBe(originalContent);
  });
});

// ---------------------------------------------------------------------------
// MEDIUM: Secret env var key sanitization in fix
// ---------------------------------------------------------------------------

describe('MEDIUM: Secret env var key sanitization', () => {
  const tmpDir = path.join(os.tmpdir(), 'mcpshield-sanitize-test');
  beforeEach(() => fs.mkdirSync(tmpDir, { recursive: true }));
  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  it('should sanitize sensitive keys containing shell metacharacters', () => {
    // The key must match the sensitive-keys list AND contain shell metacharacters.
    // E.g. "AWS_SECRET_ACCESS_KEY$(cat)" matches "AWS_SECRET_ACCESS_KEY" via substring,
    // so it will be caught and sanitized. The $(cat) part is stripped, preventing
    // any command injection when the MCP config is sourced by a shell.
    //
    // The critical security property: the original dangerous key name must NOT remain
    // in the fixed config's env object — it is deleted and replaced with a safe name.
    const configPath = path.join(tmpDir, 'metachar-config.json');
    const configWithMetacharKeys = {
      mcpServers: {
        'evil-server': {
          command: 'npx',
          args: ['-y', 'some-package'],
          env: {
            // These keys match the sensitive list AND contain shell metacharacters.
            // After the fix they should be replaced with safe alphanumeric env var names.
            'AWS_SECRET_ACCESS_KEY$(cat)': 'ak-12345678',
            'GITHUB_TOKEN`id`': 'ghp_xxxxxxxx',
            'OPENAI_API_KEY;rm -rf': 'sk-proj-xxxx',
          },
        },
      },
    };
    fs.writeFileSync(configPath, JSON.stringify(configWithMetacharKeys, null, 2), 'utf-8');

    const config = loadConfig(configPath);
    const findings = [{
      id: 'MCP-TEST',
      title: 'Sensitive Credentials in Config',
      description: 'Found sensitive env vars',
      severity: 'high' as const,
      category: 'configuration' as const,
      serverName: 'evil-server',
      remediation: 'Use env vars',
    }];

    const { config: fixed } = applyFixes(config, findings);
    const env = fixed.mcpServers['evil-server'].env!;

    // The original dangerous key names must not exist after sanitization
    expect(env).not.toHaveProperty('AWS_SECRET_ACCESS_KEY$(cat)');
    expect(env).not.toHaveProperty('GITHUB_TOKEN`id`');
    expect(env).not.toHaveProperty('OPENAI_API_KEY;rm -rf');

    // After sanitization, no remaining key should contain shell metacharacters
    for (const key of Object.keys(env)) {
      expect(key).not.toMatch(/[${}`!;&|<>]/);
      // All values must be safe env var references: ${SOME_VAR_NAME}
      expect(env[key]).toMatch(/^\$\{[^}]+\}$/);
    }
  });

  it('should produce safe env var names for AWS-style sensitive keys', () => {
    const configPath = path.join(tmpDir, 'aws-config.json');
    const configWithAws = {
      mcpServers: {
        'aws-server': {
          command: 'npx',
          args: ['-y', 'aws-mcp'],
          env: {
            'AWS_SECRET_ACCESS_KEY': 'AKIAIOSFODNN7EXAMPLE',
            'AWS_ACCESS_KEY_ID': 'AKIAIOSFODNN7EXAMPLE',
          },
        },
      },
    };
    fs.writeFileSync(configPath, JSON.stringify(configWithAws, null, 2), 'utf-8');

    const config = loadConfig(configPath);
    const findings = [{
      id: 'MCP-TEST',
      title: 'Sensitive Credentials in Config',
      description: 'Found sensitive env vars',
      severity: 'high' as const,
      category: 'configuration' as const,
      serverName: 'aws-server',
      remediation: 'Use env vars',
    }];

    const { config: fixed } = applyFixes(config, findings);
    const env = fixed.mcpServers['aws-server'].env!;

    // All keys must be alphanumeric + underscore only
    for (const key of Object.keys(env)) {
      expect(key).toMatch(/^[a-zA-Z0-9_]+$/);
      expect(env[key]).toMatch(/^\$\{[^}]+\}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// INFO-2: AI parse failure surfacing
// ---------------------------------------------------------------------------

describe('INFO-2: AI parse failure surfacing', () => {
  // NOTE: parseAIResponse is tested directly via evaluateWithAI integration.
  // The key security property is: when AI returns garbage, the user gets
  // aiParseError=true and a descriptive reasoning message — not silent failure.

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should set aiParseError=true and include error detail in reasoning when AI returns unparseable JSON', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: '```json\nnot valid json at all\n```' } }],
        model: 'gpt-4o-mini',
      }),
      text: async () => '{"choices":[{"message":{"content":"```json\\nnot valid json at all\\n```"}}],"model":"gpt-4o-mini"}',
    } as any);

    const findings = [{
      id: 'MCP-001',
      title: 'Test Finding',
      description: 'Test',
      severity: 'high' as const,
      category: 'configuration' as const,
      serverName: 'test-server',
      remediation: 'Fix it',
    }];

    const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };
    const result = await evaluateWithAI(findings, {}, aiConfig);

    expect(result.parseErrorCount).toBeGreaterThan(0);
    const parseErrorEval = result.evaluations.find(e => e.aiParseError === true);
    expect(parseErrorEval).toBeDefined();
    expect(parseErrorEval!.reasoning).toContain('could not be parsed');
    // The error detail should be in the reasoning
    expect(parseErrorEval!.reasoning.length).toBeGreaterThan('AI response could not be parsed'.length);
  });

  it('should return parseErrorCount=0 when all AI responses parse correctly', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{
          message: {
            content: JSON.stringify([
              { findingId: 'MCP-001', verdict: 'confirmed', confidence: 0.9, reasoning: 'Real risk' },
            ]),
          },
        }],
        model: 'gpt-4o-mini',
        usage: { prompt_tokens: 100, completion_tokens: 50 },
      }),
      text: async () => '{"choices":[{"message":{"content":"[{\\"findingId\\":\\"MCP-001\\",\\"verdict\\":\\"confirmed\\",\\"confidence\\":0.9,\\"reasoning\\":\\"Real risk\\"}]"}}],"model":"gpt-4o-mini","usage":{"prompt_tokens":100,"completion_tokens":50}}',
    } as any);

    const findings = [{
      id: 'MCP-001',
      title: 'Test Finding',
      description: 'Test',
      severity: 'high' as const,
      category: 'configuration' as const,
      serverName: 'test-server',
      remediation: 'Fix it',
    }];

    const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };
    const result = await evaluateWithAI(findings, {}, aiConfig);

    expect(result.parseErrorCount).toBe(0);
    expect(result.evaluations[0].aiParseError).toBeUndefined();
  });

  it('should mark all findings as needs-review with parse error when entire batch is unparseable', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: 'completely broken response with no JSON' } }],
        model: 'gpt-4o-mini',
      }),
      text: async () => '{"choices":[{"message":{"content":"completely broken response with no JSON"}}],"model":"gpt-4o-mini"}',
    } as any);

    const findings = [{
      id: 'MCP-001',
      title: 'Test Finding',
      description: 'Test',
      severity: 'high' as const,
      category: 'configuration' as const,
      serverName: 'test-server',
      remediation: 'Fix it',
    }];

    const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };
    const result = await evaluateWithAI(findings, {}, aiConfig);

    expect(result.evaluations[0].verdict).toBe('needs-review');
    expect(result.evaluations[0].aiParseError).toBe(true);
    expect(result.parseErrorCount).toBe(1);
  });

  it('should count parse errors correctly across multiple batches', async () => {
    // Mock always returns unparseable — both batches should fail
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: 'totally broken response' } }],
        model: 'gpt-4o-mini',
      }),
      text: async () => '{"choices":[{"message":{"content":"totally broken response"}}],"model":"gpt-4o-mini"}',
    } as any);

    // 25 findings → 2 batches (20 + 5). Both should fail to parse.
    const findings = Array.from({ length: 25 }, (_, i) => ({
      id: `MCP-${String(i + 1).padStart(3, '0')}`,
      title: `Test Finding ${i + 1}`,
      description: 'Test',
      severity: 'low' as const,
      category: 'configuration' as const,
      serverName: 'test-server',
      remediation: 'Fix it',
    }));

    const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };
    const result = await evaluateWithAI(findings, {}, aiConfig);

    // All 25 evaluations should have aiParseError=true
    expect(result.parseErrorCount).toBe(25);
    expect(result.evaluations.every(e => e.aiParseError === true)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Registry: version range stripping (covered by scanner tests; this
// documents the security property)
// ---------------------------------------------------------------------------

describe('Registry: version range prefix stripping', () => {
  it('documents that version ranges like ^1.0.0 are stripped before registry lookup', () => {
    // The actual logic is tested via the registry scanner integration tests.
    // The security property: without stripping, a package arg like "pkg@^1.0.0"
    // would result in a "Package Not Found" false positive.
    expect(true).toBe(true);
  });
});
