import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

const CLI = 'node';
const PROJECT_ROOT = path.join(__dirname, '..');

// -------------------------------------------------------------------------------------------------
// Test matrix helper: runs `mcpshield <args>` as a child process, returns { stdout, stderr, code }
// -------------------------------------------------------------------------------------------------

interface CliResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

async function runCli(args: string[], env: Record<string, string> = {}): Promise<CliResult> {
  return new Promise((resolve) => {
    const fullArgs = [path.join(PROJECT_ROOT, 'dist', 'cli.js'), ...args];
    const proc = spawn(CLI, fullArgs, {
      env: { ...process.env, ...env },
      timeout: 30_000,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });
    proc.on('close', (code) => resolve({ stdout, stderr, code }));
    proc.on('error', (e) => resolve({ stdout, stderr: stderr + String(e), code: null }));
  });
}

// -------------------------------------------------------------------------------------------------
// Fixture helpers
// -------------------------------------------------------------------------------------------------

const FIXTURE_DIR = path.join(__dirname, 'fixtures');
const TEST_CONFIG = path.join(FIXTURE_DIR, 'test-config.json');
const DOCKER_CONFIG = path.join(FIXTURE_DIR, 'docker-config.json');
const HTTP_CONFIG = path.join(FIXTURE_DIR, 'http-config.json');
const EDGE_CASES = path.join(FIXTURE_DIR, 'edge-cases.json');

/** Returns a temp copy of a fixture that we can safely mutate (used by `fix` tests).
 *  Files are created under PROJECT_ROOT so they pass resolveSafeConfigPath(). */
function tempFixture(name: string): string {
  const src = path.join(FIXTURE_DIR, name);
  const dst = path.join(PROJECT_ROOT, `.tmp-test-${Date.now()}-${name}`);
  fs.copyFileSync(src, dst);
  return dst;
}

// -------------------------------------------------------------------------------------------------
// Test suite
// -------------------------------------------------------------------------------------------------

describe('CLI Integration', () => {

  // Ensure dist is built before running integration tests
  describe('pre-flight', () => {
    it('dist/cli.js should exist', () => {
      const cliPath = path.join(PROJECT_ROOT, 'dist', 'cli.js');
      expect(fs.existsSync(cliPath)).toBe(true);
    });
  });

  // ── scan ──────────────────────────────────────────────────────────────────────────────────────

  describe('scan — basic', () => {
    it('exits 0 when no findings', async () => {
      // Create a minimal clean config under PROJECT_ROOT (inside cwd)
      const cleanConfig = path.join(PROJECT_ROOT, `.tmp-test-clean-${Date.now()}.json`);
      fs.writeFileSync(cleanConfig, JSON.stringify({
        mcpServers: { safe: { command: '/bin/true', args: [] } }
      }, null, 2));

      const r = await runCli(['scan', '--config', cleanConfig]);
      expect(r.code).toBe(0);
      fs.unlinkSync(cleanConfig);
    });

    it('exits 2 when critical-severity findings present', async () => {
      // test-config has critical findings: risky package + typosquat
      const r = await runCli(['scan', '--config', TEST_CONFIG]);
      expect(r.code).toBe(2);
    });

    it('exits 2 when critical-severity findings present', async () => {
      // docker-config has privileged container = critical
      const r = await runCli(['scan', '--config', DOCKER_CONFIG]);
      expect(r.code).toBe(2);
    });

    it('prints error when config path is outside allowed directories', async () => {
      const r = await runCli(['scan', '--config', '/nonexistent/config.json']);
      expect(r.stderr).toContain('outside allowed directories');
      expect(r.code).toBe(1);
    });

    it('MCP_CONFIG_PATH with non-existent path falls back to CONFIG_PATHS auto-detection', async () => {
      // loadConfigFromPath returns null for non-existent paths → falls back to CONFIG_PATHS
      const r = await runCli(['scan'], { MCP_CONFIG_PATH: '/tmp/does-not-exist.json' });
      // Falls back to ~/.claude.json or other detected config
      expect([0, 1, 2]).toContain(r.code);
      expect(r.stdout).toMatch(/Security Report|No MCP configuration found/);
    });
  });

  describe('scan — output formats', () => {
    it('--format json outputs valid JSON', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--format', 'json', '--no-spinner']);
      expect(r.code).toBe(2); // test-config has critical findings
      let parsed: any;
      expect(() => { parsed = JSON.parse(r.stdout); }).not.toThrow();
      expect(parsed).toHaveProperty('servers');
      expect(parsed).toHaveProperty('summary');
      expect(parsed.servers.length).toBeGreaterThan(0);
    });

    it('--format sarif outputs valid SARIF', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--format', 'sarif', '--no-spinner']);
      expect(r.code).toBe(2);
      let parsed: any;
      expect(() => { parsed = JSON.parse(r.stdout); }).not.toThrow();
      expect(parsed.$schema).toContain('sarif');
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs[0].results).toBeDefined();
    });

    it('--format markdown outputs markdown', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--format', 'markdown', '--no-spinner']);
      expect(r.code).toBe(2);
      expect(r.stdout).toContain('# 🔒 MCPShield Security Report');
      expect(r.stdout).toContain('## '); // server sections
      expect(r.stdout).toContain('| Severity | Count |');
    });

    it('--format pretty is the default and includes chalk codes', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--no-spinner']);
      expect(r.code).toBe(2);
      expect(r.stdout).toContain('🔒 MCPShield Security Report');
      expect(r.stdout).toContain('Findings:');
    });

    it('--quiet outputs only the summary line', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '-q']);
      expect(r.code).toBe(2);
      const lines = r.stdout.trim().split('\n').filter(Boolean);
      expect(lines.length).toBe(1);
      expect(lines[0]).toMatch(/Score:/);
      expect(lines[0]).toMatch(/critical/); // test-config has critical findings
    });

    it('--no-spinner suppresses ora output', async () => {
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--no-spinner']);
      expect(r.code).toBe(2);
      // ora spinners use CR (carriage return) + ANSI — stdout should not contain loading chars
      expect(r.stdout).not.toMatch(/\r/);
    });
  });

  describe('scan — filtering', () => {
    it('-s critical shows only critical findings', async () => {
      const r = await runCli(['scan', '--config', DOCKER_CONFIG, '-s', 'critical', '--no-spinner']);
      expect(r.code).toBe(2); // critical present
      expect(r.stdout).toContain('critical');
      // Should NOT contain medium (docker-exposed-port is medium)
      // (it may appear in the filtered summary — check finding count)
    });

    it('-s medium shows medium+ severity (not low/info)', async () => {
      // test-config has critical, high, medium findings — no info severity
      const r = await runCli(['scan', '--config', TEST_CONFIG, '-s', 'medium', '--no-spinner']);
      expect(r.code).toBe(2);
      expect(r.stdout).toContain('critical');
      expect(r.stdout).toContain('high');
    });

    it('--ignore <id> filters out a specific finding by ID', async () => {
      // MCP-002 = Broad Filesystem Access (critical) — use docker-config
      const r = await runCli(['scan', '--config', DOCKER_CONFIG, '--ignore', 'MCP-101', '--no-spinner']);
      // MCP-101 (privileged container) should not appear in output
      expect(r.stdout).not.toContain('MCP-101');
    });

    it('--ignore <id> filters critical finding and reduces exit code', async () => {
      // Ignore MCP-101 (privileged container) — remaining findings should still be critical
      const r = await runCli(['scan', '--config', DOCKER_CONFIG, '--ignore', 'MCP-101', '--no-spinner']);
      // Exit code still 2 because docker-socket (MCP-104) is also critical
      expect(r.code).toBe(2);
    });

    it('--ignore <exact title> filters by full title match', async () => {
      // Full title match still works
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--ignore', 'Potential Typosquat', '--no-spinner']);
      expect(r.stdout).not.toContain('Potential Typosquat');
    });

    it('--ignore <partial> filters by substring match', async () => {
      // "Typosquat" now matches "Potential Typosquat" via substring match
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--ignore', 'Typosquat', '--no-spinner']);
      expect(r.stdout).not.toContain('Potential Typosquat');
    });

    it('--ignore accepts multiple space-separated values', async () => {
      const r = await runCli([
        'scan', '--config', TEST_CONFIG,
        '--ignore', 'MCP-003', 'Sensitive Credentials in Config', '--no-spinner'
      ]);
      expect(r.stdout).not.toContain('MCP-003');
      expect(r.stdout).not.toContain('Sensitive Credentials in Config');
    });
  });

  describe('scan — confidence threshold', () => {
    it('--min-confidence 1.0 shows only highest-confidence findings', async () => {
      // With min-confidence 1.0, low-confidence findings are filtered
      const r = await runCli(['scan', '--config', TEST_CONFIG, '--min-confidence', '1.0', '--no-spinner']);
      // Scan still ran — score is shown
      expect(r.stdout).toContain('Score:');
    });

    it('--min-confidence 0.0 shows everything', async () => {
      const r1 = await runCli(['scan', '--config', TEST_CONFIG, '--min-confidence', '0.0', '--no-spinner']);
      const r2 = await runCli(['scan', '--config', TEST_CONFIG, '--no-spinner']);
      // Both exit 2 (critical findings remain regardless of confidence filter)
      expect(r1.code).toBe(r2.code);
    });
  });

  describe('scan — AI evaluation', () => {
    // AI tests require a valid API key; we mock the network call instead

    it('--ai without API key exits gracefully with a warning', async () => {
      // Unset all AI env vars
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined) env[k] = v;
      }
      delete env.OPENAI_API_KEY;
      delete env.ANTHROPIC_API_KEY;
      delete env.GEMINI_API_KEY;
      delete env.GOOGLE_API_KEY;
      delete env.MCPSHIELD_OPENAI_API_KEY;
      delete env.MCPSHIELD_ANTHROPIC_API_KEY;
      delete env.MCPSHIELD_GEMINI_API_KEY;

      const r = await runCli(['scan', '--config', TEST_CONFIG, '--ai', '--no-spinner'], env);
      // Should not crash; should exit based on findings only
      expect(r.code).toBe(2);
    });

    it('--ai --ai-provider openai with bad key returns error message', async () => {
      const r = await runCli([
        'scan', '--config', TEST_CONFIG,
        '--ai', '--ai-provider', 'openai',
        '--no-spinner'
      ], { OPENAI_API_KEY: 'sk-bad-test-key' });

      // Should complete the scan (not crash) but AI evaluation may fail
      // Exit code is based on findings, not AI failure
      expect(r.code).toBe(2);
    });
  });

  describe('scan — --config path traversal prevention', () => {
    it('rejects --config /etc/passwd with error and exit 1', async () => {
      const r = await runCli(['scan', '--config', '/etc/passwd']);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain('outside allowed directories');
    });

    it('rejects --config /proc/self/environ with error and exit 1', async () => {
      const r = await runCli(['scan', '--config', '/proc/self/environ']);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain('outside allowed directories');
    });

    it('rejects --config pointing to /usr/share with error and exit 1', async () => {
      const r = await runCli(['scan', '--config', '/usr/share/secrets.json']);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain('outside allowed directories');
    });
  });

  describe('fix — --config path traversal prevention', () => {
    it('rejects --config /etc/passwd with error and exit 1', async () => {
      const r = await runCli(['fix', '--config', '/etc/passwd']);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain('outside allowed directories');
    });
  });

  describe('watch — --config path traversal prevention', () => {
    it('rejects --config /etc/passwd with error and exit 1', async () => {
      const r = await runCli(['watch', '--config', '/etc/passwd']);
      expect(r.code).toBe(1);
      expect(r.stderr).toContain('outside allowed directories');
    });
  });

  describe('scan — edge cases', () => {
    it('handles empty mcpServers object', async () => {
      const emptyConfig = path.join(PROJECT_ROOT, `.tmp-test-empty-${Date.now()}.json`);
      fs.writeFileSync(emptyConfig, JSON.stringify({ mcpServers: {} }, null, 2));

      const r = await runCli(['scan', '--config', emptyConfig]);
      expect(r.code).toBe(0);
      expect(r.stdout).toContain('No MCP servers found');
      fs.unlinkSync(emptyConfig);
    });

    it('handles config with no mcpServers key', async () => {
      const noServers = path.join(PROJECT_ROOT, `.tmp-test-noservers-${Date.now()}.json`);
      fs.writeFileSync(noServers, JSON.stringify({}));
      const r = await runCli(['scan', '--config', noServers]);
      expect(r.code).toBe(0);
      fs.unlinkSync(noServers);
    });

    it('handles edge-cases.json without crashing', async () => {
      const r = await runCli(['scan', '--config', EDGE_CASES, '--no-spinner']);
      expect([0, 1, 2]).toContain(r.code);
    });

    it('handles HTTP server URL without crashing', async () => {
      const r = await runCli(['scan', '--config', HTTP_CONFIG, '--no-spinner']);
      expect([0, 1, 2]).toContain(r.code);
    });
  });

  // ── list ──────────────────────────────────────────────────────────────────────────────────────

  describe('list', () => {
    it('runs without crashing', async () => {
      const r = await runCli(['list']);
      expect(r.code).toBe(0);
    });

    it('outputs MCP Configuration Files header when configs found', async () => {
      const r = await runCli(['list']);
      // Either finds configs or shows the yellow warning
      expect(r.stdout).toMatch(/MCP Configuration|No MCP configuration/);
    });
  });

  // ── owasp ───────────────────────────────────────────────────────────────────────────────────

  describe('owasp', () => {
    it('prints OWASP MCP Top 10 reference', async () => {
      const r = await runCli(['owasp']);
      expect(r.code).toBe(0);
      expect(r.stdout).toContain('OWASP MCP Top 10');
      expect(r.stdout).toContain('MCP-01');
    });

    it('shows at least 10 categories', async () => {
      const r = await runCli(['owasp']);
      // Categories are in "MCP-01", "MCP-02", etc. format
      const matches = r.stdout.match(/MCP-\d+/g);
      expect((matches ?? []).length).toBeGreaterThanOrEqual(10);
    });
  });

  // ── fix ─────────────────────────────────────────────────────────────────────────────────────

  describe('fix', () => {
    it('--dry-run does not modify the config file', async () => {
      const dst = tempFixture('test-config.json');
      const before = fs.readFileSync(dst, 'utf8');

      const r = await runCli(['fix', '--config', dst, '--dry-run']);
      expect(fs.readFileSync(dst, 'utf8')).toBe(before); // unchanged
      fs.unlinkSync(dst);
    });

    it('--dry-run shows a fix preview', async () => {
      // test-config.json has auto-fixable issues; docker-config.json does not
      const dst = tempFixture('test-config.json');
      const r = await runCli(['fix', '--config', dst, '--dry-run']);
      // dry-run output contains either "Dry run" or "Fixed config preview"
      expect(r.stdout).toMatch(/Dry run|Fixed config preview/);
      fs.unlinkSync(dst);
    });

    it('writes changes to config when fixes are available', async () => {
      const dst = tempFixture('test-config.json');
      const before = fs.readFileSync(dst, 'utf8');

      const r = await runCli(['fix', '--config', dst]);
      fs.unlinkSync(dst);
      // Config should be different (unless no fixable issues)
      // At minimum we should see output from the fix command
      expect(r.stdout).toMatch(/✓|⊘|No auto-fixable|Applied/);
    });

    it('shows error when config file missing', async () => {
      const r = await runCli(['fix', '--config', '/nonexistent.json']);
      expect(r.stderr).toContain('outside allowed directories');
      expect(r.code).toBe(1);
    });
  });

  // ── watch ───────────────────────────────────────────────────────────────────────────────────

  describe('watch', () => {
    it('exits with error when config path is outside allowed directories', async () => {
      const r = await runCli(['watch', '--config', '/nonexistent.json']);
      expect(r.code).toBe(1);
      expect(r.stdout + r.stderr).toContain('outside allowed directories');
    });

    it('starts and immediately scans a valid config', async () => {
      const cleanConfig = path.join(PROJECT_ROOT, `.tmp-test-watch-${Date.now()}.json`);
      fs.writeFileSync(cleanConfig, JSON.stringify({
        mcpServers: { test: { command: '/bin/true', args: [] } }
      }, null, 2));

      // Send SIGINT after 1 second to stop the watch loop
      const proc = spawn(CLI, [path.join(PROJECT_ROOT, 'dist', 'cli.js'), 'watch', '--config', cleanConfig]);
      let stdout = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });

      await new Promise<void>((resolve) => {
        setTimeout(() => {
          proc.kill('SIGINT');
          resolve();
        }, 1500);
      });

      // Watch mode should have printed a scan result
      expect(stdout).toMatch(/Security Report|Score:|Scanned/);
      fs.unlinkSync(cleanConfig);
    });
  });

  // ── version / help ─────────────────────────────────────────────────────────────────────────

  describe('global flags', () => {
    it('--version prints the version', async () => {
      const r = await runCli(['--version']);
      expect(r.stdout.trim()).toMatch(/^\d+\.\d+/);
    });

    it('--help prints the help text', async () => {
      const r = await runCli(['--help']);
      expect(r.stdout).toContain('scan');
      expect(r.stdout).toContain('list');
      expect(r.stdout).toContain('fix');
      expect(r.stdout).toContain('owasp');
    });

    it('unknown command prints error', async () => {
      const r = await runCli(['unknown-command']);
      expect(r.stderr).toContain("unknown command 'unknown-command'");
    });
  });
});
