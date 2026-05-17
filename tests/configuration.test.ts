import { describe, it, expect, beforeEach } from 'vitest';
import { scanConfiguration } from '../src/scanners/configuration.js';
import { resetCounter } from '../src/utils/helpers.js';
import type { MCPServerConfig } from '../src/types/index.js';

describe('Configuration Scanner - Shell Interpreter & Metacharacter Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  // Rule 1: Shell interpreters as command
  describe('Rule 1: Shell Interpreter Used as Command', () => {
    it('should detect bash as command', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: [] });
      const f = findings.find(f => f.title === 'Shell Interpreter Used as Command');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect sh as command', () => {
      const findings = scanConfiguration('test', { command: 'sh', args: [] });
      expect(findings.some(f => f.title === 'Shell Interpreter Used as Command')).toBe(true);
    });

    it('should detect zsh, dash, ksh, csh, tcsh', () => {
      for (const shell of ['zsh', 'dash', 'ksh', 'csh', 'tcsh']) {
        const findings = scanConfiguration('test', { command: shell, args: [] });
        expect(findings.some(f => f.title === 'Shell Interpreter Used as Command'), `Missing detection for ${shell}`).toBe(true);
      }
    });

    it('should detect shell interpreter via absolute path (/bin/bash)', () => {
      const findings = scanConfiguration('test', { command: '/bin/bash', args: [] });
      expect(findings.some(f => f.title === 'Shell Interpreter Used as Command')).toBe(true);
    });

    it('should NOT flag non-shell commands', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'some-package'] });
      expect(findings.some(f => f.title === 'Shell Interpreter Used as Command')).toBe(false);
    });
  });

  // Rule 2: Shell -c/-e flags on interpreters (node, python, perl, ruby, php)
  describe('Rule 2: Direct Code Execution via Interpreter Flag', () => {
    it('should detect python -c', () => {
      const findings = scanConfiguration('test', { command: 'python', args: ['-c', 'print(1)'] });
      const f = findings.find(f => f.title === 'Direct Code Execution via Interpreter Flag');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect python3 -c', () => {
      const findings = scanConfiguration('test', { command: 'python3', args: ['-c', 'import os'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(true);
    });

    it('should detect perl -e', () => {
      const findings = scanConfiguration('test', { command: 'perl', args: ['-e', 'print 1'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(true);
    });

    it('should detect ruby -e', () => {
      const findings = scanConfiguration('test', { command: 'ruby', args: ['-e', 'puts 1'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(true);
    });

    it('should detect php -c', () => {
      const findings = scanConfiguration('test', { command: 'php', args: ['-c', 'echo 1;'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(true);
    });

    it('should NOT flag python without -c or -e', () => {
      const findings = scanConfiguration('test', { command: 'python', args: ['script.py'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(false);
    });

    it('should NOT flag bash -c (covered by Rule 7)', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['-c', 'echo hi'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Interpreter Flag')).toBe(false);
    });
  });

  // Rule 3: Newline injection
  describe('Rule 3: Newline Injection in Arguments', () => {
    it('should detect newline (\\n) in argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg\nevil'] });
      const f = findings.find(f => f.title === 'Newline Injection in Arguments');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect carriage return (\\r) in argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg\revil'] });
      expect(findings.some(f => f.title === 'Newline Injection in Arguments')).toBe(true);
    });

    it('should NOT flag clean arguments', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'clean-pkg'] });
      expect(findings.some(f => f.title === 'Newline Injection in Arguments')).toBe(false);
    });
  });

  // Rule 4: Input redirect (< standalone token)
  describe('Rule 4: Input Redirect in Arguments', () => {
    it('should detect standalone < token', () => {
      const findings = scanConfiguration('test', { command: 'cat', args: ['<', '/etc/passwd'] });
      const f = findings.find(f => f.title === 'Input Redirect in Arguments');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should NOT flag < inside a string argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'html<tag>'] });
      expect(findings.some(f => f.title === 'Input Redirect in Arguments')).toBe(false);
    });

    it('should NOT flag clean arguments', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg'] });
      expect(findings.some(f => f.title === 'Input Redirect in Arguments')).toBe(false);
    });
  });

  // Rule 5: Append redirect (>>)
  describe('Rule 5: Append Redirect in Arguments', () => {
    it('should detect >> in argument', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['-c', 'echo data >> /tmp/out'] });
      const f = findings.find(f => f.title === 'Append Redirect in Arguments');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should NOT flag single > (already in dangerousChars)', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'file>output'] });
      expect(findings.some(f => f.title === 'Append Redirect in Arguments')).toBe(false);
    });

    it('should NOT flag clean arguments', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg'] });
      expect(findings.some(f => f.title === 'Append Redirect in Arguments')).toBe(false);
    });
  });

  // Rule 6: $VAR expansion
  describe('Rule 6: Shell Variable Expansion in Arguments', () => {
    it('should detect $HOME in argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', '--path=$HOME'] });
      const f = findings.find(f => f.title === 'Shell Variable Expansion in Arguments');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect $AWS_SECRET_ACCESS_KEY in argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', '--key=$AWS_SECRET_ACCESS_KEY'] });
      const f = findings.find(f => f.title === 'Shell Variable Expansion in Arguments');
      expect(f).toBeDefined();
      expect(f!.description).toContain('$AWS_SECRET_ACCESS_KEY');
    });

    it('should NOT flag $(...) command substitution (already in dangerousChars)', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['$(whoami)'] });
      expect(findings.some(f => f.title === 'Shell Variable Expansion in Arguments')).toBe(false);
    });

    it('should NOT flag clean arguments without $', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg'] });
      expect(findings.some(f => f.title === 'Shell Variable Expansion in Arguments')).toBe(false);
    });
  });

  // Rule 7: bash -c / sh -c specifically
  describe('Rule 7: Shell Interpreter with Command Flag', () => {
    it('should detect bash -c', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['-c', 'echo hello'] });
      const f = findings.find(f => f.title === 'Shell Interpreter with Command Flag');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect sh -c', () => {
      const findings = scanConfiguration('test', { command: 'sh', args: ['-c', 'echo hello'] });
      expect(findings.some(f => f.title === 'Shell Interpreter with Command Flag')).toBe(true);
    });

    it('should detect /bin/bash -c via absolute path', () => {
      const findings = scanConfiguration('test', { command: '/bin/bash', args: ['-c', 'whoami'] });
      expect(findings.some(f => f.title === 'Shell Interpreter with Command Flag')).toBe(true);
    });

    it('should NOT flag bash without -c', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['script.sh'] });
      expect(findings.some(f => f.title === 'Shell Interpreter with Command Flag')).toBe(false);
    });

    it('should NOT flag node -c (covered by Rule 2)', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['-c'] });
      expect(findings.some(f => f.title === 'Shell Interpreter with Command Flag')).toBe(false);
    });
  });

  // Rule 8: /usr/bin/env wrapper
  describe('Rule 8: Environment Wrapper Used as Command', () => {
    it('should detect env as command', () => {
      const findings = scanConfiguration('test', { command: 'env', args: ['node', 'server.js'] });
      const f = findings.find(f => f.title === 'Environment Wrapper Used as Command');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect /usr/bin/env as command', () => {
      const findings = scanConfiguration('test', { command: '/usr/bin/env', args: ['python3', 'server.py'] });
      expect(findings.some(f => f.title === 'Environment Wrapper Used as Command')).toBe(true);
    });

    it('should NOT flag non-env commands', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'pkg'] });
      expect(findings.some(f => f.title === 'Environment Wrapper Used as Command')).toBe(false);
    });
  });

  // Rule 9: node -e / node --eval
  describe('Rule 9: Direct Code Execution via Node.js Eval', () => {
    it('should detect node -e', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['-e', 'console.log(1)'] });
      const f = findings.find(f => f.title === 'Direct Code Execution via Node.js Eval');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('critical');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect node --eval', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['--eval', 'require("fs")'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Node.js Eval')).toBe(true);
    });

    it('should detect /usr/local/bin/node -e via absolute path', () => {
      const findings = scanConfiguration('test', { command: '/usr/local/bin/node', args: ['-e', 'process.exit(0)'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Node.js Eval')).toBe(true);
    });

    it('should NOT flag node without -e or --eval', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['server.js'] });
      expect(findings.some(f => f.title === 'Direct Code Execution via Node.js Eval')).toBe(false);
    });
  });

  // Rule 10: node --require / -r preload
  describe('Rule 10: Node.js Module Preload', () => {
    it('should detect node -r', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['-r', 'dotenv/config', 'server.js'] });
      const f = findings.find(f => f.title === 'Node.js Module Preload');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
    });

    it('should detect node --require', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['--require', 'some-module', 'server.js'] });
      expect(findings.some(f => f.title === 'Node.js Module Preload')).toBe(true);
    });

    it('should NOT flag node without -r or --require', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['server.js'] });
      expect(findings.some(f => f.title === 'Node.js Module Preload')).toBe(false);
    });

    it('should NOT flag npx -r (only applies to node)', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-r', 'pkg'] });
      expect(findings.some(f => f.title === 'Node.js Module Preload')).toBe(false);
    });
  });

  // Cross-cutting: finding IDs use MCPS- prefix
  describe('Finding ID format', () => {
    it('should generate MCPS-prefixed finding IDs', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['-c', 'echo $HOME'] });
      for (const f of findings) {
        expect(f.id).toMatch(/^MCPS-\d{3}$/);
      }
    });
  });

  // Cross-cutting: multiple rules fire for same config
  describe('Multiple detections for high-risk config', () => {
    it('should detect multiple issues for bash -c with variable expansion', () => {
      const findings = scanConfiguration('test', { command: 'bash', args: ['-c', 'curl $SECRET'] });
      const titles = findings.map(f => f.title);
      expect(titles).toContain('Shell Interpreter Used as Command');
      expect(titles).toContain('Shell Interpreter with Command Flag');
      expect(titles).toContain('Shell Variable Expansion in Arguments');
    });
  });

  // Dynamic input from VS Code variables
  describe('Dynamic Input from VS Code Variables', () => {
    it('should detect ${input:variable} in argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', '--api-key=${input:apiKey}'] });
      const f = findings.find(f => f.title === 'Dynamic Input from VS Code Variables');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('medium');
      expect(f!.category).toBe('configuration');
      expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
      expect(f!.description).toContain('${input:apiKey}');
    });

    it('should detect ${input:serverUrl} in argument', () => {
      const findings = scanConfiguration('test', { command: 'node', args: ['server.js', '--url=${input:serverUrl}'] });
      expect(findings.some(f => f.title === 'Dynamic Input from VS Code Variables')).toBe(true);
    });

    it('should detect multiple ${input:...} in single argument', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['--config=${input:configPath}', '--key=${input:apiKey}'] });
      expect(findings.some(f => f.title === 'Dynamic Input from VS Code Variables')).toBe(true);
    });

    it('should NOT flag regular ${VAR} variable expansion', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', '--path=$HOME'] });
      expect(findings.some(f => f.title === 'Dynamic Input from VS Code Variables')).toBe(false);
    });

    it('should NOT flag clean arguments without ${input:...}', () => {
      const findings = scanConfiguration('test', { command: 'npx', args: ['-y', 'clean-pkg'] });
      expect(findings.some(f => f.title === 'Dynamic Input from VS Code Variables')).toBe(false);
    });
  });

  describe('URL-only server (transport-only like Continue)', () => {
    it('should NOT flag missing command when url is present', () => {
      const findings = scanConfiguration('continue-server', { command: '', url: 'http://localhost:4343/mcp' });
      expect(findings.some(f => f.title === 'Missing Command')).toBe(false);
    });

    it('should flag missing command when both command and url are absent', () => {
      const findings = scanConfiguration('empty-server', { command: '' });
      expect(findings.some(f => f.title === 'Missing Command')).toBe(true);
    });

    it('should flag missing command when command is absent and no url', () => {
      const findings = scanConfiguration('no-cmd-no-url', { command: '', args: [] });
      expect(findings.some(f => f.title === 'Missing Command')).toBe(true);
    });
  });
});
