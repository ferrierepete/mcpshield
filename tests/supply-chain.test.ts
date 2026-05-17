import { describe, it, expect, beforeEach } from 'vitest';
import { scanSupplyChain } from '../src/scanners/supply-chain.js';
import { resetCounter } from '../src/utils/helpers.js';

describe('Supply Chain Scanner', () => {
  beforeEach(() => {
    resetCounter();
  });

  describe('version pinning — Node.js packages', () => {
    it('flags pkg@^1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@^1.0.0'] });
      const unpinned = findings.find(f => f.title === 'Unpinned Package Version');
      expect(unpinned).toBeDefined();
      expect(unpinned!.severity).toBe('high');
      expect(unpinned!.references).toContain('MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering');
    });

    it('flags pkg@~1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@~1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@>=1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@>=1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@<=1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@<=1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@>1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@>1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@<1.0.0 as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@<1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@latest as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@latest'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@* as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@*'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg@x as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@x'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags pkg without any version as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['-y', 'pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('accepts pkg@1.2.3 as pinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['-y', 'some-pkg@1.2.3'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });
  });

  describe('scoped packages', () => {
    it('flags @scope/pkg@^1.0.0 as unpinned scoped package', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['@scope/pkg@^1.0.0'] });
      const unpinned = findings.find(f => f.title === 'Unpinned Package Version');
      expect(unpinned).toBeDefined();
      expect(unpinned!.severity).toBe('high');
    });

    it('accepts @scope/pkg@1.2.3 as pinned scoped package', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['@scope/pkg@1.2.3'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('flags @scope/pkg without version as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['@scope/pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('flags @scope/pkg@latest as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['@scope/pkg@latest'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });
  });

  describe('new runners', () => {
    it('detects unpinned package via npm exec', () => {
      const findings = scanSupplyChain('test', { command: 'npm', args: ['exec', 'pkg@^1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('accepts pinned package via npm exec', () => {
      const findings = scanSupplyChain('test', { command: 'npm', args: ['exec', 'pkg@1.2.3'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('detects unpinned package via pnpm dlx', () => {
      const findings = scanSupplyChain('test', { command: 'pnpm', args: ['dlx', 'pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('accepts pinned package via pnpm dlx', () => {
      const findings = scanSupplyChain('test', { command: 'pnpm', args: ['dlx', 'pkg@2.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('detects unpinned package via yarn dlx', () => {
      const findings = scanSupplyChain('test', { command: 'yarn', args: ['dlx', 'pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('accepts pinned package via yarn dlx', () => {
      const findings = scanSupplyChain('test', { command: 'yarn', args: ['dlx', 'pkg@3.1.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('detects unpinned package via bun x', () => {
      const findings = scanSupplyChain('test', { command: 'bun', args: ['x', 'pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('accepts pinned package via bun x', () => {
      const findings = scanSupplyChain('test', { command: 'bun', args: ['x', 'pkg@1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('ignores npm when subcommand is not exec', () => {
      const findings = scanSupplyChain('test', { command: 'npm', args: ['install', 'pkg'] });
      expect(findings.length).toBe(0);
    });

    it('ignores bun when subcommand is not x', () => {
      const findings = scanSupplyChain('test', { command: 'bun', args: ['run', 'script.ts'] });
      expect(findings.length).toBe(0);
    });
  });

  describe('existing npx/bunx behavior preserved', () => {
    it('npx with unpinned scoped package still detected', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['-y', '@scope/pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });

    it('npx with pinned scoped package still passes', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['-y', '@scope/pkg@1.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeUndefined();
    });

    it('bunx with unpinned package still detected', () => {
      const findings = scanSupplyChain('test', { command: 'bunx', args: ['pkg'] });
      expect(findings.find(f => f.title === 'Unpinned Package Version')).toBeDefined();
    });
  });

  describe('Python version pinning', () => {
    it('flags uvx without ==X.Y.Z as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'uvx', args: ['mcp-server-git'] });
      const unpinned = findings.find(f => f.title === 'Unpinned Python Package Version');
      expect(unpinned).toBeDefined();
      expect(unpinned!.severity).toBe('high');
    });

    it('accepts uvx with ==X.Y.Z as pinned', () => {
      const findings = scanSupplyChain('test', { command: 'uvx', args: ['mcp-server-git==1.2.3'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeUndefined();
    });

    it('flags uvx with @-style version (not ==) as unpinned', () => {
      const findings = scanSupplyChain('test', { command: 'uvx', args: ['mcp-server-git@1.2.0'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeDefined();
    });

    it('flags python -m pip install without version', () => {
      const findings = scanSupplyChain('test', { command: 'python', args: ['-m', 'pip', 'install', 'requests'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeDefined();
    });

    it('accepts python -m pip install with ==X.Y.Z', () => {
      const findings = scanSupplyChain('test', { command: 'python', args: ['-m', 'pip', 'install', 'requests==2.31.0'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeUndefined();
    });

    it('flags python3 -m pip install without version', () => {
      const findings = scanSupplyChain('test', { command: 'python3', args: ['-m', 'pip', 'install', 'flask'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeDefined();
    });

    it('accepts python3 -m pip install with ==X.Y.Z', () => {
      const findings = scanSupplyChain('test', { command: 'python3', args: ['-m', 'pip', 'install', 'flask==3.0.0'] });
      expect(findings.find(f => f.title === 'Unpinned Python Package Version')).toBeUndefined();
    });

    it('does not flag python running a local script', () => {
      const findings = scanSupplyChain('test', { command: 'python', args: ['/usr/local/bin/server.py'] });
      expect(findings.length).toBe(0);
    });
  });

  describe('finding IDs and metadata', () => {
    it('uses MCPS- prefix for finding IDs', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@^1.0.0'] });
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.id).toMatch(/^MCPS-\d{3}$/);
      }
    });

    it('references OWASP MCP04:2025', () => {
      const findings = scanSupplyChain('test', { command: 'npx', args: ['pkg@^1.0.0'] });
      const unpinned = findings.find(f => f.title === 'Unpinned Package Version');
      expect(unpinned!.references).toContain('MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering');
    });
  });
});
