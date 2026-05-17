import { describe, it, expect, beforeEach } from 'vitest';
import { scanPermissions } from '../src/scanners/permissions.js';
import { resetCounter } from '../src/utils/helpers.js';
import type { MCPServerConfig } from '../src/types/index.js';

const makeConfig = (overrides: Partial<MCPServerConfig> = {}): MCPServerConfig => ({
  command: 'npx',
  ...overrides,
});

describe('scanPermissions', () => {
  beforeEach(() => {
    resetCounter();
  });

  describe('expanded DANGEROUS_PATHS', () => {
    it('detects /tmp as dangerous path', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/tmp'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(true);
    });

    it('detects /dev as dangerous path', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/dev'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(true);
    });

    it('detects /var/run as dangerous path', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/var/run'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(true);
    });

    it('detects /run as dangerous path', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/run'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(true);
    });

    it('detects /opt as dangerous path', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/opt'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(true);
    });

    it('does not flag /tmp/user as dangerous', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/tmp/user/project'] }));
      expect(findings.some(f => f.title === 'Broad Filesystem Access')).toBe(false);
    });
  });

  describe('sudo detection', () => {
    it('detects sudo as command', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'sudo', args: ['npx', 'some-pkg'] }));
      const sudoFinding = findings.find(f => f.title === 'Privilege Escalation via sudo');
      expect(sudoFinding).toBeDefined();
      expect(sudoFinding!.severity).toBe('critical');
      expect(sudoFinding!.category).toBe('permissions');
      expect(sudoFinding!.references).toContain('MCP03:2025 - Privilege Escalation via Scope Creep');
      expect(sudoFinding!.references).toContain('MCP07:2025 - Insufficient Authentication & Authorization');
    });

    it('detects sudo in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', 'sudo', 'apt-get', 'install'] }));
      const sudoFinding = findings.find(f => f.title === 'Privilege Escalation via sudo');
      expect(sudoFinding).toBeDefined();
      expect(sudoFinding!.severity).toBe('critical');
    });

    it('does not flag when sudo is not present', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['some-pkg'] }));
      expect(findings.some(f => f.title === 'Privilege Escalation via sudo')).toBe(false);
    });

    it('does not flag substring like "sudoers" in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'cat', args: ['/etc/sudoers'] }));
      expect(findings.some(f => f.title === 'Privilege Escalation via sudo')).toBe(false);
    });
  });

  describe('chmod/chown detection', () => {
    it('detects chmod in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', 'chmod', '777', '/tmp'] }));
      const chmodFinding = findings.find(f => f.title === 'Permission Modification via chmod');
      expect(chmodFinding).toBeDefined();
      expect(chmodFinding!.severity).toBe('high');
      expect(chmodFinding!.category).toBe('permissions');
      expect(chmodFinding!.references).toContain('MCP03:2025 - Privilege Escalation via Scope Creep');
    });

    it('detects chown in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', 'chown', 'root:root', '/etc/hosts'] }));
      const chownFinding = findings.find(f => f.title === 'Permission Modification via chown');
      expect(chownFinding).toBeDefined();
      expect(chownFinding!.severity).toBe('high');
    });

    it('does not flag chmod/chown as substrings', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['chmod-wrapper'] }));
      expect(findings.some(f => f.title === 'Permission Modification via chmod')).toBe(false);
    });

    it('does not flag when no chmod/chown present', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['some-pkg'] }));
      expect(findings.some(f => f.title.includes('Permission Modification'))).toBe(false);
    });
  });

  describe('path traversal detection', () => {
    it('detects /.. in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', '../../etc/passwd'] }));
      const traversal = findings.find(f => f.title === 'Path Traversal Pattern Detected');
      expect(traversal).toBeDefined();
      expect(traversal!.severity).toBe('high');
      expect(traversal!.category).toBe('permissions');
      expect(traversal!.references).toContain('MCP03:2025 - Privilege Escalation via Scope Creep');
    });

    it('detects /./ in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', '/./etc/passwd'] }));
      expect(findings.some(f => f.title === 'Path Traversal Pattern Detected')).toBe(true);
    });

    it('detects // in args', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', '//etc/passwd'] }));
      expect(findings.some(f => f.title === 'Path Traversal Pattern Detected')).toBe(true);
    });

    it('does not flag normal paths without traversal', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['-y', 'some-pkg', '/home/user/project'] }));
      expect(findings.some(f => f.title === 'Path Traversal Pattern Detected')).toBe(false);
    });

    it('only produces one finding for multiple traversal patterns', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'bash', args: ['-c', '../.././etc//passwd'] }));
      const traversalCount = findings.filter(f => f.title === 'Path Traversal Pattern Detected').length;
      expect(traversalCount).toBe(1);
    });
  });

  describe('IPv6 ::: detection', () => {
    it('detects ::: as network binding', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['--host', ':::'] }));
      expect(findings.some(f => f.title === 'Network Binding to All Interfaces')).toBe(true);
      const ipv6Finding = findings.find(f => f.title === 'IPv6 Any-Address Binding with Port');
      expect(ipv6Finding).toBeDefined();
      expect(ipv6Finding!.severity).toBe('critical');
      expect(ipv6Finding!.category).toBe('network');
      expect(ipv6Finding!.references).toContain('MCP07:2025 - Insufficient Authentication & Authorization');
    });

    it('detects :::8080 as IPv6 any-address with port', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['--host', ':::8080'] }));
      const ipv6Finding = findings.find(f => f.title === 'IPv6 Any-Address Binding with Port');
      expect(ipv6Finding).toBeDefined();
      expect(ipv6Finding!.severity).toBe('critical');
    });

    it('does not flag when no ::: present', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'npx', args: ['some-pkg'] }));
      expect(findings.some(f => f.title === 'IPv6 Any-Address Binding with Port')).toBe(false);
    });
  });

  describe('finding IDs use MCPS- prefix', () => {
    it('generates MCPS-prefixed IDs', () => {
      const findings = scanPermissions('test', makeConfig({ command: 'sudo', args: ['/'] }));
      expect(findings.length).toBeGreaterThan(0);
      for (const f of findings) {
        expect(f.id).toMatch(/^MCPS-\d{3}$/);
      }
    });
  });

  describe('autoApprove/alwaysAllow with broad permissions', () => {
    it('detects autoApprove with broad filesystem access', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/'], autoApprove: ['read_files', 'write_files'] }));
      const f = findings.find(f => f.title === 'Auto-Approved Tools with Broad Permissions');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.category).toBe('permissions');
      expect(f!.references).toContain('MCP03:2025 - Privilege Escalation via Scope Creep');
      expect(f!.description).toContain('read_files');
      expect(f!.description).toContain('write_files');
    });

    it('detects alwaysAllow with network binding to 0.0.0.0', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['--host', '0.0.0.0'], alwaysAllow: ['execute_command'] }));
      const f = findings.find(f => f.title === 'Auto-Approved Tools with Broad Permissions');
      expect(f).toBeDefined();
      expect(f!.severity).toBe('high');
      expect(f!.description).toContain('execute_command');
    });

    it('detects autoApprove with IPv6 ::: binding', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['--host', ':::'], autoApprove: ['tool1'] }));
      expect(findings.some(f => f.title === 'Auto-Approved Tools with Broad Permissions')).toBe(true);
    });

    it('does not flag autoApprove without broad permissions', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/home/user/project'], autoApprove: ['read_files'] }));
      expect(findings.some(f => f.title === 'Auto-Approved Tools with Broad Permissions')).toBe(false);
    });

    it('does not flag config without autoApprove or alwaysAllow', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/'] }));
      expect(findings.some(f => f.title === 'Auto-Approved Tools with Broad Permissions')).toBe(false);
    });

    it('does not flag empty autoApprove array', () => {
      const findings = scanPermissions('test', makeConfig({ args: ['/'], autoApprove: [] }));
      expect(findings.some(f => f.title === 'Auto-Approved Tools with Broad Permissions')).toBe(false);
    });
  });
});
