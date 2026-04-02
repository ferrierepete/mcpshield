export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  serverName: string;
  remediation: string;
  references?: string[];
}

export type FindingCategory =
  | 'supply-chain'
  | 'permissions'
  | 'configuration'
  | 'authentication'
  | 'network'
  | 'data-exposure';

export interface MCPServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  disabled?: boolean;
}

export interface MCPConfig {
  mcpServers: Record<string, MCPServerConfig>;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  servers: ServerScanResult[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    score: number; // 0-100
  };
}

export interface ServerScanResult {
  name: string;
  command: string;
  findings: Finding[];
  score: number;
}

export const OWASP_MCP_TOP_CATEGORIES = [
  'MCP-01: Malicious Server Distribution',
  'MCP-02: Tool Poisoning',
  'MCP-03: Rug Pull Attacks',
  'MCP-04: Cross-Origin Resource Sharing',
  'MCP-05: Prompt Injection via Tools',
  'MCP-06: Unauthorized Tool Access',
  'MCP-07: Data Exfiltration',
  'MCP-08: Identity Spoofing',
  'MCP-09: Token/Secret Exposure',
  'MCP-10: Dependency Confusion',
] as const;
