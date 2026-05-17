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
  confidence?: number; // 0.0–1.0, set by heuristic or AI evaluation
  aiVerdict?: AIVerdict;
}

export type AIVerdict = 'confirmed' | 'likely-false-positive' | 'needs-review';

export type AIProviderType = 'openai' | 'anthropic' | 'gemini';

export interface AIConfig {
  provider: AIProviderType;
  apiKey: string;
  model?: string;
  baseUrl?: string; // for OpenAI-compatible endpoints (Groq, Together, Ollama, etc.)
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
  url?: string;
  headers?: Record<string, string>;
  type?: 'stdio' | 'sse' | 'http';
  autoApprove?: string[];
  alwaysAllow?: string[];
  inputs?: Array<{ id: string; type: string; password?: boolean }>;
  settings?: Record<string, unknown>;
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
  'MCP01:2025 - Token Mismanagement & Secret Exposure',
  'MCP02:2025 - Tool Poisoning',
  'MCP03:2025 - Privilege Escalation via Scope Creep',
  'MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering',
  'MCP05:2025 - Command Injection & Execution',
  'MCP06:2025 - Intent Flow Subversion',
  'MCP07:2025 - Insufficient Authentication & Authorization',
  'MCP08:2025 - Lack of Audit and Telemetry',
  'MCP09:2025 - Shadow MCP Servers',
  'MCP10:2025 - Context Injection & Over-Sharing',
] as const;
