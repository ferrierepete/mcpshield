# 🔒 MCPShield

**Security scanner for MCP (Model Context Protocol) servers.** Detect supply chain risks, permission overreach, and misconfigurations before they compromise your system.

[![npm version](https://img.shields.io/npm/v/mcpshield.svg)](https://www.npmjs.com/package/mcpshield)

## Why?

MCP (Model Context Protocol) is the standard way AI tools like Claude Desktop, VS Code, and Cursor connect to external services. Every MCP server you install can **execute arbitrary code** on your machine.

Recent attacks include:
- **Mass-forking & republishing** of MCP servers with malicious payloads ([HN, March 2026](https://news.ycombinator.com))
- **Typosquatting** — packages mimicking official `@modelcontextprotocol` servers
- **Rug pulls** — legitimate packages updated to include malicious code
- **Data exfiltration** — servers secretly sending your data to external endpoints

**MCPShield scans your MCP configuration** and flags these risks before they become incidents.

## Install

```bash
npm install -g mcpshield
```

## Quick Start

```bash
# Auto-detect and scan your MCP config
npx mcpshield scan

# Scan a specific config file
npx mcpshield scan --config ~/.config/claude/config.json

# Output as JSON (for CI/CD)
npx mcpshield scan --format json

# Output as Markdown
npx mcpshield scan --format markdown

# Output as SARIF (for GitHub Security tab)
npx mcpshield scan --format sarif

# Enable remote registry checks (npm/PyPI)
npx mcpshield scan --registry

# Filter by severity
npx mcpshield scan --severity high

# Ignore specific findings
npx mcpshield scan --ignore MCP-001 MCP-003

# Quiet mode (CI-friendly one-liner output)
npx mcpshield scan --quiet

# Auto-fix common issues
npx mcpshield fix
npx mcpshield fix --dry-run

# Watch config for changes and re-scan
npx mcpshield watch

# List discovered config files
npx mcpshield list

# Show OWASP MCP Top 10 reference
npx mcpshield owasp
```

## What It Detects

| Category | Checks |
|----------|--------|
| **Supply Chain** | Unpinned versions, unverified packages, known risky packages, typosquats |
| **Registry** | Package existence on npm/PyPI, recently published packages, single-version packages, missing source repos *(with `--registry`)* |
| **Permissions** | Broad filesystem access, sensitive working directories, overly permissive runtime flags |
| **Secrets** | Hardcoded API keys, tokens in plaintext config |
| **Configuration** | Missing commands, shell injection patterns, dangerous runtime flags, eval/exec patterns |
| **Network** | Binding to 0.0.0.0, suspicious URLs (pastebin, webhook.site, etc.), IP-based server URLs |
| **Docker** | `--privileged` flag, sensitive volume mounts, Docker socket exposure, unpinned image tags, exposed ports |
| **HTTP/SSE Transport** | Insecure HTTP connections, missing authentication headers on remote servers |
| **Threats** | Typosquatting, obfuscated values, data exfiltration indicators |

## Commands

### `mcpshield scan`

Scan MCP server configurations for security issues.

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to MCP config file |
| `-f, --format <fmt>` | Output format: `pretty`, `json`, `markdown`, `sarif` |
| `-r, --registry` | Enable remote npm/PyPI registry checks |
| `-s, --severity <level>` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `-i, --ignore <ids...>` | Finding IDs or titles to ignore |
| `-q, --quiet` | One-line summary output (ideal for CI scripts) |
| `--no-spinner` | Disable progress spinner |

### `mcpshield fix`

Auto-fix common security issues in your MCP config.

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to MCP config file |
| `--dry-run` | Preview fixes without writing changes |

Supported auto-fixes:
- **Pin package versions** — appends `@latest` to unpinned packages
- **Replace hardcoded secrets** — substitutes with `${VAR_NAME}` references
- **Bind to localhost** — replaces `0.0.0.0` with `127.0.0.1`
- **Upgrade to HTTPS** — replaces `http://` with `https://` for remote URLs
- **Remove empty env vars** — cleans up empty or wildcard environment variables

### `mcpshield watch`

Watch your MCP config file and re-scan automatically on every change.

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to MCP config file |
| `-f, --format <fmt>` | Output format: `pretty`, `json`, `markdown`, `sarif` |

### `mcpshield list`

List all discovered MCP configuration files on your system.

### `mcpshield owasp`

Display the OWASP MCP Top 10 security framework reference.

## Security Score

MCPShield generates a 0-100 security score:
- **80-100** ✅ Good — minor improvements possible
- **60-79** ⚠️ Warning — meaningful risks to address
- **0-59** 🔴 Critical — immediate action required

## OWASP MCP Top 10

MCPShield maps findings to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top/) framework:
- MCP-01: Malicious Server Distribution
- MCP-02: Tool Poisoning
- MCP-03: Rug Pull Attacks
- MCP-04: Cross-Origin Resource Sharing
- MCP-05: Prompt Injection via Tools
- MCP-06: Unauthorized Tool Access
- MCP-07: Data Exfiltration
- MCP-08: Identity Spoofing
- MCP-09: Token/Secret Exposure
- MCP-10: Dependency Confusion

## Example Output

```
🔒 MCPShield Security Report
──────────────────────────────────────────────────
Config: /home/user/.config/claude/config.json
Date:  2026-04-02 22:15:00

Security Score: 42/100

Findings: 2 critical  3 high  1 medium

📦 filesystem-dangerous [25/100]
   Command: npx

   🔴 Broad Filesystem Access [MCP-001]
    Server has access to path "/". This grants read/write access to sensitive system directories.
    → Fix: Restrict filesystem access to only the specific directories this server needs.
    Refs: MCP-06: Unauthorized Tool Access, MCP-07: Data Exfiltration

   🟠 Sensitive Credentials in Config [MCP-002]
    Found 1 sensitive environment variable(s): AWS_SECRET_ACCESS_KEY
    → Fix: Use a secrets manager instead of hardcoding credentials.

📦 github-safe [100/100]
   ✅ No security issues found
```

## CI/CD Integration

```yaml
# GitHub Actions — JSON output
- name: MCP Security Scan
  run: npx mcpshield scan --format json
  # Exits with code 2 for critical, 1 for high findings

# GitHub Actions — SARIF for Security tab
- name: MCP Security Scan (SARIF)
  run: npx mcpshield scan --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Configuration

### `.mcpshieldrc`

Create a `.mcpshieldrc`, `.mcpshieldrc.json`, or `.mcpshield.json` file in your project root or home directory to set defaults:

```json
{
  "severityThreshold": "medium",
  "ignore": ["MCP-001"],
  "format": "pretty",
  "registry": false,
  "trustedPackages": ["@myorg/custom-mcp-server"],
  "riskyPackages": ["some-known-bad-package"]
}
```

MCPShield searches for this file in the current directory first, then the home directory.

### Customizing Package Lists

Trusted and risky package lists are stored as JSON files in `src/data/`:
- `trusted-packages.json` — packages verified as legitimate
- `risky-packages.json` — packages known to be malicious or suspicious
- `suspicious-patterns.json` — URL patterns and typosquat regexes

## Plugin System

Extend MCPShield with custom scanners via the plugin API:

```typescript
import { pluginRegistry, definePlugin, createFinding } from 'mcpshield';

pluginRegistry.register(definePlugin({
  name: 'my-org-policy',
  description: 'Enforce internal security policies',
  scan: (serverName, config) => {
    const findings = [];
    // Your custom checks here
    if (!config.env?.AUDIT_LOG) {
      findings.push(createFinding({
        title: 'Missing Audit Log',
        description: 'Internal policy requires AUDIT_LOG env var.',
        severity: 'medium',
        category: 'configuration',
        serverName,
        remediation: 'Add AUDIT_LOG=true to the server environment.',
      }));
    }
    return findings;
  },
}));
```

Plugins support both sync and async scanners, and errors in plugins are isolated — a crashing plugin won't affect the rest of the scan.

## Programmatic API

MCPShield can be used as a library in your own Node.js tooling:

```typescript
import {
  scanAllServers,
  scanAllServersWithRegistry,
  loadConfig,
  autoDetectConfig,
} from 'mcpshield';

// Load a config file
const config = loadConfig('/path/to/mcp.json');

// Run a local scan
const result = scanAllServers(config.mcpServers, '/path/to/mcp.json');
console.log(`Score: ${result.summary.score}/100`);
console.log(`Critical: ${result.summary.critical}`);

// Run with remote registry verification
const fullResult = await scanAllServersWithRegistry(config.mcpServers, '/path/to/mcp.json');

// Access per-server findings
for (const server of fullResult.servers) {
  console.log(`${server.name}: ${server.findings.length} findings`);
  for (const finding of server.findings) {
    console.log(`  [${finding.severity}] ${finding.title}`);
    console.log(`  Fix: ${finding.remediation}`);
  }
}
```

### Key Exported Types

```typescript
import type {
  ScanResult,       // Top-level result from scanAllServers
  ServerScanResult, // Per-server findings and score
  Finding,          // Individual security finding
  Severity,         // 'critical' | 'high' | 'medium' | 'low' | 'info'
  FindingCategory,  // 'supply-chain' | 'permissions' | 'configuration' | ...
  MCPConfig,        // Parsed MCP config file shape
  MCPServerConfig,  // Individual server config
} from 'mcpshield';
```

## Config Locations

MCPShield auto-discovers configs from:
- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `~/.config/claude/config.json`
- `~/.vscode/mcp.json`
- `~/.cursor/mcp.json`
- `~/.mcp/config.json`
- `./mcp.json` (current directory)
- `MCP_CONFIG_PATH` environment variable

## License

MIT © Peter Ferriere
