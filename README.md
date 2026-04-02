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

# List discovered config files
npx mcpshield list

# Show OWASP MCP Top 10 reference
npx mcpshield owasp
```

## What It Detects

| Category | Checks |
|----------|--------|
| **Supply Chain** | Unpinned versions, unverified packages, known risky packages, typosquats |
| **Permissions** | Broad filesystem access, sensitive working directories |
| **Secrets** | Hardcoded API keys, tokens in plaintext config |
| **Configuration** | Missing commands, shell injection patterns, dangerous runtime flags |
| **Network** | Binding to 0.0.0.0, suspicious URLs (pastebin, webhook.site, etc.) |
| **Threats** | Typosquatting, obfuscated values, data exfiltration indicators |

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
# GitHub Actions
- name: MCP Security Scan
  run: npx mcpshield scan --format json
  # Exits with code 2 for critical, 1 for high findings
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
