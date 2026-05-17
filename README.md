# 🔒 MCPShield

**Security scanner for MCP (Model Context Protocol) servers.** Detect supply chain risks, permission overreach, and misconfigurations before they compromise your system.

[![npm version](https://img.shields.io/npm/v/@ferrierepete/mcpshield.svg)](https://www.npmjs.com/package/@ferrierepete/mcpshield)

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
npm install -g @ferrierepete/mcpshield
```

## Quick Start

```bash
# Auto-detect and scan your MCP config
npx @ferrierepete/mcpshield scan

# Scan a specific config file
npx @ferrierepete/mcpshield scan --config ~/.config/claude/config.json

# Output as JSON (for CI/CD)
npx @ferrierepete/mcpshield scan --format json

# Output as Markdown
npx @ferrierepete/mcpshield scan --format markdown

# Output as SARIF (for GitHub Security tab)
npx @ferrierepete/mcpshield scan --format sarif

# Enable remote registry checks (npm/PyPI)
npx @ferrierepete/mcpshield scan --registry

# Filter by severity
npx @ferrierepete/mcpshield scan --severity high

# Ignore specific findings
npx @ferrierepete/mcpshield scan --ignore MCPS-001 MCPS-003

# Quiet mode (CI-friendly one-liner output)
npx @ferrierepete/mcpshield scan --quiet

# Filter by severity (critical | high | medium | low | info)
npx @ferrierepete/mcpshield scan -s high

# Ignore findings by ID or title (partial matching supported)
npx @ferrierepete/mcpshield scan --ignore MCPS-001 Typosquat

# Filter out low-confidence findings (heuristic, no API key needed)
# Warns if all findings are filtered to zero
npx @ferrierepete/mcpshield scan --min-confidence 0.7

# AI-powered false positive reduction (BYOK — bring your own key)
npx @ferrierepete/mcpshield scan --ai --ai-provider openai
npx @ferrierepete/mcpshield scan --ai --ai-provider anthropic
npx @ferrierepete/mcpshield scan --ai --ai-provider gemini

# Use a custom OpenAI-compatible endpoint (Groq, Together, Ollama, etc.)
npx @ferrierepete/mcpshield scan --ai --ai-provider openai --ai-base-url http://localhost:11434/v1

# Auto-fix common issues
npx @ferrierepete/mcpshield fix
npx @ferrierepete/mcpshield fix --dry-run

# Watch config for changes and re-scan
npx @ferrierepete/mcpshield watch

# List discovered config files
npx @ferrierepete/mcpshield list

# Show OWASP MCP Top 10 reference
npx @ferrierepete/mcpshield owasp
```

**Multi-config discovery:** `mcpshield scan` auto-discovers and scans ALL MCP configs from all installed clients (Claude Desktop, VS Code, Cursor, Windsurf, Continue, Zed, etc.) by default. No `--config` flag needed. Use `mcpshield list` to see which config files were discovered.

## What It Detects

| Category | Checks |
|----------|--------|
| **Supply Chain** | Unpinned versions (semver ranges rejected: `^`, `~`, `>=`), unverified packages, known risky packages, typosquats, npm exec/pnpm dlx/yarn dlx/bun x runners, Python version pinning |
| **Registry** | Package existence on npm/PyPI, recently published packages, single-version packages, missing source repos, PyPI deep analysis (age, version count, maintainer count, source repo verification) *(with `--registry`)* |
| **Permissions** | Broad filesystem access, sensitive working directories, overly permissive runtime flags, sudo/chmod/chown in args, expanded dangerous paths (/tmp, /proc, /sys, /dev), path traversal attempts, IPv6 `:::` binding |
| **Secrets** | Hardcoded API keys, tokens in plaintext config, 28 sensitive env var patterns, AWS/GitHub/Stripe/Slack key format detection |
| **Configuration** | Missing commands, shell injection patterns (bash, sh, zsh, `bash -c`, `node -e`), dangerous runtime flags, eval/exec patterns, newline injection, `$VAR` expansion, input/append redirect, `/usr/bin/env` wrapper, `node --require` preload |
| **Network** | Binding to 0.0.0.0, suspicious URLs (24 patterns including webhook.site, pastebin, Discord webhooks, Telegram bots, URL shorteners, Google Forms), IP-based server URLs, credentials in URLs |
| **Docker** | `--privileged` flag, 11 Docker security options (`--security-opt`, `--user root`, `--cap-add`, etc.), `--mount` syntax, sensitive volume mounts, Docker socket exposure, unpinned image tags, exposed ports, docker compose detection |
| **HTTP/SSE Transport** | Insecure HTTP connections, `ws://` detection, missing authentication headers on remote servers, URL credentials |
| **Threats** | Typosquatting (14 patterns including `@anthropic/`, `@openai/` scope-extension bypass), reverse shell detection, hex-encoded strings, short base64 (obfuscation), credentials in URLs, URL-encoded payloads |
| **Tool Poisoning** | Auto-approved tools, remote servers without authentication *(informational severity)* |
| **Client-Specific** | VS Code `type`/`inputs` fields, Claude `autoApprove`/`alwaysAllow`, Zed `settings`, Continue URL-only servers |

## Commands

### `mcpshield scan`

Scan MCP server configurations for security issues.

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to MCP config file |
| `-f, --format <fmt>` | Output format: `pretty`, `json`, `markdown`, `sarif` |
| `-r, --registry` | Enable remote npm/PyPI registry checks |
| `-s, --severity <level>` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `-i, --ignore <ids...>` | Finding IDs or titles to ignore (substring matching — `--ignore typo` matches "Potential Typosquat") |
| `-q, --quiet` | One-line summary output (ideal for CI scripts) |
| `--min-confidence <n>` | Minimum confidence threshold (0.0–1.0) to display findings |
| `--ai` | Enable AI-based false positive reduction (requires API key) |
| `--ai-provider <name>` | AI provider: `openai`, `anthropic`, `gemini` |
| `--ai-model <model>` | Override the default AI model |
| `--ai-base-url <url>` | Custom base URL for OpenAI-compatible endpoints |
| `--no-spinner` | Disable progress spinner |

### `mcpshield fix`

Auto-fix common security issues in your MCP config.

| Flag | Description |
|------|-------------|
| `-c, --config <path>` | Path to MCP config file |
| `--dry-run` | Preview fixes without writing changes |

Supported auto-fixes:
- **Pin package versions** — resolves exact versions from npm registry (e.g. `pkg@1.2.3`); falls back to `pkg@0.0.0-REVIEW-NEEDED` if resolution fails
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

MCPShield maps findings to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) framework:

| ID | Category |
|----|----------|
| MCP01:2025 | Token Mismanagement & Secret Exposure |
| MCP02:2025 | Tool Poisoning |
| MCP03:2025 | Privilege Escalation via Scope Creep |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering |
| MCP05:2025 | Command Injection & Execution |
| MCP06:2025 | Intent Flow Subversion |
| MCP07:2025 | Insufficient Authentication & Authorization |
| MCP08:2025 | Lack of Audit and Telemetry |
| MCP09:2025 | Shadow MCP Servers |
| MCP10:2025 | Context Injection & Over-Sharing |

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

   🔴 Broad Filesystem Access [MCPS-001]
    Server has access to path "/". This grants read/write access to sensitive system directories.
    → Fix: Restrict filesystem access to only the specific directories this server needs.
    Refs: MCP03:2025 - Privilege Escalation via Scope Creep, MCP07:2025 - Insufficient Authentication & Authorization

   🟠 Sensitive Credentials in Config [MCPS-002]
    Found 1 sensitive environment variable(s): AWS_SECRET_ACCESS_KEY
    → Fix: Use a secrets manager instead of hardcoding credentials.

📦 [Dormant] old-server [N/A]
   Command: npx
   ℹ️ Server is disabled and excluded from the security score.

📦 github-safe [100/100]
   ✅ No security issues found
```

## CI/CD Integration

```yaml
# GitHub Actions — JSON output
- name: MCP Security Scan
  run: npx @ferrierepete/mcpshield scan --format json
  # Exits with code 2 for critical, 1 for high findings

# GitHub Actions — SARIF for Security tab
- name: MCP Security Scan (SARIF)
  run: npx @ferrierepete/mcpshield scan --format sarif > results.sarif

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
  "ignore": ["MCPS-001"],
  "format": "pretty",
  "registry": false,
  "trustedPackages": ["@myorg/custom-mcp-server"],
  "riskyPackages": ["some-known-bad-package"],
  "ai": true,
  "aiProvider": "openai",
  "aiModel": "gpt-4o-mini",
  "minConfidence": 0.6
}
```

MCPShield searches for this file in the current directory first, then the home directory.

MCPShield warns about potentially dangerous `.mcpshieldrc` options:
- Overly broad `ignore` rules that could suppress critical findings
- Packages in `trustedPackages` that don't match known org patterns (e.g. `@modelcontextprotocol/`)
- `minConfidence` set above 0.9 (effectively silences all findings)

### Customizing Package Lists

Trusted and risky package lists are stored as JSON files in `src/data/`:
- `trusted-packages.json` — packages verified as legitimate
- `risky-packages.json` — packages known to be malicious or suspicious
- `suspicious-patterns.json` — URL patterns and typosquat regexes

## AI False Positive Reduction

MCPShield uses a two-layer system to reduce false positives:

### Layer 1: Heuristic Confidence Scoring (always on, no API key)

Every finding gets a **confidence score** (0.0–1.0) based on contextual rules:
- Trusted packages flagged as unpinned → lower confidence
- Localhost HTTP connections → lower confidence
- Env vars using `${VAR}` references → lower confidence
- Private IP addresses → lower confidence
- `--privileged` Docker flag → higher confidence
- Known risky packages / typosquats → higher confidence

Use `--min-confidence 0.7` to filter out low-confidence findings.

### Layer 2: AI Evaluation (opt-in, BYOK)

Pass `--ai` to send findings to an LLM for contextual evaluation. Each finding receives a verdict:
- **confirmed** — real security risk
- **likely-false-positive** — probably safe in this context
- **needs-review** — human should verify

**Supported providers:**

| Provider | Flag | Env Var(s) | Default Model |
|----------|------|-----------|---------------|
| **OpenAI** | `--ai-provider openai` | `OPENAI_API_KEY` or `MCPSHIELD_OPENAI_API_KEY` | `gpt-4o-mini` |
| **Anthropic** | `--ai-provider anthropic` | `ANTHROPIC_API_KEY` or `MCPSHIELD_ANTHROPIC_API_KEY` | `claude-sonnet-4-20250514` |
| **Google Gemini** | `--ai-provider gemini` | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, or `MCPSHIELD_GEMINI_API_KEY` | `gemini-2.0-flash` |
| **OpenAI-compatible** | `--ai-provider openai --ai-base-url <url>` | Same as OpenAI | — |

Works with **Groq, Together AI, Ollama**, and any OpenAI-compatible endpoint via `--ai-base-url`.

**Additional env vars:**
- `MCPSHIELD_AI_MODEL` — override the default model for any provider
- `MCPSHIELD_AI_BASE_URL` — set a custom OpenAI-compatible endpoint
- `MCPSHIELD_AI_PROVIDER` — set the default provider without `--ai-provider` flag

**Security note:** MCPShield never sends your secrets to the AI. Only env var *keys* (not values) are included in the prompt.

## Plugin System

Extend MCPShield with custom scanners via the plugin API:

```typescript
import { pluginRegistry, definePlugin, createFinding } from '@ferrierepete/mcpshield';

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
} from '@ferrierepete/mcpshield';

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
} from '@ferrierepete/mcpshield';
```

## Security Hardening

MCPShield includes several built-in protections to prevent misuse:

- **Path traversal prevention** — all config paths (whether from `--config`, `MCP_CONFIG_PATH`, or auto-detection) are validated via `resolveSafeConfigPath()`. Only paths within your current working directory or home directory are allowed. Attempts to load files like `/etc/passwd` or `/proc/self/environ` are rejected with a clear error
- **Multi-config scanning** — scans ALL discovered MCP configs by default, not just the first one found. Servers from every client config are merged and scanned together
- **Dormant server marking** — disabled servers get a `[Dormant]` prefix on findings and are excluded from the overall security score
- **Config backup before writes** — the `fix` command creates a `.bak` backup of your config file before applying any changes
- **Secret key sanitization** — the `fix` command sanitizes env var key names containing shell metacharacters (e.g. `$(cmd)`, `` `cmd` ``, `;rm -rf`) by deleting the dangerous key and replacing it with a safe alphanumeric name
- **Exact version pinning** — auto-fix resolves exact versions from the npm registry (async) instead of using `@latest`; falls back to `@0.0.0-REVIEW-NEEDED` if the registry is unreachable
- **SARIF with valid URLs** — all SARIF output includes valid `helpUri` links and OWASP MCP Top 10 references for each finding
- **AI response size limits** — AI provider responses are capped at 1 MB to prevent memory exhaustion from unbounded responses
- **Registry fail-closed** — when npm/PyPI registry checks fail (network errors, HTTP 500, rate limits), packages are treated as unverified rather than silently passing
- **Secret values never sent to AI** — only env var *keys* (not values) are included in AI evaluation prompts

## Config Locations

MCPShield auto-discovers configs from all major MCP clients:

| Client | Scope | Path |
|--------|-------|------|
| **Claude Desktop** | macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Claude Desktop** | Linux | `~/.config/Claude/claude_desktop_config.json` |
| **Claude Desktop** | Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Claude Code** | User/Local | `~/.claude.json` |
| **Claude Code** | Project | `.mcp.json` |
| **Claude Code** | Local | `.claude/settings.local.json` |
| **VS Code** | Workspace | `.vscode/mcp.json` |
| **Cursor** | Global | `~/.cursor/mcp.json` |
| **Cursor** | Project | `.cursor/mcp.json` |
| **Windsurf** | Global | `~/.codeium/windsurf/mcp_config.json` |
| **Continue** | Global | `~/.continue/config.json` |
| **Zed** | Global | `~/.config/zed/settings.json` |
| **Custom** | — | `MCP_CONFIG_PATH` environment variable |

MCPShield handles the different config formats automatically — `mcpServers` (object), `servers` (VS Code), `context_servers` (Zed), and array-based `mcpServers` (Continue).

## License

MIT © Peter Ferriere
