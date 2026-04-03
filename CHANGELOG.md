# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-03

### Fixed
- Corrected MCP config file discovery paths for all supported clients
- Added missing paths: Claude Code (`~/.claude.json`, `.mcp.json`, `.claude/settings.local.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), Continue (`~/.continue/config.json`), Zed (`~/.config/zed/settings.json`)
- Fixed Claude Desktop Linux path (`~/.config/Claude/` not `~/.config/claude/`)
- Added Windows `%APPDATA%` path for Claude Desktop
- Added Cursor project-scope path (`.cursor/mcp.json`)
- Fixed VS Code path to workspace-level `.vscode/mcp.json` (was incorrectly `~/.vscode/mcp.json`)
- Removed non-existent paths (`~/.mcp/config.json`, `./mcp.json`)

### Added
- Config format auto-detection: Zed `context_servers` format, Continue array-based `mcpServers`, VS Code `servers` key
- 3 new test fixtures and test cases for Continue, Zed, and VS Code config formats
- 90 tests across 9 test suites (was 87)

## [0.1.0] - 2026-04-03

### Added
- Initial release
- `scan` command — auto-detect or specify MCP config files, with `pretty`, `json`, `markdown`, and `sarif` output formats
- `fix` command — auto-fix common issues (pin versions, replace hardcoded secrets, remove wildcards, upgrade HTTP to HTTPS) with `--dry-run` support
- `watch` command — live re-scan on config file changes with debouncing
- `list` command — discover MCP config files across Claude Desktop, VS Code, Cursor, and generic locations
- `owasp` command — display OWASP MCP Top 10 reference
- Five built-in scanner modules: configuration, supply-chain, permissions, threats, transport
- Docker-specific checks: `--privileged` flag, sensitive volume mounts, Docker socket exposure, unpinned image tags, exposed ports
- HTTP/SSE transport checks: insecure HTTP, missing auth headers on remote servers, IP-based URLs
- Remote registry verification (`--registry`): npm/PyPI package existence, age, maintainer, and source repo checks
- `--severity` flag to filter output by minimum severity threshold
- `--ignore` flag to suppress specific findings by ID or title
- `--quiet` flag for CI-friendly minimal output
- `.mcpshieldrc` config file support for persistent defaults
- Plugin system (`pluginRegistry`, `definePlugin`) for custom scanner rules with async support
- SARIF 2.1.0 output for GitHub Security tab and other SAST integrations
- `ScanContext` class for isolated, scan-scoped finding counters
- Externalized package lists (`trusted-packages.json`, `risky-packages.json`, `suspicious-patterns.json`) for easy community updates
- 87 tests across 9 test suites

- Package published as `@ferrierepete/mcpshield` on npm

[Unreleased]: https://github.com/ferrierepete/mcpshield/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/ferrierepete/mcpshield/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ferrierepete/mcpshield/releases/tag/v0.1.0
