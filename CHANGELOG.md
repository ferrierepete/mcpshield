# Changelog

All notable changes to MCPShield are documented here.

## [0.2.0] — 2026-04-04

### Added
- **CLI integration test suite** (`tests/cli-integration.test.ts`) — 40 tests covering `scan`, `list`, `owasp`, `fix`, `watch`, and global flags including output formats, severity filtering, `--ignore`, `--min-confidence`, AI mode, and error paths
- **Substring matching for `--ignore`** — `--ignore typo` now matches findings containing "typo" anywhere in their ID or title (e.g. "Potential Typosquat"). Previously required exact full title match
- **`--min-confidence` empty-result warning** — when `--min-confidence` filters all findings to zero, a warning is now printed: `[mcpshield] --min-confidence N filtered all N finding(s). No findings will be displayed.`
- **`MCP_CONFIG_PATH` fallback warning** — when `MCP_CONFIG_PATH` is set but the file can't be loaded, MCPShield now prints a warning before falling back to auto-detection: `[mcpshield] MCP_CONFIG_PATH is set to "..." but that file could not be loaded. Falling back to auto-detection.`
- **`fix --dry-run` always prints dry-run banner** — even when no auto-fixable issues are found, `--dry-run` now prints `(Dry run — no changes written)` followed by `✅ No auto-fixable issues found.` (previously exited silently with just the banner)

### Fixed
- **Version constant** bumped from `0.1.1` to `0.2.0` in CLI (`src/cli.ts`) to match `package.json`
- **`watch --config <nonexistent>` crash** — `fs.watch()` now has a preceding `fs.existsSync()` guard. Previously, if the config file did not exist, `runWatchScan` would silently log a scan error but `fs.watch` would throw an uncaught `ENOENT` and crash the process
- **`fix --dry-run` early-return bypass** — removed the `if (available.length === 0) return;` guard that prevented the `(Dry run)` banner from being printed when no fixes were available in dry-run mode

### Changed
- **`--ignore` behavior** — ID and title matching now uses substring comparison (`id.includes(ignore)`) instead of exact equality. This is a breaking change if you were relying on exact ID-only matching; use `--ignore "MCP-001"` still works exactly

## [0.1.1] — 2026-03-28

### Added
- `mcpshield list` command — discover all MCP config files on the system
- `mcpshield owasp` command — display OWASP MCP Top 10 reference framework
- `--no-spinner` flag — disable progress spinner for cleaner CI output
- `.mcpshieldrc` configuration file support — set project-wide defaults (severity threshold, ignore list, AI settings, etc.)
- **AI false positive reduction** — two-layer system: heuristic confidence scoring (always on) + opt-in LLM evaluation (BYOK)
- **Supported AI providers** — OpenAI, Anthropic, Google Gemini, and any OpenAI-compatible endpoint (Groq, Together, Ollama)
- **SARIF output** — GitHub Security tab integration via `github/codeql-action/upload-sarif`
- **Programmatic API** — import `scanAllServers`, `loadConfig`, `autoDetectConfig` and types directly from the package
- **Plugin system** — register custom scanners via `pluginRegistry.register(definePlugin({...}))`

### Fixed
- `mcpServers` array format support (Continue extension)
- `context_servers` format support (Zed editor)
- `servers` object format support (VS Code)
- `unknown` server type handling in pretty output
