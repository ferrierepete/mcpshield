# Changelog

All notable changes to MCPShield are documented here.

## [0.2.2] — 2026-04-04

### Fixed
- **Build: copy JSON data files to `dist/`** — `tsc` only compiles `.ts` files, so the JSON data files (`trusted-packages.json`, `risky-packages.json`, `suspicious-patterns.json`) loaded at runtime via `readFileSync` were missing in `dist/data/` on clean builds, causing all scan/fix/watch commands to crash
- **Lint: remove unused imports and variables** — removed unused `existsSync`/`cpSync` from `src/fix/index.ts` and unused `getAvailableFixes` from `src/cli.ts`
- **CI: add build step before tests** — CLI integration tests spawn `node dist/cli.js`, which requires a prior build

## [0.2.1] — 2026-04-04

### Fixed
- **`--config` path traversal prevention** — the `--config` flag on `scan`, `fix`, and `watch` commands now gates all paths through `resolveSafeConfigPath()`. Previously, `--config /etc/passwd` would attempt to load the file directly, bypassing the path traversal protection that was already in place for `MCP_CONFIG_PATH` and auto-detection. Paths outside `cwd` and `homedir` are now rejected with a clear error message
- **npm registry non-OK HTTP responses treated as unverified** — when the npm registry returns a non-OK HTTP status (e.g. 500, 429 rate limit), the package is now correctly marked as `exists: false` and surfaces a "Package Not Found on npm" finding. Previously, non-OK responses silently returned `exists: true`, allowing potentially malicious packages to pass registry checks without verification. This is consistent with the PyPI handler and the network error handler

### Added
- **Path traversal regression tests** — 8 new tests covering `--config` path traversal rejection across `scan`, `fix`, and `watch` commands (both CLI integration and unit level)
- **Registry HTTP error regression tests** — 3 new tests verifying that npm HTTP 500, 429, and 200 responses are handled correctly

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
