# Contributing to MCPShield

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Adding a New Check](#adding-a-new-check)
- [Updating Package Lists](#updating-package-lists)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a branch** for your change: `git checkout -b feat/my-improvement`
4. Make your changes, write tests, and open a PR

## Development Setup

```bash
# Install dependencies
npm install

# Run the CLI in dev mode (no build needed)
npm run dev -- scan --config path/to/your/mcp.json

# Build
npm run build

# Type-check only
npm run typecheck
```

## Running Tests

```bash
# Run all tests once
npm test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage
```

Tests live in `tests/`. Each scanner module has a corresponding test file. Test fixtures live in `tests/fixtures/`.

## Project Structure

```
src/
  cli.ts              # CLI entry point (commands: scan, fix, watch, list, owasp)
  index.ts            # Public API exports
  config/             # .mcpshieldrc loader and severity filtering
  data/               # Externalized JSON package lists and patterns
  fix/                # Auto-fix engine
  formatters/         # Output formatters (SARIF)
  plugins/            # Plugin registry and API
  scanners/           # Scanner modules
    config-loader.ts  # MCP config discovery and loading
    configuration.ts  # Command/argument checks
    index.ts          # Orchestrator
    permissions.ts    # Filesystem and secret checks
    registry.ts       # Remote npm/PyPI verification
    supply-chain.ts   # Package version and provenance checks
    threats.ts        # Typosquatting, obfuscation, suspicious URLs
    transport.ts      # Docker and HTTP/SSE transport checks
  types/              # Shared TypeScript types
  utils/              # Helpers (scoring, ScanContext, icons)
tests/
  fixtures/           # Sample MCP config files for testing
  *.test.ts           # Test suites
```

## Adding a New Check

1. Identify the right scanner module (`configuration.ts`, `permissions.ts`, `supply-chain.ts`, `threats.ts`, or `transport.ts`), or create a new one.
2. Use `createFinding()` to produce a typed finding with a clear title, description, severity, and remediation.
3. Map it to the closest [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top/) category in `references`.
4. Add a test case in the corresponding test file, with a fixture in `tests/fixtures/` if needed.
5. If the check belongs in a new scanner module, register it in `src/scanners/index.ts`.

**Severity guidelines:**

| Severity | When to use |
|----------|-------------|
| `critical` | Direct path to code execution or data exfiltration |
| `high` | Significant risk requiring prompt attention |
| `medium` | Meaningful risk but requires specific conditions to exploit |
| `low` | Best-practice violation with limited direct risk |
| `info` | Informational, no risk implied |

## Updating Package Lists

The trusted, risky, and suspicious-pattern lists are plain JSON files — no code change required:

- `src/data/trusted-packages.json` — add verified legitimate packages
- `src/data/risky-packages.json` — add packages confirmed malicious or highly suspicious
- `src/data/suspicious-patterns.json` — add URL patterns or typosquat regexes

When submitting additions to these lists, please include a brief justification in your PR description (npm link, CVE reference, news article, etc.).

## Submitting a Pull Request

- Keep PRs focused — one feature or fix per PR
- All tests must pass (`npm test`)
- TypeScript must compile cleanly (`npm run typecheck`)
- Update `CHANGELOG.md` under `[Unreleased]` with a summary of your change
- If you're adding a new CLI flag or command, update `README.md`

## Reporting Bugs

Open a [GitHub Issue](https://github.com/ferrierepete/mcpshield/issues) and include:

- Your OS and Node.js version
- The MCPShield version (`mcpshield --version`)
- The command you ran
- The expected vs actual output
- Your MCP config file (with secrets redacted)
