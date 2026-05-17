# MCPShield Security Hardening — Full Audit Remediation

## TL;DR

> **Quick Summary**: Fix ALL security blind spots identified in the comprehensive audit — taxonomy mismatch, execution evasion, supply chain gaps, transport weaknesses, client-specific field blindness, and tooling defects — across 6 phases with 24 implementation tasks.
> 
> **Deliverables**:
> - Corrected OWASP MCP Top 10 taxonomy aligned with official standard
> - Hardened shell/interpreter detection in configuration scanner
> - Exact version pinning validation (no semver ranges)
> - Expanded typosquat, suspicious URL, and sensitive key coverage
> - Docker security option detection (--security-opt, --device, etc.)
> - Client-specific field parsing (autoApprove, alwaysAllow, type, inputs)
> - Fixed auto-fix logic (no more @latest pinning)
> - Finding ID scheme that doesn't collide with OWASP category IDs
> - SARIF helpUri fix (valid URLs, not category name strings)
> - New tool-poisoning informational scanner
> - All new detection rules backed by tests
> 
> **Estimated Effort**: Large
> **Parallel Execution**: YES - 6 waves
> **Critical Path**: T1 (types) → T5-T8 (scanner hardening) → T13-T15 (client fields) → T17-T18 (tooling) → T19-T22 (fixes) → F1-F4 (verification)

---

## Context

### Original Request
Fix ALL security issues identified in the comprehensive audit of MCPShield, covering taxonomy, execution, supply chain, transport, client-specific, and tooling gaps.

### Interview Summary
**Key Discussions**:
- User confirmed desire to fix ALL identified issues, not a subset
- All research completed via 3 explore agents + 1 librarian agent
- Metis consultation revealed additional gaps: Tool Poisoning (MCP-02) zero coverage, finding ID collision with OWASP IDs, SARIF helpUri bug, registry scanner low test coverage

**Research Findings**:
- 6 scanner files need modification, 3 data files need expansion
- Types need OWASP taxonomy replacement + finding ID scheme change
- Config loader needs client-specific field preservation
- Registry scanner at 61% lines / 44.8% branches (needs dedicated test file)
- Fix command pins to @latest (paradoxical behavior)
- Tests use `resetCounter()` pattern and `tempFixture()` for writable configs

### Metis Review
**Identified Gaps** (addressed):
- Tool Poisoning (MCP-02) has zero scanner coverage → Added Task T12 (informational scanner)
- Finding IDs (`MCP-001`) collide with OWASP category IDs (`MCP-01`) → Added Task T2 (ID scheme change)
- SARIF `helpUri` receives category names not URLs → Added Task T19 (SARIF fix)
- Registry scanner has no dedicated test file → Added to Task T10 (registry deepening)
- New findings must not shift existing test ID assertions → Guardrails in every scanner task

---

## Work Objectives

### Core Objective
Harden MCPShield to close every blind spot identified in the security audit, achieving comprehensive coverage of the official OWASP MCP Top 10 and eliminating all known detection bypasses.

### Concrete Deliverables
- Updated `src/types/index.ts` with official OWASP taxonomy + new finding ID scheme
- Hardened `src/scanners/configuration.ts` with shell interpreter + metacharacter detection
- Hardened `src/scanners/supply-chain.ts` with exact version pinning + expanded package runners
- Hardened `src/scanners/permissions.ts` with expanded sensitive keys + value pattern matching
- Hardened `src/scanners/threats.ts` with expanded typosquat + URL + obfuscation detection
- Hardened `src/scanners/transport.ts` with Docker security options + WebSocket detection
- Hardened `src/scanners/registry.ts` with deep PyPI analysis
- New `src/scanners/tool-poisoning.ts` informational scanner
- Updated `src/data/suspicious-patterns.json` with expanded URL + typosquat patterns
- Updated `src/scanners/config-loader.ts` with client-specific field parsing
- Updated `src/fix/index.ts` with correct version pinning logic
- Updated `src/formatters/sarif.ts` with valid helpUri
- Updated `src/cli.ts` with multi-config discovery
- Updated `src/ai/confidence.ts` with new rule adjustments
- New + updated test files for all changes

### Definition of Done
- [ ] `bun test` passes with 0 failures (all existing 216 + new tests)
- [ ] `bun run build` succeeds with 0 errors
- [ ] Every new detection rule has at least 1 happy-path + 1 edge-case test
- [ ] No `as any`, `@ts-ignore`, or type suppression anywhere
- [ ] All findings reference official OWASP MCP Top 10 categories (not custom taxonomy)

### Must Have
- All 6 audit areas fully addressed
- Zero regressions in existing 216 tests
- Official OWASP MCP Top 10 taxonomy (not custom)
- Exact version pin validation (reject semver ranges)
- Shell interpreter detection (bash, sh, node -e, etc.)
- Docker security option detection (--security-opt, --device, etc.)
- Expanded suspicious URL patterns (Discord, Telegram, serverless, etc.)
- Client-specific field parsing (autoApprove, alwaysAllow, type, inputs)
- Fixed auto-fix logic (no @latest)
- New finding ID scheme that doesn't collide with OWASP IDs

### Must NOT Have (Guardrails)
- NO new runtime dependencies (keep chalk, commander, ora only)
- NO breaking changes to the public API (`src/index.ts` exports)
- NO removal of existing detection rules (only additions and refinements)
- NO `as any`, `@ts-ignore`, or type suppression
- NO changes to test coverage threshold (70% stays)
- NO changes to CI/CD configuration
- NO changes to README/documentation except for the OWASP link correction in Task 1
- NO new scanner that requires network access by default (tool-poisoning scanner is informational only)
- NO assumptions about business logic without code evidence
- New findings MUST be appended AFTER existing ones in each scanner to avoid shifting test ID assertions

---

## Verification Strategy (MANDATORY)

> **ZERO HUMAN INTERVENTION** - ALL verification is agent-executed. No exceptions.

### Test Decision
- **Infrastructure exists**: YES (Vitest)
- **Automated tests**: YES (TDD — write failing test first, then implement)
- **Framework**: Vitest
- **If TDD**: Each task follows RED (failing test) → GREEN (minimal impl) → REFACTOR

### QA Policy
Every task MUST include agent-executed QA scenarios.
Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **Library/Module**: Use Bash (bun test) — Run specific test files, assert pass/fail counts
- **CLI**: Use Bash (bun run cli) — Run commands, validate output, check exit codes
- **Build**: Use Bash (bun run build) — Verify TypeScript compilation succeeds

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Foundation — types, IDs, data):
├── Task 1:  Replace OWASP taxonomy with official standard [quick]
├── Task 2:  Change finding ID scheme to avoid OWASP collision [quick]
├── Task 3:  Expand suspicious-patterns.json [quick]
├── Task 4:  Expand SENSITIVE_ENV_KEYS + add value patterns [quick]

Wave 2 (Scanner Hardening — MAX PARALLEL):
├── Task 5:  Harden configuration.ts — shell interpreters + metacharacters [deep]
├── Task 6:  Harden supply-chain.ts — exact pins + expanded runners [deep]
├── Task 7:  Harden permissions.ts — expanded keys + value patterns [unspecified-high]
├── Task 8:  Harden threats.ts — typosquat fix + URL expansion + obfuscation [deep]
├── Task 9:  Harden transport.ts — Docker security + WebSocket + SSE [deep]
├── Task 10: Harden registry.ts — deep PyPI analysis + dedicated tests [deep]
├── Task 11: Update confidence.ts — new rules for new detections [quick]
├── Task 12: Add tool-poisoning.ts — informational scanner [quick]

Wave 3 (Client + Config):
├── Task 13: Update config-loader.ts — parse client-specific fields [deep]
├── Task 14: Update types for client-specific fields (MCPServerConfig) [quick]
├── Task 15: Add client-specific security checks to scanners [unspecified-high]

Wave 4 (Tooling + UX):
├── Task 16: Update CLI — multi-config discovery [quick]
├── Task 17: Fix auto-fix logic — no @latest, validate HTTPS [quick]
├── Task 18: Add .mcpshieldrc integrity warning [quick]
├── Task 19: Fix SARIF helpUri — valid URLs [quick]
├── Task 20: Update scanner index — wire new scanner + disabled server logic [unspecified-high]

Wave 5 (Integration + Polish):
├── Task 21: Integration test — full scan with all new detections [deep]
├── Task 22: Update existing tests for taxonomy + ID changes [unspecified-high]

Wave FINAL (After ALL tasks — 4 parallel reviews):
├── Task F1: Plan compliance audit (oracle)
├── Task F2: Code quality review (unspecified-high)
├── Task F3: Real manual QA (unspecified-high)
├── Task F4: Scope fidelity check (deep)
→ Present results → Get explicit user okay

Critical Path: T1 → T5-T12 → T13-T15 → T16-T20 → T21-T22 → F1-F4
Parallel Speedup: ~65% faster than sequential
Max Concurrent: 8 (Wave 2)
```

### Dependency Matrix

| Task | Depends On | Blocks |
|------|-----------|--------|
| T1   | - | T5-T12, T14, T15, T19, T22 |
| T2   | - | T5-T12, T19, T22 |
| T3   | - | T8 |
| T4   | - | T7 |
| T5   | T1, T2 | T15, T20, T21 |
| T6   | T1, T2 | T15, T17, T20, T21 |
| T7   | T1, T2, T4 | T15, T20, T21 |
| T8   | T1, T2, T3 | T15, T20, T21 |
| T9   | T1, T2 | T15, T20, T21 |
| T10  | T1, T2 | T15, T20, T21 |
| T11  | T1 | T20 |
| T12  | T1, T2 | T20 |
| T13  | T1, T14 | T15 |
| T14  | T1 | T13, T15 |
| T15  | T5-T10, T13, T14 | T21 |
| T16  | - | T21 |
| T17  | T6 | T21 |
| T18  | - | T21 |
| T19  | T1, T2 | T21 |
| T20  | T5-T12 | T21 |
| T21  | T5-T20 | F1-F4 |
| T22  | T1, T2, T5-T12 | F1-F4 |

### Agent Dispatch Summary

- **Wave 1**: **4** tasks — T1-T4 → `quick`
- **Wave 2**: **8** tasks — T5, T6, T8-T10 → `deep`, T7 → `unspecified-high`, T11, T12 → `quick`
- **Wave 3**: **3** tasks — T13 → `deep`, T14 → `quick`, T15 → `unspecified-high`
- **Wave 4**: **5** tasks — T16-T19 → `quick`, T20 → `unspecified-high`
- **Wave 5**: **2** tasks — T21 → `deep`, T22 → `unspecified-high`
- **FINAL**: **4** tasks — F1 → `oracle`, F2-F3 → `unspecified-high`, F4 → `deep`

---

## TODOs

- [x] 1. Replace OWASP Taxonomy with Official Standard

  **What to do**:
  - Open `src/types/index.ts`
  - Replace the `OWASP_MCP_TOP_CATEGORIES` array with the official OWASP MCP Top 10 categories:
    ```
    MCP01:2025 - Token Mismanagement & Secret Exposure
    MCP02:2025 - Tool Poisoning
    MCP03:2025 - Privilege Escalation via Scope Creep
    MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering
    MCP05:2025 - Command Injection & Execution
    MCP06:2025 - Intent Flow Subversion
    MCP07:2025 - Insufficient Authentication & Authorization
    MCP08:2025 - Lack of Audit and Telemetry
    MCP09:2025 - Shadow MCP Servers
    MCP10:2025 - Context Injection & Over-Sharing
    ```
  - Update the `OWASPCategory` type to use the new format
  - Update ALL scanner files that reference `MCP-XX` category strings to use the new official category names
  - Fix the OWASP link in README.md from `/www-project-mcp-top/` to `/www-project-mcp-top-10/`
  - Update the `owasp` CLI command output to display the official categories

  **Must NOT do**:
  - Do not change the finding severity or detection logic
  - Do not add new scanners

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Mechanical find-and-replace of string constants across known files
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2, 3, 4)
  - **Blocks**: T5-T12, T14, T15, T19, T22
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/types/index.ts:71-82` — Current custom OWASP_MCP_TOP_CATEGORIES array to replace
  - `src/scanners/supply-chain.ts` — References `MCP-10`, `MCP-01`, `MCP-03` category strings
  - `src/scanners/permissions.ts` — References `MCP-06`, `MCP-07`, `MCP-09`, `MCP-04` category strings
  - `src/scanners/threats.ts` — References `MCP-08`, `MCP-01`, `MCP-07` category strings
  - `src/scanners/transport.ts` — References `MCP-06`, `MCP-07`, `MCP-01`, `MCP-03`, `MCP-04`, `MCP-09`, `MCP-08` category strings
  - `src/scanners/configuration.ts` — References `MCP-05`, `MCP-07` category strings
  - `src/scanners/registry.ts` — References `MCP-10`, `MCP-01` category strings

  **Test References**:
  - `tests/security-fixes.test.ts` — Tests that assert on finding references/category strings

  **External References**:
  - Official OWASP MCP Top 10: `https://owasp.org/www-project-mcp-top-10/`

  **WHY Each Reference Matters**:
  - `src/types/index.ts:71-82` is the single source of truth for categories — change this first, then update all consumers
  - Each scanner file uses these category strings in `references` arrays on findings — must be updated to match new names

  **Acceptance Criteria**:

  - [ ] `OWASP_MCP_TOP_CATEGORIES` contains exactly 10 entries matching the official OWASP standard
  - [ ] All scanner files reference the new category format
  - [ ] `bun test` passes with 0 failures
  - [ ] `bun run build` succeeds

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Official OWASP categories are present in types
    Tool: Bash
    Preconditions: Project built successfully
    Steps:
      1. Run: grep -c "MCP01:2025\|MCP02:2025\|MCP03:2025\|MCP04:2025\|MCP05:2025\|MCP06:2025\|MCP07:2025\|MCP08:2025\|MCP09:2025\|MCP10:2025" src/types/index.ts
      2. Assert count is 10
    Expected Result: All 10 official categories present
    Evidence: .sisyphus/evidence/task-1-owasp-categories.txt

  Scenario: No custom taxonomy strings remain in scanners
    Tool: Bash
    Preconditions: All scanner files updated
    Steps:
      1. Run: grep -rn "MCP-0[1-9]:\|MCP-10:" src/scanners/ || echo "CLEAN"
      2. Assert output is "CLEAN"
    Expected Result: Zero references to old custom format
    Evidence: .sisyphus/evidence/task-1-no-old-format.txt

  Scenario: All existing tests still pass
    Tool: Bash
    Steps:
      1. Run: bun test
      2. Assert exit code 0
    Expected Result: 216+ tests pass, 0 failures
    Evidence: .sisyphus/evidence/task-1-tests.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `refactor(types): align OWASP taxonomy with official MCP Top 10 standard`
  - Files: `src/types/index.ts`, all scanner files, README.md
  - Pre-commit: `bun test`

- [x] 2. Change Finding ID Scheme to Avoid OWASP Collision

  **What to do**:
  - Open `src/utils/helpers.ts`
  - Change the finding ID prefix from `MCP-` to `MCPS-` (MCPShield finding)
  - Update `ScanContext` class: `this.counter++` should produce `MCPS-001`, `MCPS-002`, etc.
  - Update ALL test files that assert on finding IDs containing `MCP-0` to use `MCPS-0`
  - Update `--ignore` flag documentation/help text to reflect new prefix
  - Update `.mcpshieldrc` schema if it references finding ID format

  **Must NOT do**:
  - Do not change the OWASP category ID format (those stay as `MCP01:2025`, etc.)
  - Do not change any detection logic

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Mechanical prefix change + test update
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 3, 4)
  - **Blocks**: T5-T12, T19, T22
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/utils/helpers.ts:15-20` — ScanContext class with counter and `MCP-` prefix generation
  - All test files in `tests/` — Assert on finding IDs like `MCP-001`, `MCP-002`

  **Test References**:
  - `tests/security-fixes.test.ts` — Asserts on specific finding IDs
  - `tests/cli-integration.test.ts` — CLI tests that may reference finding IDs in output

  **WHY Each Reference Matters**:
  - `helpers.ts:15-20` is the single point of ID generation — change the prefix here
  - Every test file that checks finding IDs must be updated to match the new prefix

  **Acceptance Criteria**:

  - [ ] Finding IDs use `MCPS-NNN` format (not `MCP-NNN`)
  - [ ] `bun test` passes with 0 failures
  - [ ] `bun run build` succeeds

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Finding IDs use MCPS- prefix
    Tool: Bash
    Steps:
      1. Run: grep -n "MCP-" src/utils/helpers.ts
      2. Assert: The only MCP- references are in the ID generation, now using MCPS-
      3. Run: bun test 2>&1 | grep -c "MCPS-"
      4. Assert: Count > 0 (tests reference new format)
    Expected Result: MCPS- prefix used for all finding IDs
    Evidence: .sisyphus/evidence/task-2-finding-ids.txt

  Scenario: No old MCP-NNN finding IDs in tests
    Tool: Bash
    Steps:
      1. Run: grep -rn "MCP-0[0-9][0-9][0-9]" tests/ || echo "CLEAN"
      2. Assert output is "CLEAN"
    Expected Result: Zero old-format finding IDs in test files
    Evidence: .sisyphus/evidence/task-2-no-old-ids.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `refactor(types): change finding IDs from MCP-NNN to MCPS-NNN`
  - Files: `src/utils/helpers.ts`, all test files
  - Pre-commit: `bun test`

- [x] 3. Expand suspicious-patterns.json

  **What to do**:
  - Open `src/data/suspicious-patterns.json`
  - Add to `suspiciousUrlPatterns`:
    - `discord.com/api/webhooks`, `discordapp.com/api/webhooks`
    - `api.telegram.org/bot`
    - `*.herokuapp.com`
    - `*.vercel.app`
    - `*.netlify.app`
    - `*.fly.dev`
    - `*.workers.dev` (Cloudflare Workers)
    - `*.cloudfunctions.net`
    - `execute-api.*.amazonaws.com`
    - `bit.ly`, `t.co`, `tinyurl.com`, `goo.gl`
    - `docs.google.com/forms/d/e/`
    - `script.google.com/macros/s/`
  - Add to `typosquatPatterns`:
    - Patterns for `@anthropic/` scope (common character swaps)
    - Patterns for `@openai/` scope
  - Ensure all new patterns have regex-compatible format matching existing entries

  **Must NOT do**:
  - Do not modify any scanner logic
  - Do not remove existing patterns

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Pure data file expansion, no logic changes
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 4)
  - **Blocks**: T8
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/data/suspicious-patterns.json` — Current 8 URL patterns + 4 typosquat patterns
  - `src/scanners/threats.ts:28-42` — How URL patterns and typosquat patterns are consumed

  **WHY Each Reference Matters**:
  - The JSON file structure determines what format new entries must follow
  - `threats.ts` shows how patterns are matched — new entries must be compatible with the regex engine

  **Acceptance Criteria**:

  - [ ] `suspiciousUrlPatterns` has 20+ entries (from current 8)
  - [ ] `typosquatPatterns` has 10+ entries (from current 4, adding @anthropic/ and @openai/ patterns)
  - [ ] JSON file is valid (parseable)
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Suspicious URL patterns expanded
    Tool: Bash
    Steps:
      1. Run: node -e "const d = require('./src/data/suspicious-patterns.json'); console.log(d.suspiciousUrlPatterns.length)"
      2. Assert count >= 20
    Expected Result: 20+ URL patterns present
    Evidence: .sisyphus/evidence/task-3-url-count.txt

  Scenario: Typosquat patterns expanded
    Tool: Bash
    Steps:
      1. Run: node -e "const d = require('./src/data/suspicious-patterns.json'); console.log(d.typosquatPatterns.length)"
      2. Assert count >= 10
    Expected Result: 10+ typosquat patterns present
    Evidence: .sisyphus/evidence/task-3-typosquat-count.txt

  Scenario: Discord webhook detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/threats.test.ts 2>&1
      2. Verify existing URL detection tests still pass
    Expected Result: All pass, new patterns loaded
    Evidence: .sisyphus/evidence/task-3-patterns-test.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `feat(data): expand suspicious URL and typosquat detection patterns`
  - Files: `src/data/suspicious-patterns.json`
  - Pre-commit: `bun test`

- [x] 4. Expand SENSITIVE_ENV_KEYS + Add Value Patterns

  **What to do**:
  - Open `src/scanners/permissions.ts`
  - Expand `SENSITIVE_ENV_KEYS` array (currently 12 entries) to include:
    - `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
    - `HEROKU_API_KEY`
    - `TWILIO_AUTH_TOKEN`
    - `SENDGRID_API_KEY`
    - `MAILGUN_API_KEY`
    - `CLOUDFLARE_API_TOKEN`
    - `DIGITALOCEAN_TOKEN`
    - `GOOGLE_APPLICATION_CREDENTIALS`
    - `NPM_TOKEN`, `PYPI_API_TOKEN`
    - `VAULT_TOKEN`
    - `KUBERNETES_TOKEN`, `SERVICE_ACCOUNT_KEY`
    - `JWT_SECRET`, `ENCRYPTION_KEY`
  - Add new detection: **secret value pattern matching** on env VALUES (not just keys)
    - AWS access key: value starts with `AKIA` (20 char pattern)
    - AWS secret key: value matches `/^[A-Za-z0-9/+=]{40}$/`
    - GitHub token: value matches `/^ghp_[a-zA-Z0-9]{36}$/`
    - GitHub OAuth: value matches `/^gho_[a-zA-Z0-9]{36}$/`
    - Slack token: value starts with `xoxb-`, `xoxp-`
    - Stripe key: value starts with `sk_live_`, `sk_test_`
  - Add corresponding tests in `tests/permissions.test.ts`

  **Must NOT do**:
  - Do not remove existing keys
  - Do not change severity levels of existing detections

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Array expansion + new conditional block in existing scanner
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3)
  - **Blocks**: T7
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/scanners/permissions.ts:9-16` — Current `SENSITIVE_ENV_KEYS` array with 12 entries
  - `src/scanners/permissions.ts:46-60` — Current credential detection logic checking key names

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing permission-related tests

  **External References**:
  - AWS key format: `https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html`
  - GitHub token format: `https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication`

  **WHY Each Reference Matters**:
  - `permissions.ts:9-16` is where the key list lives — add to this array
  - `permissions.ts:46-60` shows the pattern for checking env vars — follow same pattern for value checking

  **Acceptance Criteria**:

  - [ ] `SENSITIVE_ENV_KEYS` has 28+ entries (from current 12)
  - [ ] Value pattern matching detects AWS keys, GitHub tokens, Slack tokens, Stripe keys
  - [ ] New tests pass for all added patterns
  - [ ] `bun test` passes with 0 regressions

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: New sensitive env keys detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify tests for AZURE_CLIENT_SECRET, NPM_TOKEN, JWT_SECRET pass
    Expected Result: New key detection tests pass
    Evidence: .sisyphus/evidence/task-4-env-keys.txt

  Scenario: AWS key value pattern detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify test for AKIA-prefixed value detection passes
    Expected Result: Value pattern test passes
    Evidence: .sisyphus/evidence/task-4-value-patterns.txt

  Scenario: No regressions
    Tool: Bash
    Steps:
      1. Run: bun test
      2. Assert exit code 0, all 216+ tests pass
    Expected Result: 0 failures
    Evidence: .sisyphus/evidence/task-4-no-regressions.txt
  ```

  **Commit**: YES (groups with Wave 1)
  - Message: `feat(permissions): expand sensitive env key detection and add value pattern matching`
  - Files: `src/scanners/permissions.ts`, `tests/permissions.test.ts`
  - Pre-commit: `bun test`

- [x] 5. Harden configuration.ts — Shell Interpreters + Metacharacters

  **What to do**:
  - Open `src/scanners/configuration.ts`
  - Add NEW detections (append AFTER existing `return findings` at the end, before the final return):
    1. **Shell Interpreter Detection**: Flag `cmd` values of `bash`, `sh`, `zsh`, `dash`, `ksh`, `csh`, `tcsh` as `high` severity with reference to `MCP05:2025 - Command Injection & Execution`
    2. **Shell `-c` / `-e` Flag Detection**: If cmd is any interpreter (including `node`, `python`, `perl`, `ruby`, `php`) AND args contain `-c` or `-e`, flag as `critical` severity
    3. **Newline Injection**: If any arg contains `\n` or `\r`, flag as `high` severity
    4. **Input Redirect**: If any arg contains `< ` (with space) as a standalone token, flag as `high`
    5. **Append Redirect**: If any arg contains `>>`, flag as `high`
    6. **`$VAR` Expansion**: If any arg contains `$` followed by alphanumeric chars NOT inside `$(...)`, flag as `medium` (shell variable expansion risk)
    7. **`bash -c` / `sh -c` specifically**: Flag as `critical` with confidence +0.15
    8. **`/usr/bin/env` wrapper**: If `cmd` is `env` or `/usr/bin/env`, flag as `medium` (indirect execution)
    9. **`node -e` / `node --eval`**: If `cmd` is `node` and args contain `-e` or `--eval`, flag as `critical`
    10. **`--require` / `-r` preload**: If `cmd` is `node` and args contain `--require` or `-r` (not as a require.resolve pattern), flag as `high`
  - Map all new detections to `MCP05:2025 - Command Injection & Execution`
  - Add corresponding tests in `tests/configuration.test.ts`

  **Must NOT do**:
  - Do not remove or modify existing detection rules (only append new ones)
  - Do not change the early-return behavior for missing command or disabled server (those are addressed in Task 20)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multiple new detection rules with nuanced regex patterns, needs careful implementation to avoid false positives
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 6-12)
  - **Blocks**: T15, T20, T21
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/scanners/configuration.ts:1-88` — Current scanner with 6 detection rules; new rules append after line 88
  - `src/scanners/configuration.ts:48-63` — Existing shell metacharacter detection pattern to follow for new metachar rules

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing configuration scanner tests

  **WHY Each Reference Matters**:
  - `configuration.ts:1-88` shows the full scanner structure — new rules must follow same pattern of pushing to `findings` array
  - `configuration.ts:48-63` shows the metacharacter detection style — new char checks should follow same `dangerousChars` + loop pattern

  **Acceptance Criteria**:

  - [ ] Shell interpreters (bash, sh, zsh) detected as `high` severity
  - [ ] `bash -c`, `node -e` detected as `critical` severity
  - [ ] Newline injection (`\n` in args) detected as `high`
  - [ ] Input redirect (`<`) and append redirect (`>>`) detected
  - [ ] `/usr/bin/env` wrapper detected as `medium`
  - [ ] `node --require` preload detected as `high`
  - [ ] All new rules have tests
  - [ ] `bun test` passes with 0 regressions

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Shell interpreter detection works
    Tool: Bash
    Steps:
      1. Run: bun test tests/configuration.test.ts 2>&1
      2. Verify "bash" and "sh" command detection tests pass
    Expected Result: Shell interpreter tests pass with correct severity
    Evidence: .sisyphus/evidence/task-5-shell-interpreters.txt

  Scenario: Node -e detection works
    Tool: Bash
    Steps:
      1. Run: bun test tests/configuration.test.ts 2>&1
      2. Verify "node -e" and "node --eval" detection tests pass
    Expected Result: Direct code execution tests pass with critical severity
    Evidence: .sisyphus/evidence/task-5-node-eval.txt

  Scenario: Newline injection detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/configuration.test.ts 2>&1
      2. Verify test for args containing "\n" passes
    Expected Result: Newline injection test passes
    Evidence: .sisyphus/evidence/task-5-newline.txt

  Scenario: No regressions in existing tests
    Tool: Bash
    Steps:
      1. Run: bun test
      2. Assert 0 failures
    Expected Result: All existing tests pass
    Evidence: .sisyphus/evidence/task-5-regressions.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(configuration): detect shell interpreters, code exec flags, and advanced metacharacters`
  - Files: `src/scanners/configuration.ts`, `tests/configuration.test.ts`
  - Pre-commit: `bun test`

- [x] 6. Harden supply-chain.ts — Exact Pins + Expanded Runners

  **What to do**:
  - Open `src/scanners/supply-chain.ts`
  - Fix **version pinning validation**: Replace the simple `lastIndexOf('@')` check with exact semver validation:
    - Extract version part after the last `@` (for scoped packages, after the second `@`)
    - Validate it matches exact semver: `/^\d+\.\d+\.\d+$/`
    - Flag as unpinned if version is: `latest`, `*`, `x` range, contains `^`, `~`, `>=`, `<=`, `>`, `<`, `||`, ` - `, or any non-exact range syntax
  - Add **new package runner detection**: Expand beyond `npx`/`bunx` to also check:
    - `npm exec` (equivalent to npx)
    - `pnpm dlx` (equivalent to npx for pnpm)
    - `yarn dlx` (equivalent to npx for yarn)
    - `bun x` (note the space vs `bunx`)
    - Apply the same unpinned, risky, unverified checks to these runners
  - Add **Python version pinning**: For `uvx`/`python`/`python3` commands, check if the package arg includes `==X.Y.Z` exact version. If not, flag as unpinned.
  - Map new detections to `MCP04:2025 - Software Supply Chain Attacks & Dependency Tampering`
  - Add tests

  **Must NOT do**:
  - Do not remove existing trusted/risky package lists
  - Do not change the behavior for existing `npx`/`bunx` detections (only expand)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Complex version parsing logic with edge cases (scoped packages, semver ranges)
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 7-12)
  - **Blocks**: T15, T17, T20, T21
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/scanners/supply-chain.ts:11-26` — Current unpinned version check using `lastIndexOf('@')` — must be replaced with exact semver validation
  - `src/scanners/supply-chain.ts:8-9` — `if (cmd === 'npx' || cmd === 'bunx')` — must be expanded to include new runners

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing supply chain tests

  **External References**:
  - Semver specification: `https://semver.org/`

  **WHY Each Reference Matters**:
  - `supply-chain.ts:11-26` is the flawed version check — this is the core logic to replace
  - `supply-chain.ts:8-9` is the runner check — this is where new runners must be added

  **Acceptance Criteria**:

  - [ ] `pkg@^1.0.0` flagged as unpinned (not accepted)
  - [ ] `pkg@~1.0.0` flagged as unpinned
  - [ ] `pkg@latest` flagged as unpinned
  - [ ] `pkg@*` flagged as unpinned
  - [ ] `pkg@1.0.0` accepted as pinned (no finding)
  - [ ] `npm exec`, `pnpm dlx`, `yarn dlx` detected as package runners
  - [ ] Python packages without `==X.Y.Z` flagged
  - [ ] All new rules have tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Semver ranges rejected as unpinned
    Tool: Bash
    Steps:
      1. Run: bun test tests/supply-chain.test.ts 2>&1
      2. Verify tests for ^, ~, latest, *, >= ranges all produce unpinned finding
    Expected Result: All semver range variants flagged
    Evidence: .sisyphus/evidence/task-6-semver-ranges.txt

  Scenario: Exact versions accepted
    Tool: Bash
    Steps:
      1. Run: bun test tests/supply-chain.test.ts 2>&1
      2. Verify test for "pkg@1.2.3" produces no unpinned finding
    Expected Result: Exact version passes pinning check
    Evidence: .sisyphus/evidence/task-6-exact-version.txt

  Scenario: New package runners detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/supply-chain.test.ts 2>&1
      2. Verify tests for "npm exec", "pnpm dlx" runner detection pass
    Expected Result: All runners trigger supply chain checks
    Evidence: .sisyphus/evidence/task-6-new-runners.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(supply-chain): enforce exact version pins and detect additional package runners`
  - Files: `src/scanners/supply-chain.ts`, `tests/supply-chain.test.ts`
  - Pre-commit: `bun test`

- [x] 7. Harden permissions.ts — Expanded Keys + Value Patterns

  **What to do**:
  - Open `src/scanners/permissions.ts`
  - This task validates that Task 4's changes integrate correctly and adds additional detections:
    1. **`sudo` in command**: If `cmd` is `sudo` or args contain `sudo`, flag as `critical`
    2. **`chmod`/`chown` in args**: Flag as `high` (privilege escalation)
    3. **Expanded filesystem access**: Add `/tmp`, `/proc`, `/sys`, `/dev`, `/var/run`, `/run`, `/opt` to `DANGEROUS_PATHS`
    4. **Path traversal in args**: Detect `/./`, `/../`, `//` sequences in args
    5. **IPv6 any address**: Detect `:::` (IPv6 any with port) in addition to existing `0.0.0.0`
  - Map new detections to appropriate OWASP categories (`MCP03:2025`, `MCP07:2025`)
  - Add tests

  **Must NOT do**:
  - Do not change existing filesystem path detection logic (only expand the list)
  - Do not modify the confidence scoring rules (that's Task 11)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Multiple detection additions across different permission concerns
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5, 6, 8-12)
  - **Blocks**: T15, T20, T21
  - **Blocked By**: T1, T2, T4

  **References**:

  **Pattern References**:
  - `src/scanners/permissions.ts:26-43` — `DANGEROUS_PATHS` array to expand
  - `src/scanners/permissions.ts:66-73` — Network binding detection (`0.0.0.0`, `::`) — add `:::`

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing permission tests

  **WHY Each Reference Matters**:
  - `permissions.ts:26-43` is where dangerous paths are listed — add new entries to this array
  - `permissions.ts:66-73` shows how network binding is detected — add IPv6 variant

  **Acceptance Criteria**:

  - [ ] `sudo` in command/args detected as `critical`
  - [ ] `/tmp`, `/proc`, `/sys`, `/dev` added to dangerous paths
  - [ ] Path traversal (`/../`) detected in args
  - [ ] IPv6 `:::` detected
  - [ ] All new rules have tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Sudo detection works
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify sudo command and sudo-in-args tests pass
    Expected Result: Sudo flagged as critical
    Evidence: .sisyphus/evidence/task-7-sudo.txt

  Scenario: Expanded dangerous paths
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify /tmp, /proc, /dev, /sys path access detection tests pass
    Expected Result: All new paths flagged as dangerous
    Evidence: .sisyphus/evidence/task-7-paths.txt

  Scenario: Path traversal detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify /../ and /./ path traversal tests pass
    Expected Result: Path traversal flagged
    Evidence: .sisyphus/evidence/task-7-traversal.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(permissions): detect sudo, expanded paths, path traversal, and IPv6 any`
  - Files: `src/scanners/permissions.ts`, `tests/permissions.test.ts`
  - Pre-commit: `bun test`

- [x] 8. Harden threats.ts — Typosquat Fix + URL Expansion + Obfuscation

  **What to do**:
  - Open `src/scanners/threats.ts`
  - Fix **typosquat scope-extension bypass**: Change the check from `!arg.includes(original)` to exact scope matching:
    - Extract the scope part of the arg (everything before the first `/`)
    - Compare the extracted scope against the typosquat pattern match
    - Only flag if the scope itself matches the typosquat regex AND is NOT the exact original scope
  - Add **reverse shell pattern detection**: Detect args/env values containing:
    - `nc -l`, `ncat -l`, `socat TCP-LISTEN`
    - `/dev/tcp/`, `/dev/udp/`
    - `bash -i >&`, `sh -i >&`
    - Flag as `critical` with reference to `MCP05:2025`
  - Add **hex-encoded string detection**: If env values contain long hex sequences (`/[0-9a-fA-F]{32,}/`), flag as `medium`
  - Add **short base64 detection**: Lower the minimum from 40 to 20 chars for env values that don't match known token prefixes
  - Add **URL in command field**: Check `config.command` itself for suspicious URL patterns (currently only args/env/url/headers are checked)
  - Add **URL-encoded payload detection**: Detect `%XX` encoded sequences in env values that decode to suspicious patterns
  - Add **credentials in URL**: Detect `user:pass@` pattern in `config.url`
  - Map to appropriate OWASP categories
  - Add tests

  **Must NOT do**:
  - Do not remove existing typosquat patterns (only fix the bypass logic)
  - Do not change the base64 detection for known token prefixes (`sk-`, `ghp_` exemptions stay)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Complex typosquat logic fix + multiple new detection categories with encoding awareness
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5-7, 9-12)
  - **Blocks**: T15, T20, T21
  - **Blocked By**: T1, T2, T3

  **References**:

  **Pattern References**:
  - `src/scanners/threats.ts:28-42` — Typosquat detection with the flawed `!arg.includes(original)` check — this is the line to fix
  - `src/scanners/threats.ts:44-58` — Suspicious URL detection — expand to include command field
  - `src/scanners/threats.ts:60-75` — Base64 obfuscation detection — lower char threshold

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing threat tests

  **WHY Each Reference Matters**:
  - `threats.ts:28-42` contains the bypass — the `includes()` check allows `@modelcontextprotocol-evil` to pass
  - `threats.ts:44-58` only checks args/env/url/headers but not command field
  - `threats.ts:60-75` has the 40-char minimum that misses short payloads

  **Acceptance Criteria**:

  - [ ] `@modelcontextprotocol-evil/server` now flagged as typosquat
  - [ ] `@modelcontextprotocol/server-github` still NOT flagged (legitimate)
  - [ ] Reverse shell patterns (`nc -l`, `/dev/tcp/`) detected as `critical`
  - [ ] Hex-encoded strings detected as `medium`
  - [ ] Base64 threshold lowered to 20 chars
  - [ ] URLs in command field checked for suspicious patterns
  - [ ] Credentials in URLs detected (`user:pass@`)
  - [ ] All new rules have tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Typosquat scope extension bypass fixed
    Tool: Bash
    Steps:
      1. Run: bun test tests/threats.test.ts 2>&1
      2. Verify test for "@modelcontextprotocol-evil/server" produces typosquat finding
      3. Verify test for "@modelcontextprotocol/server-github" does NOT produce typosquat
    Expected Result: Bypass closed, legitimate package still allowed
    Evidence: .sisyphus/evidence/task-8-typosquat-fix.txt

  Scenario: Reverse shell detection
    Tool: Bash
    Steps:
      1. Run: bun test tests/threats.test.ts 2>&1
      2. Verify "nc -l" and "/dev/tcp/" tests pass with critical severity
    Expected Result: Reverse shell patterns detected
    Evidence: .sisyphus/evidence/task-8-reverse-shell.txt

  Scenario: No regressions
    Tool: Bash
    Steps:
      1. Run: bun test
      2. Assert 0 failures
    Expected Result: All tests pass
    Evidence: .sisyphus/evidence/task-8-regressions.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(threats): fix typosquat bypass, add reverse shell/hex/URL detection`
  - Files: `src/scanners/threats.ts`, `tests/threats.test.ts`
  - Pre-commit: `bun test`

- [x] 9. Harden transport.ts — Docker Security + WebSocket + SSE

  **What to do**:
  - Open `src/scanners/transport.ts`
  - Add to `DANGEROUS_DOCKER_FLAGS`:
    - `--security-opt seccomp=unconfined`
    - `--security-opt apparmor=unconfined`
    - `--security-opt label=disable`
    - `--user root`
    - `--userns=host`
    - `--uts=host`
    - `--cgroupns=host`
    - `--device` (any device mount — flag as `high`)
    - `--dns` (DNS hijacking risk)
    - `--add-host` (DNS override)
    - `--entrypoint` (entrypoint override)
  - Fix `--cap-add` detection: Also detect `--cap-add ALL` (space-separated, not just `=` syntax) and additional capabilities: `NET_ADMIN`, `CHOWN`, `DAC_OVERRIDE`, `SETUID`, `SETGID`
  - Add to `SENSITIVE_DOCKER_MOUNTS`:
    - `/proc`, `/sys`, `/dev`, `/tmp`, `/var`, `/run`
    - `:/` as target (root mount regardless of source)
  - Add **`--mount` syntax** detection: Parse `--mount type=bind,source=...,target=...` syntax in addition to `-v`
  - Add **`docker compose`/`docker-compose` command detection**: Flag as `medium` with note "compose files not statically analyzed"
  - Add **WebSocket detection**: If `config.url` starts with `ws://` (not `wss://`), flag as `high`
  - Add **URL credentials detection**: If `config.url` contains `@` before the path (user:pass@host), flag as `high`
  - Map to `MCP07:2025` and `MCP05:2025`
  - Add tests

  **Must NOT do**:
  - Do not remove existing Docker flag/mount/port checks
  - Do not add network-dependent checks (all detection is static)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Many new Docker detection rules with complex string parsing for --mount and --cap-add space syntax
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5-8, 10-12)
  - **Blocks**: T15, T20, T21
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/scanners/transport.ts:4-12` — `DANGEROUS_DOCKER_FLAGS` array to expand
  - `src/scanners/transport.ts:14-20` — `SENSITIVE_DOCKER_MOUNTS` array to expand
  - `src/scanners/transport.ts:80-92` — Docker flag detection loop — add `--cap-add` space syntax
  - `src/scanners/transport.ts:139-149` — HTTP transport check — add WebSocket here

  **WHY Each Reference Matters**:
  - `transport.ts:4-12` is the flag list — add all missing dangerous Docker options
  - `transport.ts:14-20` is the mount list — add missing sensitive paths
  - `transport.ts:80-92` only checks `includes()` — need to also check space-separated values
  - `transport.ts:139-149` only checks `http://` — add `ws://` check

  **Acceptance Criteria**:

  - [ ] `--security-opt seccomp=unconfined` detected as `critical`
  - [ ] `--cap-add ALL` (space syntax) detected
  - [ ] `--user root` detected
  - [ ] `--device /dev/sda` detected
  - [ ] `/proc`, `/sys`, `/dev` mount detection works
  - [ ] `docker compose` flagged with "not statically analyzed" note
  - [ ] `ws://` URLs detected as insecure
  - [ ] URL credentials (`user:pass@`) detected
  - [ ] `--mount` syntax parsed for sensitive source paths
  - [ ] All new rules have tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Docker security options detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/transport.test.ts 2>&1
      2. Verify --security-opt, --user root, --device tests pass
    Expected Result: All Docker security options flagged
    Evidence: .sisyphus/evidence/task-9-docker-security.txt

  Scenario: Docker compose flagged
    Tool: Bash
    Steps:
      1. Run: bun test tests/transport.test.ts 2>&1
      2. Verify "docker compose" and "docker-compose" tests pass with warning
    Expected Result: Docker compose flagged as not statically analyzed
    Evidence: .sisyphus/evidence/task-9-docker-compose.txt

  Scenario: WebSocket detected
    Tool: Bash
    Steps:
      1. Run: bun test tests/transport.test.ts 2>&1
      2. Verify ws:// URL detection test passes
    Expected Result: Insecure WebSocket flagged
    Evidence: .sisyphus/evidence/task-9-websocket.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(transport): detect Docker security options, compose, WebSocket, and URL credentials`
  - Files: `src/scanners/transport.ts`, `tests/transport.test.ts`
  - Pre-commit: `bun test`

- [x] 10. Harden registry.ts — Deep PyPI Analysis + Dedicated Tests

  **What to do**:
  - Open `src/scanners/registry.ts`
  - Expand PyPI checks to match npm-level analysis:
    1. **PyPI package age**: Parse `data.releases` to determine first release date. Flag if < 30 days.
    2. **PyPI version count**: Count unique versions in `data.releases`. Flag if <= 1.
    3. **PyPI maintainer count**: Parse `data.info.author` and `data.info.author_email`. Flag if only one author AND no `project_urls` with repository link.
    4. **PyPI missing source repo**: Check `data.info.project_urls` for `Repository` or `Source` links. Flag if missing.
  - Create new dedicated test file `tests/registry.test.ts`:
    - Mock PyPI API responses for all new checks
    - Mock npm API responses for existing check validation
    - Use `beforeEach(() => resetCounter())` pattern
    - Target raising coverage from 61% to 70%+ (above threshold)
  - Map to `MCP04:2025`

  **Must NOT do**:
  - Do not change npm check logic (only add PyPI depth)
  - Do not make registry checks default-on (that's a separate decision)

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: PyPI API response parsing + dedicated test file with mocked HTTP responses
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5-9, 11, 12)
  - **Blocks**: T15, T20, T21
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/scanners/registry.ts:87-108` — npm existence check pattern to follow for PyPI deep checks
  - `src/scanners/registry.ts:114-167` — npm metadata checks (age, version count, maintainer, repo) — replicate for PyPI
  - `src/scanners/registry.ts:170-190` — Current shallow PyPI check (only existence) — expand this

  **Test References**:
  - `tests/security-fixes.test.ts` — Existing registry tests (only 2 HTTP error cases)

  **External References**:
  - PyPI JSON API: `https://warehouse.pypa.io/api-reference/json.html`

  **WHY Each Reference Matters**:
  - `registry.ts:114-167` is the template for deep npm checks — follow this pattern for PyPI
  - `registry.ts:170-190` is the current PyPI stub — this is where deep analysis goes
  - PyPI JSON API docs explain the response structure for `releases`, `info.author`, `info.project_urls`

  **Acceptance Criteria**:

  - [ ] PyPI package age check works (< 30 days flagged)
  - [ ] PyPI version count check works (<= 1 flagged)
  - [ ] PyPI missing source repo check works
  - [ ] `tests/registry.test.ts` created with 10+ test cases
  - [ ] Registry scanner coverage > 70%
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: PyPI deep analysis works
    Tool: Bash
    Steps:
      1. Run: bun test tests/registry.test.ts 2>&1
      2. Verify tests for PyPI age, version count, and missing repo pass
    Expected Result: All PyPI deep analysis tests pass
    Evidence: .sisyphus/evidence/task-10-pypi-deep.txt

  Scenario: Registry test coverage above threshold
    Tool: Bash
    Steps:
      1. Run: bun test tests/registry.test.ts --coverage 2>&1
      2. Verify registry.ts line coverage > 70%
    Expected Result: Coverage meets 70% threshold
    Evidence: .sisyphus/evidence/task-10-coverage.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(registry): deep PyPI analysis with age, version, and repo checks`
  - Files: `src/scanners/registry.ts`, `tests/registry.test.ts`
  - Pre-commit: `bun test`

- [x] 11. Update confidence.ts — New Rules for New Detections

  **What to do**:
  - Open `src/ai/confidence.ts`
  - Add new confidence adjustment rules for the new detection types:
    - `bash`/`sh` as command: +0.15 (high confidence it's dangerous)
    - `node -e`/`python -c`: +0.2 (very high confidence for direct code execution)
    - Reverse shell patterns: +0.25 (extremely high confidence)
    - Docker `--security-opt`: +0.15 (clear security weakening)
    - Docker `--user root`: +0.15
    - `sudo` in command: +0.2 (unambiguous privilege escalation)
    - Docker compose: -0.2 (lower confidence — can't analyze compose file)
    - `ws://` transport: +0.1
    - Credentials in URL: +0.15
    - Semver range (not exact pin): +0.1 (still a real risk, but less than fully unpinned)
    - Expanded typosquat (scope extension): +0.1
  - Append new rules AFTER existing rules in the `calculateConfidence` function
  - Add tests for new confidence rules

  **Must NOT do**:
  - Do not change existing confidence rules
  - Do not change base confidence values by severity

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Adding new conditional blocks to existing rule engine
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5-10, 12)
  - **Blocks**: T20
  - **Blocked By**: T1

  **References**:

  **Pattern References**:
  - `src/ai/confidence.ts:20-150` — Existing confidence rules — follow same pattern of checking finding properties and returning adjustment

  **Test References**:
  - `tests/confidence.test.ts` — Existing confidence tests

  **WHY Each Reference Matters**:
  - `confidence.ts:20-150` shows the rule structure — each rule checks finding text/references/severity and returns a signed adjustment

  **Acceptance Criteria**:

  - [ ] New confidence rules for all new detection types present
  - [ ] Existing confidence rules unchanged
  - [ ] Tests for new rules pass
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: New confidence rules applied
    Tool: Bash
    Steps:
      1. Run: bun test tests/confidence.test.ts 2>&1
      2. Verify tests for bash, node -e, sudo, --security-opt rules pass
    Expected Result: All new confidence rules tested and passing
    Evidence: .sisyphus/evidence/task-11-confidence.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(confidence): add scoring rules for new detection types`
  - Files: `src/ai/confidence.ts`, `tests/confidence.test.ts`
  - Pre-commit: `bun test`

- [x] 12. Add tool-poisoning.ts — Informational Scanner

  **What to do**:
  - Create new file `src/scanners/tool-poisoning.ts`
  - Implement an informational scanner that:
    1. Checks if a server has `autoApprove` or `alwaysAllow` fields (once Task 13/14 adds these to the type) — if so, flags tools listed there as "auto-approved without user confirmation" with `medium` severity
    2. Emits an informational finding for EVERY server: "This scanner cannot verify tool behavior at runtime. Tool poisoning (MCP02:2025) requires runtime analysis. Consider using MCPShield's watch mode for ongoing monitoring."
    3. Checks if a server URL is present but no auth headers — warns "Remote server without authentication may serve poisoned tool definitions"
  - Follow the same export pattern as other scanners: `export function scanToolPoisoning(name: string, config: MCPServerConfig): Finding[]`
  - Map all findings to `MCP02:2025 - Tool Poisoning`
  - This scanner does NOT make network requests — it's purely static analysis
  - Add test file `tests/tool-poisoning.test.ts`

  **Must NOT do**:
  - Do not make network requests
  - Do not attempt to analyze actual tool schemas (that's runtime behavior)
  - Do not flag this as critical — it's informational

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: New file following established scanner pattern, purely informational
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 2 (with Tasks 5-11)
  - **Blocks**: T20
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/scanners/configuration.ts` — Follow this file's structure for the new scanner
  - `src/types/index.ts` — Finding type, Severity, OWASP categories

  **Test References**:
  - `tests/security-fixes.test.ts` — Follow this pattern for test structure

  **WHY Each Reference Matters**:
  - `configuration.ts` is the simplest scanner — use as template for the new file

  **Acceptance Criteria**:

  - [ ] `src/scanners/tool-poisoning.ts` created
  - [ ] Informational finding emitted for every server about runtime analysis limitation
  - [ ] Auto-approved tools flagged if `autoApprove`/`alwaysAllow` present
  - [ ] No network requests made
  - [ ] Test file created with 5+ tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Tool poisoning scanner works
    Tool: Bash
    Steps:
      1. Run: bun test tests/tool-poisoning.test.ts 2>&1
      2. Verify informational finding emitted
      3. Verify auto-approved tools detection test passes
    Expected Result: All tool-poisoning tests pass
    Evidence: .sisyphus/evidence/task-12-tool-poisoning.txt

  Scenario: No network requests
    Tool: Bash
    Steps:
      1. Read src/scanners/tool-poisoning.ts
      2. Verify no `fetch`, `http`, `https`, or `request` imports
    Expected Result: No network imports present
    Evidence: .sisyphus/evidence/task-12-no-network.txt
  ```

  **Commit**: YES (groups with Wave 2)
  - Message: `feat(tool-poisoning): add informational scanner for MCP02:2025`
  - Files: `src/scanners/tool-poisoning.ts`, `tests/tool-poisoning.test.ts`
  - Pre-commit: `bun test`

- [x] 13. Update config-loader.ts — Parse Client-Specific Fields

  **What to do**:
  - Open `src/scanners/config-loader.ts`
  - For **VS Code** configs: Parse and preserve the `type` field (http/sse/stdio)
  - For **VS Code** configs: Parse `inputs` array and detect `${input:...}` variable references
  - For **Claude Desktop** configs: Parse `autoApprove` and `alwaysAllow` arrays from server entries
  - For **Zed** configs: Parse `settings` sub-object from `command` entries
  - For **Continue** configs: Handle URL-only servers correctly (no "Missing Command" false positive when `url` is present)
  - Store these in extended fields on the normalized config (the MCPServerConfig type is updated in Task 14)

  **Must NOT do**:
  - Do not break existing config loading for any client format
  - Do not remove support for any client

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Multi-format config parsing with client-specific edge cases
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO (depends on T14 for type)
  - **Parallel Group**: Wave 3 (with Tasks 14, 15)
  - **Blocks**: T15
  - **Blocked By**: T1, T14

  **References**:

  **Pattern References**:
  - `src/scanners/config-loader.ts:6-32` — Client path auto-detection
  - `src/scanners/config-loader.ts:34-60` — Claude Desktop / Cursor / Windsurf parsing
  - `src/scanners/config-loader.ts:62-80` — Zed `context_servers` parsing — currently drops `settings`
  - `src/scanners/config-loader.ts:82-105` — VS Code / Continue parsing — currently drops `type` and `inputs`

  **Test References**:
  - `tests/config-loader.test.ts` — Existing config loader tests
  - `tests/fixtures/vscode-config.json` — VS Code fixture with `type` field
  - `tests/fixtures/continue-config.json` — Continue fixture with URL-only server

  **WHY Each Reference Matters**:
  - `config-loader.ts:62-80` drops Zed settings — must be preserved
  - `config-loader.ts:82-105` drops VS Code type/inputs — must be preserved
  - Fixtures show the actual client config formats being parsed

  **Acceptance Criteria**:

  - [ ] VS Code `type` field preserved in parsed config
  - [ ] Claude `autoApprove`/`alwaysAllow` arrays preserved
  - [ ] Zed `settings` object preserved
  - [ ] Continue URL-only servers not flagged as "Missing Command"
  - [ ] `${input:...}` references detected
  - [ ] All existing config loading still works
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Client-specific fields preserved
    Tool: Bash
    Steps:
      1. Run: bun test tests/config-loader.test.ts 2>&1
      2. Verify tests for type, autoApprove, settings field parsing pass
    Expected Result: All client-specific field tests pass
    Evidence: .sisyphus/evidence/task-13-client-fields.txt

  Scenario: Continue URL-only server handled
    Tool: Bash
    Steps:
      1. Run: bun test tests/config-loader.test.ts 2>&1
      2. Verify URL-only server not treated as missing command
    Expected Result: URL-only servers parsed as transport configs
    Evidence: .sisyphus/evidence/task-13-continue-url.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `feat(config-loader): parse and preserve client-specific fields`
  - Files: `src/scanners/config-loader.ts`, `tests/config-loader.test.ts`
  - Pre-commit: `bun test`

- [x] 14. Update MCPServerConfig Type for Client-Specific Fields

  **What to do**:
  - Open `src/types/index.ts`
  - Add optional fields to `MCPServerConfig` interface:
    - `type?: 'stdio' | 'sse' | 'http'` — transport type (VS Code)
    - `autoApprove?: string[]` — auto-approved tool names (Claude Desktop)
    - `alwaysAllow?: string[]` — always-allowed tool names (Claude Desktop)
    - `inputs?: Array<{id: string; type: string; password?: boolean}>` — VS Code input variables
    - `settings?: Record<string, unknown>` — Zed context server settings
  - All fields are optional to maintain backward compatibility

  **Must NOT do**:
  - Do not make any fields required
  - Do not change existing fields

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Adding optional fields to an existing interface
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 3 (with Tasks 13, 15)
  - **Blocks**: T13, T15
  - **Blocked By**: T1

  **References**:

  **Pattern References**:
  - `src/types/index.ts:MCPServerConfig` — Current interface with command, args, env, cwd, disabled, url, headers

  **WHY Each Reference Matters**:
  - This is the type that config-loader normalizes to — new fields must be declared here first

  **Acceptance Criteria**:

  - [ ] New optional fields added to MCPServerConfig
  - [ ] `bun run build` succeeds (no type errors)
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: New type fields compile
    Tool: Bash
    Steps:
      1. Run: bun run build
      2. Assert exit code 0
    Expected Result: TypeScript compilation succeeds
    Evidence: .sisyphus/evidence/task-14-type-build.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `feat(types): add client-specific fields to MCPServerConfig`
  - Files: `src/types/index.ts`
  - Pre-commit: `bun run build && bun test`

- [x] 15. Add Client-Specific Security Checks to Scanners

  **What to do**:
  - Update existing scanners to check the new client-specific fields:
    1. **`autoApprove`/`alwaysAllow` check** (in `permissions.ts` or new logic): If a server has `autoApprove` or `alwaysAllow` with tool names, AND the server also has broad filesystem access or network binding, flag as `high` — "Auto-approved tools with broad permissions bypass user confirmation"
    2. **`${input:...}` dynamic input** (in `configuration.ts`): If args contain `${input:...}` patterns, flag as `medium` — "Dynamic input from VS Code variables cannot be statically analyzed"
    3. **`type: 'http'` without `url`** (in `transport.ts`): If `type` is `'http'` or `'sse'` but no `url` field, flag as `medium`
    4. **`type: 'stdio'` with `url`** (in `transport.ts`): If `type` is `'stdio'` but `url` is present, flag as `info` — "URL field ignored for stdio transport"
    5. **Continue URL-only server**: When `url` is present but `command` is empty AND `type` is `'sse'` or `'http'`, treat as valid transport config (not missing command)
  - Map to appropriate OWASP categories
  - Add tests

  **Must NOT do**:
  - Do not add checks that require network access
  - Do not break existing scanner logic for configs without client-specific fields

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Cross-cutting changes across multiple scanner files
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 3 (sequential after T13, T14)
  - **Blocks**: T21
  - **Blocked By**: T5-T10, T13, T14

  **References**:

  **Pattern References**:
  - `src/scanners/permissions.ts` — Where autoApprove/alwaysAllow checks go
  - `src/scanners/configuration.ts` — Where dynamic input checks go
  - `src/scanners/transport.ts` — Where transport type consistency checks go

  **WHY Each Reference Matters**:
  - These are the scanners that need to consume the new client-specific fields

  **Acceptance Criteria**:

  - [ ] autoApprove with broad filesystem access flagged
  - [ ] `${input:...}` patterns flagged as dynamic/unanalyzable
  - [ ] Transport type consistency checked
  - [ ] Continue URL-only servers handled correctly
  - [ ] All new checks have tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Auto-approved tools with broad access flagged
    Tool: Bash
    Steps:
      1. Run: bun test tests/permissions.test.ts 2>&1
      2. Verify test for autoApprove + filesystem access passes
    Expected Result: Auto-approved tools with dangerous access flagged
    Evidence: .sisyphus/evidence/task-15-autoapprove.txt

  Scenario: Dynamic input detection
    Tool: Bash
    Steps:
      1. Run: bun test tests/configuration.test.ts 2>&1
      2. Verify ${input:apiKey} detection test passes
    Expected Result: Dynamic input flagged as unanalyzable
    Evidence: .sisyphus/evidence/task-15-dynamic-input.txt
  ```

  **Commit**: YES (groups with Wave 3)
  - Message: `feat(scanners): add client-specific security checks for autoApprove, inputs, transport type`
  - Files: `src/scanners/permissions.ts`, `src/scanners/configuration.ts`, `src/scanners/transport.ts`, related test files
  - Pre-commit: `bun test`

- [x] 16. Update CLI — Multi-Config Discovery

  **What to do**:
  - Open `src/cli.ts`
  - Modify `autoDetectConfig` function (or equivalent): Instead of returning the first discovered config, return ALL discovered configs
  - Update the `scan` command: When no `--config` is specified, scan ALL discovered configs and merge findings
  - Add a summary line: "Scanned N config files from [client names]"
  - Preserve the `--config` flag behavior for single-file scanning

  **Must NOT do**:
  - Do not remove the `--config` flag
  - Do not change the output format (findings array structure stays the same)

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Logic change in discovery function + scan loop
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 17-20)
  - **Blocks**: T21
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/cli.ts` — CLI entry point with scan command
  - `src/scanners/config-loader.ts:autoDetectConfig` — Current single-config discovery

  **WHY Each Reference Matters**:
  - `config-loader.ts:autoDetectConfig` currently returns first found — must return all

  **Acceptance Criteria**:

  - [ ] `mcpshield scan` (no --config) discovers and scans ALL client configs
  - [ ] `mcpshield scan --config path` still scans single file
  - [ ] Summary shows number of configs scanned
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Multi-config discovery works
    Tool: Bash
    Steps:
      1. Run: bun test tests/cli-integration.test.ts 2>&1
      2. Verify multi-config discovery test passes
    Expected Result: All discovered configs scanned
    Evidence: .sisyphus/evidence/task-16-multi-config.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(cli): scan all discovered config files by default`
  - Files: `src/cli.ts`, `src/scanners/config-loader.ts`, `tests/cli-integration.test.ts`
  - Pre-commit: `bun test`

- [x] 17. Fix Auto-Fix Logic — No @latest, Validate HTTPS

  **What to do**:
  - Open `src/fix/index.ts`
  - Fix version pinning: Instead of pinning to `@latest`, resolve the actual latest version and pin to the exact `@X.Y.Z`
    - For npm packages: Look up the version from the registry (fetch `https://registry.npmjs.org/pkg/latest` and extract `version`)
    - For packages where registry lookup fails: Pin to `@0.0.0-REVIEW-NEEDED` (force manual review) instead of `@latest`
  - Fix HTTP → HTTPS upgrade: Before upgrading, validate that the HTTPS version is actually reachable (or at minimum, add a comment in the fixed config noting the upgrade may break servers without HTTPS)
  - Add tests

  **Must NOT do**:
  - Do not make the fix command require network access for all fixes (only for version resolution)
  - Do not change the backup/restore mechanism

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Targeted logic fix in existing auto-fix code
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 16, 18-20)
  - **Blocks**: T21
  - **Blocked By**: T6

  **References**:

  **Pattern References**:
  - `src/fix/index.ts:24` — Line that pins to `@latest` — must be replaced with exact version resolution

  **WHY Each Reference Matters**:
  - `fix/index.ts:24` is the paradoxical line — pinning to @latest is the same as unpinned

  **Acceptance Criteria**:

  - [ ] Fix no longer pins to `@latest`
  - [ ] When registry reachable, pins to exact `@X.Y.Z`
  - [ ] When registry unreachable, pins to `@0.0.0-REVIEW-NEEDED`
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Fix pins to exact version
    Tool: Bash
    Steps:
      1. Run: bun test tests/fix.test.ts 2>&1
      2. Verify fix produces exact version pin, not @latest
    Expected Result: No @latest in fix output
    Evidence: .sisyphus/evidence/task-17-exact-pin.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `fix(auto-fix): pin to exact versions instead of @latest`
  - Files: `src/fix/index.ts`, `tests/fix.test.ts`
  - Pre-commit: `bun test`

- [x] 18. Add .mcpshieldrc Integrity Warning

  **What to do**:
  - Open `src/config/index.ts`
  - When loading `.mcpshieldrc`, add warning logic:
    - If file contains `ignore` entries, emit a warning to stderr: "⚠ .mcpshieldrc contains N ignore rules — verify these were not maliciously added"
    - If file contains `trustedPackages` entries beyond defaults, emit a warning: "⚠ .mcpshieldrc adds N trusted packages — verify these are legitimate"
    - If `minConfidence` is set above 0.8, emit a warning: "⚠ .mcpshieldrc sets high minConfidence — this may suppress real findings"
  - Warnings go to stderr (not stdout) so they don't break JSON/SARIF output
  - Add tests

  **Must NOT do**:
  - Do not refuse to load the config (only warn)
  - Do not change the ignore/trusted behavior

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: Adding warning console output during config load
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 16, 17, 19, 20)
  - **Blocks**: T21
  - **Blocked By**: None

  **References**:

  **Pattern References**:
  - `src/config/index.ts` — .mcpshieldrc loader

  **WHY Each Reference Matters**:
  - This is where config overrides are applied — the warning must happen at load time

  **Acceptance Criteria**:

  - [ ] Warning emitted when `ignore` entries present
  - [ ] Warning emitted when custom `trustedPackages` present
  - [ ] Warning emitted when `minConfidence > 0.8`
  - [ ] Warnings go to stderr only
  - [ ] Config still loads normally
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Integrity warnings emitted
    Tool: Bash
    Steps:
      1. Run: bun test tests/config-shield.test.ts 2>&1
      2. Verify warning tests pass
    Expected Result: Warnings emitted for suspicious .mcpshieldrc entries
    Evidence: .sisyphus/evidence/task-18-integrity.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(config): warn about potentially malicious .mcpshieldrc overrides`
  - Files: `src/config/index.ts`, `tests/config-shield.test.ts`
  - Pre-commit: `bun test`

- [x] 19. Fix SARIF helpUri — Valid URLs

  **What to do**:
  - Open `src/formatters/sarif.ts`
  - Fix `helpUri` to contain valid URLs instead of OWASP category name strings:
    - When a finding has a reference that looks like a URL (starts with `https://`), use it as `helpUri`
    - When a finding has only OWASP category text (e.g., `MCP05:2025 - Command Injection`), construct a URL: `https://owasp.org/www-project-mcp-top-10/` as the base, and use the category as a descriptor
    - Never put plain text (non-URL strings) in `helpUri`
  - Update all scanners to include the OWASP reference URL in their `references` array:
    - Add `'https://owasp.org/www-project-mcp-top-10/'` to every finding's references
  - Add tests

  **Must NOT do**:
  - Do not change the SARIF structure or schema
  - Do not break existing SARIF consumers

  **Recommended Agent Profile**:
  - **Category**: `quick`
    - Reason: URL construction logic in formatter + adding URL string to scanner references
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 16-18, 20)
  - **Blocks**: T21
  - **Blocked By**: T1, T2

  **References**:

  **Pattern References**:
  - `src/formatters/sarif.ts` — SARIF formatter using `finding.references[0]` as helpUri

  **WHY Each Reference Matters**:
  - This is where the invalid URIs are emitted — fix must ensure only valid URLs are used

  **Acceptance Criteria**:

  - [ ] SARIF `helpUri` always contains a valid URL (starts with `https://`)
  - [ ] No plain-text category strings in `helpUri`
  - [ ] All findings include OWASP reference URL in references
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: SARIF helpUri is valid URL
    Tool: Bash
    Steps:
      1. Run: bun test tests/sarif.test.ts 2>&1
      2. Verify all helpUri values start with "https://"
    Expected Result: All helpUri fields are valid URLs
    Evidence: .sisyphus/evidence/task-19-sarif-url.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `fix(sarif): ensure helpUri contains valid URLs, not category text`
  - Files: `src/formatters/sarif.ts`, all scanner files (references arrays), `tests/sarif.test.ts`
  - Pre-commit: `bun test`

- [x] 20. Update Scanner Index — Wire New Scanner + Disabled Server Logic

  **What to do**:
  - Open `src/scanners/index.ts`
  - Add `scanToolPoisoning` to the scanner pipeline (import from `./tool-poisoning.ts`)
  - Add it to the `scanServer` findings array: `...scanToolPoisoning(name, config)`
  - Fix the **disabled server handling**: Instead of letting all scanners run on disabled servers (which pollutes scores), add a clear "DORMANT RISK" label:
    - If `config.disabled === true`, still run all scanners BUT prefix all findings with "[Dormant]" in the description
    - OR: separate findings into "active" and "dormant" categories in the scan result
    - The key fix: the `calculateScore` function should NOT penalize for dormant findings (or clearly separate the score)
  - Add error handling for the new scanner in `scanAllServersWithRegistry`
  - Add tests

  **Must NOT do**:
  - Do not skip scanning disabled servers entirely
  - Do not remove the existing "Disabled Server" info finding

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Orchestrator changes affecting all scanners + score calculation
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 4 (with Tasks 16-19)
  - **Blocks**: T21
  - **Blocked By**: T5-T12

  **References**:

  **Pattern References**:
  - `src/scanners/index.ts:35-50` — Scanner pipeline where all scanners are composed
  - `src/scanners/index.ts:53-56` — Error handling for registry scanner
  - `src/utils/helpers.ts:54-57` — `calculateScore` function

  **WHY Each Reference Matters**:
  - `index.ts:35-50` is where the new tool-poisoning scanner must be wired in
  - `helpers.ts:54-57` is where dormant risk scoring must be adjusted

  **Acceptance Criteria**:

  - [ ] `scanToolPoisoning` included in scanner pipeline
  - [ ] Disabled server findings clearly labeled as "Dormant"
  - [ ] Dormant findings don't inflate the security score
  - [ ] Error handling for new scanner present
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Tool poisoning scanner wired in
    Tool: Bash
    Steps:
      1. Run: bun test tests/scanner-index.test.ts 2>&1
      2. Verify tool-poisoning findings appear in scan results
    Expected Result: Tool poisoning scanner runs as part of pipeline
    Evidence: .sisyphus/evidence/task-20-wired.txt

  Scenario: Dormant risk separated
    Tool: Bash
    Steps:
      1. Run: bun test tests/scanner-index.test.ts 2>&1
      2. Verify disabled server findings are labeled dormant
      3. Verify dormant findings don't affect score
    Expected Result: Dormant risks clearly separated from active risks
    Evidence: .sisyphus/evidence/task-20-dormant.txt
  ```

  **Commit**: YES (groups with Wave 4)
  - Message: `feat(scanners): wire tool-poisoning scanner and separate dormant risk scoring`
  - Files: `src/scanners/index.ts`, `src/utils/helpers.ts`, related test files
  - Pre-commit: `bun test`

- [x] 21. Integration Test — Full Scan with All New Detections

  **What to do**:
  - Create comprehensive integration test file `tests/integration-hardening.test.ts`
  - Test scenarios:
    1. **Malicious config with all bypass vectors**: A config using `bash -c`, newline injection, scope-extension typosquat, semver range pinning, `--security-opt`, and Discord webhook URL — verify ALL are detected in a single scan
    2. **Disabled server with malicious config**: Verify dormant labeling + score separation
    3. **Multi-config scan**: Multiple config files with different client formats
    4. **Clean config with all new checks**: A properly configured server that should produce minimal findings
    5. **SARIF output validation**: Full scan with SARIF output, verify all helpUri are valid URLs
    6. **Fix command integration**: Auto-fix produces exact version pins
  - Use `beforeEach(() => resetCounter())` pattern
  - Use `tempFixture()` for writable configs

  **Must NOT do**:
  - Do not test implementation details (only test behavior)
  - Do not use network-dependent tests

  **Recommended Agent Profile**:
  - **Category**: `deep`
    - Reason: Comprehensive integration test covering all new detections together
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 5 (sequential, after all implementation)
  - **Blocks**: F1-F4
  - **Blocked By**: T5-T20

  **References**:

  **Test References**:
  - `tests/cli-integration.test.ts` — Pattern for integration tests with `tempFixture()`
  - `tests/security-fixes.test.ts` — Pattern for scanner-specific tests

  **WHY Each Reference Matters**:
  - `cli-integration.test.ts` shows how to test the full CLI pipeline
  - `security-fixes.test.ts` shows how to test individual scanner findings

  **Acceptance Criteria**:

  - [ ] All 6 integration scenarios pass
  - [ ] No network dependencies in tests
  - [ ] `bun test` passes

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: Full bypass detection integration
    Tool: Bash
    Steps:
      1. Run: bun test tests/integration-hardening.test.ts 2>&1
      2. Verify test catches all bypass vectors in single scan
    Expected Result: All bypass vectors detected, 0 missed
    Evidence: .sisyphus/evidence/task-21-integration.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `test: add comprehensive integration tests for security hardening`
  - Files: `tests/integration-hardening.test.ts`
  - Pre-commit: `bun test`

- [x] 22. Update Existing Tests for Taxonomy + ID Changes

  **What to do**:
  - Update ALL test files that assert on:
    - Old OWASP category strings (e.g., `MCP-01: Malicious Server Distribution` → `MCP01:2025 - Token Mismanagement & Secret Exposure`)
    - Old finding IDs (e.g., `MCP-001` → `MCPS-001`)
  - This is a catch-all task to ensure all test assertions match the new taxonomy and ID scheme
  - Run full test suite to verify zero regressions

  **Must NOT do**:
  - Do not change test logic or assertions about finding COUNTS or SEVERITIES
  - Only update string references (category names and finding IDs)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
    - Reason: Many test files to update with string replacements, must be thorough
  - **Skills**: []

  **Parallelization**:
  - **Can Run In Parallel**: NO
  - **Parallel Group**: Wave 5 (with Task 21)
  - **Blocks**: F1-F4
  - **Blocked By**: T1, T2, T5-T12

  **References**:

  **Test References**:
  - All files in `tests/` — Any test asserting on finding references or IDs

  **WHY Each Reference Matters**:
  - Every test file that checks finding properties needs string updates

  **Acceptance Criteria**:

  - [ ] No test references old OWASP category format
  - [ ] No test references old `MCP-NNN` finding IDs
  - [ ] `bun test` passes with 0 failures

  **QA Scenarios (MANDATORY):**

  ```
  Scenario: All tests pass with new taxonomy
    Tool: Bash
    Steps:
      1. Run: bun test
      2. Assert 0 failures
    Expected Result: Full suite passes
    Evidence: .sisyphus/evidence/task-22-full-suite.txt

  Scenario: No old category strings in tests
    Tool: Bash
    Steps:
      1. Run: grep -rn "MCP-0[1-9]:\|MCP-10:" tests/ || echo "CLEAN"
      2. Assert output is "CLEAN"
    Expected Result: Zero old category strings
    Evidence: .sisyphus/evidence/task-22-no-old.txt
  ```

  **Commit**: YES (groups with Wave 5)
  - Message: `test: update all tests for official OWASP taxonomy and new finding IDs`
  - Files: All test files in `tests/`
  - Pre-commit: `bun test`

---

## Final Verification Wave (MANDATORY — after ALL implementation tasks)

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [x] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [x] F2. **Code Quality Review** — `unspecified-high`
  Run `tsc --noEmit` + linter + `bun test`. Review all changed files for: `as any`/`@ts-ignore`, empty catches, console.log in prod, commented-out code, unused imports. Check AI slop: excessive comments, over-abstraction, generic names.
  Output: `Build [PASS/FAIL] | Lint [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [x] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state. Run `bun run build && bun test`. Execute EVERY QA scenario from EVERY task. Test cross-task integration. Test edge cases. Save to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [x] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff. Verify 1:1 — everything in spec was built, nothing beyond spec was built. Check "Must NOT do" compliance. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

- **Wave 1 complete**: `refactor(types): align OWASP taxonomy with official MCP Top 10 standard`
- **Wave 2 complete**: `feat(scanners): harden all detection rules per security audit`
- **Wave 3 complete**: `feat(config): parse client-specific fields for differential security checks`
- **Wave 4 complete**: `fix(tooling): correct auto-fix logic, SARIF output, and config discovery`
- **Wave 5 complete**: `test: add integration tests and update existing tests for new taxonomy`
- **Final**: `test: final verification wave — all audit issues resolved`

---

## Success Criteria

### Verification Commands
```bash
bun test                    # Expected: ALL pass (216+ existing + all new)
bun run build               # Expected: 0 errors
tsc --noEmit                # Expected: 0 errors
```

### Final Checklist
- [x] All "Must Have" present
- [x] All "Must NOT Have" absent
- [x] All tests pass
- [x] OWASP taxonomy matches official standard
- [x] Finding IDs don't collide with OWASP category IDs
- [x] Shell interpreters detected (bash, sh, node -e, etc.)
- [x] Version pinning rejects semver ranges
- [x] Docker security options detected
- [x] Client-specific fields parsed and checked
- [x] Auto-fix pins to exact versions (not @latest)
- [x] SARIF helpUri contains valid URLs
