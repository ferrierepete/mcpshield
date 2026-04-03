# 🔒 MCPShield v0.2.0 — AI-Powered False Positive Reduction

MCPShield now uses a two-layer system to reduce false positives: **heuristic confidence scoring** (always on, zero config) and **opt-in AI evaluation** with BYOK (Bring Your Own Key) support.

## ✨ What's New

### Heuristic Confidence Scoring (no API key needed)

Every finding now gets a **confidence score** (0.0–1.0) based on 20+ contextual rules:

- Trusted packages flagged as unpinned → lower confidence
- Env vars using `${VAR}` references (not hardcoded) → lower confidence
- Private IP addresses / localhost HTTP → lower confidence
- `--privileged` Docker flag, known risky packages, typosquats → higher confidence

Filter out noise with `--min-confidence`:

```bash
npx @ferrierepete/mcpshield scan --min-confidence 0.7
```

### AI-Powered Evaluation (opt-in, BYOK)

Pass `--ai` to send findings to an LLM for contextual analysis. Each finding receives a verdict: **confirmed**, **likely false positive**, or **needs review**.

**Supported providers:**

| Provider | Flag | Default Model |
|----------|------|---------------|
| OpenAI | `--ai-provider openai` | `gpt-4o-mini` |
| Anthropic | `--ai-provider anthropic` | `claude-sonnet-4-20250514` |
| Google Gemini | `--ai-provider gemini` | `gemini-2.0-flash` |
| OpenAI-compatible | `--ai-provider openai --ai-base-url <url>` | — |

Works with **Groq, Together AI, Ollama**, and any OpenAI-compatible endpoint.

```bash
# Set your API key
export GEMINI_API_KEY=your-key-here

# Run with AI evaluation
npx @ferrierepete/mcpshield scan --ai --ai-provider gemini --ai-model gemini-3-flash-preview
```

### 🔐 Security

- Env var **values are never sent** to AI providers — only key names are included in prompts
- API keys are read from environment variables (BYOK), never stored

## New CLI Flags

| Flag | Description |
|------|-------------|
| `--ai` | Enable AI-based false positive reduction |
| `--ai-provider <name>` | AI provider: `openai`, `anthropic`, `gemini` |
| `--ai-model <model>` | Override the default model |
| `--ai-base-url <url>` | Custom OpenAI-compatible endpoint |
| `--min-confidence <n>` | Minimum confidence threshold (0.0–1.0) |

## .mcpshieldrc Support

```json
{
  "ai": true,
  "aiProvider": "openai",
  "aiModel": "gpt-4o-mini",
  "minConfidence": 0.6
}
```

## Environment Variables

- `MCPSHIELD_AI_PROVIDER` — default provider
- `MCPSHIELD_AI_MODEL` — override model
- `MCPSHIELD_AI_BASE_URL` — custom endpoint
- `MCPSHIELD_OPENAI_API_KEY` / `OPENAI_API_KEY`
- `MCPSHIELD_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY`
- `MCPSHIELD_GEMINI_API_KEY` / `GEMINI_API_KEY` / `GOOGLE_API_KEY`

## Stats

- **144 tests** across 11 test suites (52 new)
- **1,451 lines** added across 14 files
- Zero breaking changes — fully backward compatible

---

**Full Changelog:** https://github.com/ferrierepete/mcpshield/compare/v0.1.1...v0.2.0
