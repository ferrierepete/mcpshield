import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { evaluateWithAI, applyAIEvaluations } from '../src/ai/evaluator.js';
import { resolveAIConfig, createProvider } from '../src/ai/providers.js';
import type { Finding, AIConfig, MCPServerConfig } from '../src/types/index.js';

function makeFinding(id: string, title: string, severity: Finding['severity'] = 'high'): Finding {
  return {
    id,
    title,
    description: `Description for ${title}`,
    severity,
    category: 'configuration',
    serverName: 'test-server',
    remediation: 'Fix it',
  };
}

/** Helper that adds a .text() implementation alongside .json() for all mock fetch responses. */
function withText<T extends { json?: () => Promise<unknown> }>(mockResponse: T): T & { text: () => Promise<string> } {
  return {
    ...mockResponse,
    text: async () => JSON.stringify(mockResponse.json ? await mockResponse.json() : {}),
  } as T & { text: () => Promise<string> };
}

describe('AI Evaluator', () => {
  describe('applyAIEvaluations', () => {
    it('should apply AI verdicts to matching findings', () => {
      const findings: Finding[] = [
        makeFinding('MCPS-001', 'Unpinned Package Version'),
        makeFinding('MCPS-002', 'Sensitive Credentials in Config'),
      ];
      const evaluations = [
        { findingId: 'MCPS-001', verdict: 'likely-false-positive' as const, confidence: 0.3, reasoning: 'Trusted package' },
        { findingId: 'MCPS-002', verdict: 'confirmed' as const, confidence: 0.95, reasoning: 'Real hardcoded secret' },
      ];

      const result = applyAIEvaluations(findings, evaluations);
      expect(result[0].aiVerdict).toBe('likely-false-positive');
      expect(result[0].confidence).toBe(0.3);
      expect(result[1].aiVerdict).toBe('confirmed');
      expect(result[1].confidence).toBe(0.95);
    });

    it('should leave findings unchanged when no matching evaluation', () => {
      const findings: Finding[] = [
        makeFinding('MCPS-001', 'Unpinned Package Version'),
      ];
      const evaluations = [
        { findingId: 'MCPS-999', verdict: 'confirmed' as const, confidence: 0.9, reasoning: 'Different finding' },
      ];

      const result = applyAIEvaluations(findings, evaluations);
      expect(result[0].aiVerdict).toBeUndefined();
      expect(result[0].confidence).toBeUndefined();
    });

    it('should handle empty findings array', () => {
      const result = applyAIEvaluations([], []);
      expect(result).toEqual([]);
    });

    it('should handle empty evaluations array', () => {
      const findings: Finding[] = [makeFinding('MCPS-001', 'Test')];
      const result = applyAIEvaluations(findings, []);
      expect(result).toHaveLength(1);
      expect(result[0].aiVerdict).toBeUndefined();
    });
  });

  describe('evaluateWithAI', () => {
    const originalFetch = global.fetch;

    afterEach(() => {
      global.fetch = originalFetch;
      vi.restoreAllMocks();
    });

    it('should return empty evaluations for empty findings', async () => {
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };
      const result = await evaluateWithAI([], {}, aiConfig);
      expect(result.evaluations).toEqual([]);
    });

    it('should call OpenAI API and parse response', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify([
                { findingId: 'MCPS-001', verdict: 'confirmed', confidence: 0.9, reasoning: 'Real risk' },
              ]),
            },
          }],
          model: 'gpt-4o-mini',
          usage: { prompt_tokens: 100, completion_tokens: 50 },
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test Finding')];
      const configs: Record<string, MCPServerConfig> = {
        'test-server': { command: 'npx', args: ['-y', 'some-pkg'] },
      };
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key', model: 'gpt-4o-mini' };

      const result = await evaluateWithAI(findings, configs, aiConfig);
      expect(result.evaluations).toHaveLength(1);
      expect(result.evaluations[0].verdict).toBe('confirmed');
      expect(result.model).toBe('gpt-4o-mini');
      expect(result.usage).toBeDefined();
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should call Anthropic API correctly', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          content: [{
            type: 'text',
            text: JSON.stringify([
              { findingId: 'MCPS-001', verdict: 'likely-false-positive', confidence: 0.2, reasoning: 'Trusted pkg' },
            ]),
          }],
          model: 'claude-sonnet-4-20250514',
          usage: { input_tokens: 100, output_tokens: 50 },
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = { provider: 'anthropic', apiKey: 'test-key' };

      const result = await evaluateWithAI(findings, {}, aiConfig);
      expect(result.evaluations).toHaveLength(1);
      expect(result.evaluations[0].verdict).toBe('likely-false-positive');

      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[0]).toBe('https://api.anthropic.com/v1/messages');
      expect(JSON.parse(fetchCall[1].body)).toHaveProperty('model');
    });

    it('should call Gemini API correctly', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          candidates: [{
            content: {
              parts: [{
                text: JSON.stringify([
                  { findingId: 'MCPS-001', verdict: 'needs-review', confidence: 0.5, reasoning: 'Unclear' },
                ]),
              }],
            },
          }],
          usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 50 },
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = { provider: 'gemini', apiKey: 'test-key' };

      const result = await evaluateWithAI(findings, {}, aiConfig);
      expect(result.evaluations).toHaveLength(1);
      expect(result.evaluations[0].verdict).toBe('needs-review');

      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[0]).toContain('generativelanguage.googleapis.com');
    });

    it('should handle API errors gracefully with needs-review fallback', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: { content: 'This is not valid JSON at all' },
          }],
          model: 'gpt-4o-mini',
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };

      const result = await evaluateWithAI(findings, {}, aiConfig);
      expect(result.evaluations).toHaveLength(1);
      expect(result.evaluations[0].verdict).toBe('needs-review');
      expect(result.evaluations[0].reasoning).toContain('could not be parsed');
    });

    it('should handle HTTP error from API', async () => {
      const mockResponse = {
        ok: false,
        status: 401,
        text: async () => 'Unauthorized',
      };
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'bad-key' };

      await expect(evaluateWithAI(findings, {}, aiConfig)).rejects.toThrow('OpenAI API error (401)');
    });

    it('should handle markdown-wrapped JSON in AI response', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: '```json\n[{\"findingId\":\"MCPS-001\",\"verdict\":\"confirmed\",\"confidence\":0.85,\"reasoning\":\"Real risk\"}]\n```',
            },
          }],
          model: 'gpt-4o-mini',
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };

      const result = await evaluateWithAI(findings, {}, aiConfig);
      expect(result.evaluations).toHaveLength(1);
      expect(result.evaluations[0].verdict).toBe('confirmed');
    });

    it('should batch large finding sets', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify(
                Array.from({ length: 20 }, (_, i) => ({
                  findingId: `MCPS-${String(i + 1).padStart(3, '0')}`,
                  verdict: 'confirmed',
                  confidence: 0.8,
                  reasoning: 'Test',
                }))
              ),
            },
          }],
          model: 'gpt-4o-mini',
          usage: { prompt_tokens: 100, completion_tokens: 50 },
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      // 25 findings should produce 2 batches (20 + 5)
      const findings = Array.from({ length: 25 }, (_, i) =>
        makeFinding(`MCPS-${String(i + 1).padStart(3, '0')}`, `Finding ${i + 1}`)
      );
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };

      const result = await evaluateWithAI(findings, {}, aiConfig);
      expect(global.fetch).toHaveBeenCalledTimes(2);
      expect(result.evaluations.length).toBeGreaterThan(0);
    });

    it('should use custom base URL for OpenAI-compatible providers', async () => {
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify([
                { findingId: 'MCPS-001', verdict: 'confirmed', confidence: 0.9, reasoning: 'Test' },
              ]),
            },
          }],
          model: 'llama-3',
        }),
      });
      global.fetch = vi.fn().mockResolvedValue(mockResponse);

      const findings = [makeFinding('MCPS-001', 'Test')];
      const aiConfig: AIConfig = {
        provider: 'openai',
        apiKey: 'test-key',
        model: 'llama-3',
        baseUrl: 'http://localhost:11434/v1',
      };

      await evaluateWithAI(findings, {}, aiConfig);
      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[0]).toBe('http://localhost:11434/v1/chat/completions');
    });

    it('should sanitize env var values (only send keys, not values)', async () => {
      let capturedBody = '';
      const mockResponse = withText({
        ok: true,
        json: async () => ({
          choices: [{
            message: {
              content: JSON.stringify([
                { findingId: 'MCPS-001', verdict: 'confirmed', confidence: 0.9, reasoning: 'Test' },
              ]),
            },
          }],
          model: 'gpt-4o-mini',
        }),
      });
      global.fetch = vi.fn().mockImplementation((_url: string, opts: any) => {
        capturedBody = opts.body;
        return Promise.resolve(mockResponse);
      });

      const findings = [makeFinding('MCPS-001', 'Test')];
      const configs: Record<string, MCPServerConfig> = {
        'test-server': {
          command: 'npx',
          env: { SECRET_KEY: 'super-secret-value-12345' },
        },
      };
      const aiConfig: AIConfig = { provider: 'openai', apiKey: 'test-key' };

      await evaluateWithAI(findings, configs, aiConfig);
      // Verify that the actual secret value is NOT sent to the AI
      expect(capturedBody).not.toContain('super-secret-value-12345');
      // But the key name should be present
      expect(capturedBody).toContain('SECRET_KEY');
    });
  });

  describe('resolveAIConfig', () => {
    const envBackup: Record<string, string | undefined> = {};

    beforeEach(() => {
      envBackup.MCPSHIELD_AI_PROVIDER = process.env.MCPSHIELD_AI_PROVIDER;
      envBackup.MCPSHIELD_OPENAI_API_KEY = process.env.MCPSHIELD_OPENAI_API_KEY;
      envBackup.OPENAI_API_KEY = process.env.OPENAI_API_KEY;
      envBackup.MCPSHIELD_ANTHROPIC_API_KEY = process.env.MCPSHIELD_ANTHROPIC_API_KEY;
      envBackup.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
      envBackup.MCPSHIELD_GEMINI_API_KEY = process.env.MCPSHIELD_GEMINI_API_KEY;
      envBackup.GEMINI_API_KEY = process.env.GEMINI_API_KEY;
      envBackup.GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
      envBackup.MCPSHIELD_AI_BASE_URL = process.env.MCPSHIELD_AI_BASE_URL;
      envBackup.MCPSHIELD_AI_MODEL = process.env.MCPSHIELD_AI_MODEL;

      // Clear all env vars
      delete process.env.MCPSHIELD_AI_PROVIDER;
      delete process.env.MCPSHIELD_OPENAI_API_KEY;
      delete process.env.OPENAI_API_KEY;
      delete process.env.MCPSHIELD_ANTHROPIC_API_KEY;
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.MCPSHIELD_GEMINI_API_KEY;
      delete process.env.GEMINI_API_KEY;
      delete process.env.GOOGLE_API_KEY;
      delete process.env.MCPSHIELD_AI_BASE_URL;
      delete process.env.MCPSHIELD_AI_MODEL;
    });

    afterEach(() => {
      for (const [key, value] of Object.entries(envBackup)) {
        if (value === undefined) {
          delete process.env[key];
        } else {
          process.env[key] = value;
        }
      }
    });

    it('should return null when no provider specified', () => {
      const result = resolveAIConfig({});
      expect(result).toBeNull();
    });

    it('should resolve OpenAI config from env', () => {
      process.env.OPENAI_API_KEY = 'sk-test-key';
      const result = resolveAIConfig({ provider: 'openai' });
      expect(result).not.toBeNull();
      expect(result!.provider).toBe('openai');
      expect(result!.apiKey).toBe('sk-test-key');
      expect(result!.model).toBe('gpt-4o-mini');
    });

    it('should prefer MCPSHIELD-prefixed env vars', () => {
      process.env.OPENAI_API_KEY = 'generic-key';
      process.env.MCPSHIELD_OPENAI_API_KEY = 'mcpshield-key';
      const result = resolveAIConfig({ provider: 'openai' });
      expect(result!.apiKey).toBe('mcpshield-key');
    });

    it('should resolve Anthropic config', () => {
      process.env.ANTHROPIC_API_KEY = 'sk-ant-test';
      const result = resolveAIConfig({ provider: 'anthropic' });
      expect(result!.provider).toBe('anthropic');
      expect(result!.apiKey).toBe('sk-ant-test');
    });

    it('should resolve Gemini config from multiple env vars', () => {
      process.env.GOOGLE_API_KEY = 'google-key';
      const result = resolveAIConfig({ provider: 'gemini' });
      expect(result!.provider).toBe('gemini');
      expect(result!.apiKey).toBe('google-key');
    });

    it('should throw on missing API key', () => {
      expect(() => resolveAIConfig({ provider: 'openai' })).toThrow('No API key found');
    });

    it('should throw on invalid provider', () => {
      expect(() => resolveAIConfig({ provider: 'invalid' })).toThrow('Invalid AI provider');
    });

    it('should accept model override', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      const result = resolveAIConfig({ provider: 'openai', model: 'gpt-4o' });
      expect(result!.model).toBe('gpt-4o');
    });

    it('should accept base URL override', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      const result = resolveAIConfig({ provider: 'openai', baseUrl: 'http://localhost:11434/v1' });
      expect(result!.baseUrl).toBe('http://localhost:11434/v1');
    });

    it('should read provider from env var fallback', () => {
      process.env.MCPSHIELD_AI_PROVIDER = 'openai';
      process.env.OPENAI_API_KEY = 'sk-test';
      const result = resolveAIConfig({});
      expect(result!.provider).toBe('openai');
    });

    it('should read base URL from env var', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      process.env.MCPSHIELD_AI_BASE_URL = 'http://custom:8080/v1';
      const result = resolveAIConfig({ provider: 'openai' });
      expect(result!.baseUrl).toBe('http://custom:8080/v1');
    });

    it('should read model from MCPSHIELD_AI_MODEL env var', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      process.env.MCPSHIELD_AI_MODEL = 'gpt-4o';
      const result = resolveAIConfig({ provider: 'openai' });
      expect(result!.model).toBe('gpt-4o');
    });

    it('should prefer explicit model option over MCPSHIELD_AI_MODEL env var', () => {
      process.env.OPENAI_API_KEY = 'sk-test';
      process.env.MCPSHIELD_AI_MODEL = 'gpt-4o';
      const result = resolveAIConfig({ provider: 'openai', model: 'gpt-4-turbo' });
      expect(result!.model).toBe('gpt-4-turbo');
    });
  });

  describe('createProvider', () => {
    it('should create an OpenAI provider', () => {
      const provider = createProvider({ provider: 'openai', apiKey: 'test' });
      expect(provider.name).toBe('openai');
      expect(typeof provider.chat).toBe('function');
    });

    it('should create an Anthropic provider', () => {
      const provider = createProvider({ provider: 'anthropic', apiKey: 'test' });
      expect(provider.name).toBe('anthropic');
    });

    it('should create a Gemini provider', () => {
      const provider = createProvider({ provider: 'gemini', apiKey: 'test' });
      expect(provider.name).toBe('gemini');
    });

    it('should throw on unsupported provider', () => {
      expect(() => createProvider({ provider: 'invalid' as any, apiKey: 'test' })).toThrow('Unsupported AI provider');
    });
  });
});
