import { AIConfig, AIProviderType } from '../types/index.js';

export interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface AIResponse {
  content: string;
  model: string;
  usage?: { promptTokens: number; completionTokens: number };
}

export interface AIProvider {
  name: AIProviderType;
  chat(messages: AIMessage[]): Promise<AIResponse>;
}

const DEFAULT_MODELS: Record<AIProviderType, string> = {
  openai: 'gpt-4o-mini',
  anthropic: 'claude-sonnet-4-20250514',
  gemini: 'gemini-2.0-flash',
};

export function createProvider(config: AIConfig): AIProvider {
  switch (config.provider) {
    case 'openai':
      return createOpenAIProvider(config);
    case 'anthropic':
      return createAnthropicProvider(config);
    case 'gemini':
      return createGeminiProvider(config);
    default:
      throw new Error(`Unsupported AI provider: ${config.provider}`);
  }
}

export function resolveAIConfig(opts: {
  provider?: string;
  model?: string;
  baseUrl?: string;
}): AIConfig | null {
  const provider = (opts.provider || process.env.MCPSHIELD_AI_PROVIDER || '') as AIProviderType;
  if (!provider) return null;

  const validProviders: AIProviderType[] = ['openai', 'anthropic', 'gemini'];
  if (!validProviders.includes(provider)) {
    throw new Error(`Invalid AI provider "${provider}". Supported: ${validProviders.join(', ')}`);
  }

  const envKeyMap: Record<AIProviderType, string[]> = {
    openai: ['MCPSHIELD_OPENAI_API_KEY', 'OPENAI_API_KEY'],
    anthropic: ['MCPSHIELD_ANTHROPIC_API_KEY', 'ANTHROPIC_API_KEY'],
    gemini: ['MCPSHIELD_GEMINI_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY'],
  };

  const envKeys = envKeyMap[provider] || [];
  const apiKey = envKeys.reduce(
    (found, key) => found || process.env[key] || '', ''
  );

  if (!apiKey) {
    throw new Error(
      `No API key found for provider "${provider}". ` +
      `Set one of: ${envKeys.join(', ')}`
    );
  }

  return {
    provider,
    apiKey,
    model: opts.model || process.env.MCPSHIELD_AI_MODEL || DEFAULT_MODELS[provider],
    baseUrl: opts.baseUrl || process.env.MCPSHIELD_AI_BASE_URL,
  };
}

// --- OpenAI-compatible provider (also works with Groq, Together, Ollama, etc.) ---

function createOpenAIProvider(config: AIConfig): AIProvider {
  const baseUrl = config.baseUrl || 'https://api.openai.com/v1';
  const model = config.model || DEFAULT_MODELS.openai;

  return {
    name: 'openai',
    async chat(messages: AIMessage[]): Promise<AIResponse> {
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: messages.map(m => ({ role: m.role, content: m.content })),
          temperature: 0.1,
          max_tokens: 4096,
        }),
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`OpenAI API error (${response.status}): ${body}`);
      }

      const data = await response.json() as any;
      return {
        content: data.choices?.[0]?.message?.content || '',
        model: data.model || model,
        usage: data.usage ? {
          promptTokens: data.usage.prompt_tokens,
          completionTokens: data.usage.completion_tokens,
        } : undefined,
      };
    },
  };
}

// --- Anthropic Claude provider ---

function createAnthropicProvider(config: AIConfig): AIProvider {
  const model = config.model || DEFAULT_MODELS.anthropic;

  return {
    name: 'anthropic',
    async chat(messages: AIMessage[]): Promise<AIResponse> {
      const systemMsg = messages.find(m => m.role === 'system');
      const nonSystemMsgs = messages.filter(m => m.role !== 'system');

      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': config.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          ...(systemMsg ? { system: systemMsg.content } : {}),
          messages: nonSystemMsgs.map(m => ({ role: m.role, content: m.content })),
        }),
      });

      if (!response.ok) {
        const body = await response.text();
        throw new Error(`Anthropic API error (${response.status}): ${body}`);
      }

      const data = await response.json() as any;
      const textBlock = data.content?.find((b: any) => b.type === 'text');
      return {
        content: textBlock?.text || '',
        model: data.model || model,
        usage: data.usage ? {
          promptTokens: data.usage.input_tokens,
          completionTokens: data.usage.output_tokens,
        } : undefined,
      };
    },
  };
}

// --- Google Gemini provider ---

function createGeminiProvider(config: AIConfig): AIProvider {
  const model = config.model || DEFAULT_MODELS.gemini;

  return {
    name: 'gemini',
    async chat(messages: AIMessage[]): Promise<AIResponse> {
      const systemMsg = messages.find(m => m.role === 'system');
      const nonSystemMsgs = messages.filter(m => m.role !== 'system');

      const contents = nonSystemMsgs.map(m => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

      const body: any = { contents };
      if (systemMsg) {
        body.systemInstruction = { parts: [{ text: systemMsg.content }] };
      }
      body.generationConfig = { temperature: 0.1, maxOutputTokens: 4096 };

      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${config.apiKey}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!response.ok) {
        const errBody = await response.text();
        throw new Error(`Gemini API error (${response.status}): ${errBody}`);
      }

      const data = await response.json() as any;
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      return {
        content: text,
        model,
        usage: data.usageMetadata ? {
          promptTokens: data.usageMetadata.promptTokenCount || 0,
          completionTokens: data.usageMetadata.candidatesTokenCount || 0,
        } : undefined,
      };
    },
  };
}
