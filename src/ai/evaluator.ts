import { Finding, MCPServerConfig, AIConfig, AIVerdict } from '../types/index.js';
import { createProvider, AIMessage } from './providers.js';

export interface AIEvaluation {
  findingId: string;
  verdict: AIVerdict;
  confidence: number;
  reasoning: string;
}

export interface AIEvaluationResult {
  evaluations: AIEvaluation[];
  model: string;
  usage?: { promptTokens: number; completionTokens: number };
}

const SYSTEM_PROMPT = `You are a security expert specializing in MCP (Model Context Protocol) server configurations. Your job is to evaluate security findings and determine whether each is a true positive or a false positive.

For each finding, respond with a JSON array of objects with these fields:
- "findingId": the finding ID (e.g. "MCP-001")
- "verdict": one of "confirmed", "likely-false-positive", or "needs-review"
- "confidence": a number from 0.0 to 1.0 indicating your confidence
- "reasoning": a brief explanation (1-2 sentences)

Rules:
- "confirmed" = this is a real security risk that should be addressed
- "likely-false-positive" = this is probably not a real risk in this context
- "needs-review" = cannot determine without more context; human should review
- Consider the server name, command, arguments, environment variables, and URL when evaluating
- A trusted package (e.g. @modelcontextprotocol/*) being unpinned is lower risk than an unknown package
- Localhost HTTP connections are generally safe
- Credentials passed as env vars to local processes may be intentional
- Docker --privileged and root filesystem mounts are almost always true positives
- eval/exec patterns and shell metacharacters are almost always true positives

Respond ONLY with a valid JSON array. No markdown, no explanation outside the JSON.`;

function buildFindingsPrompt(
  findings: Finding[],
  serverConfigs: Record<string, MCPServerConfig>
): string {
  const findingsData = findings.map(f => {
    const config = serverConfigs[f.serverName];
    return {
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      description: f.description,
      serverName: f.serverName,
      serverConfig: config ? {
        command: config.command,
        args: config.args,
        env: config.env ? Object.keys(config.env) : undefined, // only keys, not values
        url: config.url,
        disabled: config.disabled,
      } : undefined,
    };
  });

  return `Evaluate these ${findings.length} security findings from an MCP server configuration scan:\n\n${JSON.stringify(findingsData, null, 2)}`;
}

function parseAIResponse(content: string): AIEvaluation[] {
  // Try to extract JSON array from the response
  let jsonStr = content.trim();

  // Handle markdown code blocks
  const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonMatch) {
    jsonStr = jsonMatch[1].trim();
  }

  // Handle case where response starts with text before JSON
  const arrayStart = jsonStr.indexOf('[');
  const arrayEnd = jsonStr.lastIndexOf(']');
  if (arrayStart !== -1 && arrayEnd !== -1) {
    jsonStr = jsonStr.slice(arrayStart, arrayEnd + 1);
  }

  const parsed = JSON.parse(jsonStr);
  if (!Array.isArray(parsed)) {
    throw new Error('AI response is not a JSON array');
  }

  const validVerdicts: AIVerdict[] = ['confirmed', 'likely-false-positive', 'needs-review'];

  return parsed.map((item: any) => ({
    findingId: String(item.findingId || ''),
    verdict: validVerdicts.includes(item.verdict) ? item.verdict : 'needs-review',
    confidence: Math.max(0, Math.min(1, Number(item.confidence) || 0.5)),
    reasoning: String(item.reasoning || ''),
  }));
}

const MAX_FINDINGS_PER_BATCH = 20;

export async function evaluateWithAI(
  findings: Finding[],
  serverConfigs: Record<string, MCPServerConfig>,
  aiConfig: AIConfig
): Promise<AIEvaluationResult> {
  if (findings.length === 0) {
    return { evaluations: [], model: aiConfig.model || 'none' };
  }

  const provider = createProvider(aiConfig);
  const allEvaluations: AIEvaluation[] = [];
  let totalPromptTokens = 0;
  let totalCompletionTokens = 0;
  let modelUsed = '';

  // Batch findings to avoid token limits
  for (let i = 0; i < findings.length; i += MAX_FINDINGS_PER_BATCH) {
    const batch = findings.slice(i, i + MAX_FINDINGS_PER_BATCH);
    const userPrompt = buildFindingsPrompt(batch, serverConfigs);

    const messages: AIMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: userPrompt },
    ];

    const response = await provider.chat(messages);
    modelUsed = response.model;

    if (response.usage) {
      totalPromptTokens += response.usage.promptTokens;
      totalCompletionTokens += response.usage.completionTokens;
    }

    try {
      const evaluations = parseAIResponse(response.content);
      allEvaluations.push(...evaluations);
    } catch {
      // If parsing fails for a batch, mark all as needs-review
      for (const f of batch) {
        allEvaluations.push({
          findingId: f.id,
          verdict: 'needs-review',
          confidence: 0.5,
          reasoning: 'AI response could not be parsed',
        });
      }
    }
  }

  return {
    evaluations: allEvaluations,
    model: modelUsed,
    usage: totalPromptTokens > 0 ? {
      promptTokens: totalPromptTokens,
      completionTokens: totalCompletionTokens,
    } : undefined,
  };
}

export function applyAIEvaluations(
  findings: Finding[],
  evaluations: AIEvaluation[]
): Finding[] {
  const evalMap = new Map(evaluations.map(e => [e.findingId, e]));

  return findings.map(f => {
    const evaluation = evalMap.get(f.id);
    if (!evaluation) return f;

    return {
      ...f,
      confidence: evaluation.confidence,
      aiVerdict: evaluation.verdict,
    };
  });
}
