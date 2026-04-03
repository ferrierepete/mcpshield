import { ScanResult, Finding, Severity } from '../types/index.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  artifacts: SarifArtifact[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fixes?: SarifFix[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId?: string };
  };
  message?: { text: string };
}

interface SarifArtifact {
  location: { uri: string };
}

interface SarifFix {
  description: { text: string };
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function toSarif(result: ScanResult, version: string = '0.1.0'): SarifLog {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIndexMap = new Map<string, number>();

  for (const server of result.servers) {
    for (const finding of server.findings) {
      // Create rule if not already present
      const ruleKey = `${finding.category}/${finding.title}`;
      if (!ruleIndexMap.has(ruleKey)) {
        ruleIndexMap.set(ruleKey, rules.length);
        rules.push({
          id: finding.id,
          name: finding.title.replace(/\s+/g, ''),
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          defaultConfiguration: { level: SEVERITY_TO_SARIF_LEVEL[finding.severity] },
          ...(finding.references?.length ? { helpUri: finding.references[0] } : {}),
        });
      }

      results.push({
        ruleId: finding.id,
        ruleIndex: ruleIndexMap.get(ruleKey)!,
        level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
        message: {
          text: `[${server.name}] ${finding.description}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: result.target },
            },
            message: { text: `Server: ${server.name}` },
          },
        ],
        fixes: finding.remediation
          ? [{ description: { text: finding.remediation } }]
          : undefined,
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'MCPShield',
            version,
            informationUri: 'https://github.com/ferrierepete/mcpshield',
            rules,
          },
        },
        results,
        artifacts: [{ location: { uri: result.target } }],
      },
    ],
  };
}
