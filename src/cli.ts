#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { autoDetectConfig, discoverConfigs, loadConfig, resolveSafeConfigPath } from './scanners/config-loader.js';
import { scanAllServers, scanAllServersWithRegistry } from './scanners/index.js';
import { severityIcon } from './utils/helpers.js';
import { ScanResult, OWASP_MCP_TOP_CATEGORIES, Severity } from './types/index.js';
import { toSarif } from './formatters/sarif.js';
import { loadMCPShieldConfig, severityMeetsThreshold } from './config/index.js';
import { applyFixes, writeConfig } from './fix/index.js';
import * as fs from 'fs';
import { watch } from 'fs';
import { resolveAIConfig, evaluateWithAI, applyAIEvaluations, filterByConfidence } from './ai/index.js';

const VERSION = '0.2.2';

const program = new Command();

program
  .name('mcpshield')
  .description('🔒 Security scanner for MCP (Model Context Protocol) servers')
  .version(VERSION);

program
  .command('scan')
  .description('Scan MCP server configurations for security issues')
  .option('-c, --config <path>', 'Path to MCP config file')
  .option('-f, --format <fmt>', 'Output format: pretty, json, markdown, sarif', 'pretty')
  .option('--no-spinner', 'Disable progress spinner')
  .option('-r, --registry', 'Enable remote registry checks (npm/PyPI) for supply chain verification')
  .option('-s, --severity <level>', 'Minimum severity threshold to display: critical, high, medium, low, info')
  .option('-i, --ignore <ids...>', 'Finding IDs or titles to ignore (space-separated)')
  .option('-q, --quiet', 'Only print the summary line and findings count (no per-server details)')
  .option('--ai', 'Enable AI-based false positive reduction (requires API key)')
  .option('--ai-provider <provider>', 'AI provider: openai, anthropic, gemini')
  .option('--ai-model <model>', 'AI model to use (overrides default)')
  .option('--ai-base-url <url>', 'Custom base URL for OpenAI-compatible endpoints')
  .option('--min-confidence <n>', 'Minimum confidence threshold (0.0–1.0) to display findings', parseFloat)
  .action(async (opts) => {
    // Load MCPShield's own config (.mcpshieldrc)
    const shieldConfig = loadMCPShieldConfig();

    // CLI flags override .mcpshieldrc defaults
    const format = opts.format || shieldConfig.format || 'pretty';
    const useRegistry = opts.registry || shieldConfig.registry || false;
    const severityThreshold: Severity = opts.severity || shieldConfig.severityThreshold || 'info';
    const ignoreList: string[] = [...(opts.ignore || []), ...(shieldConfig.ignore || [])];

    // Load config
    let config;
    let configPath: string;

    if (opts.config) {
      const safePath = resolveSafeConfigPath(opts.config);
      if (!safePath) {
        console.error(chalk.red(`Error: Config path "${opts.config}" is outside allowed directories (cwd and home). Refusing to load.`));
        process.exit(1);
      }
      try {
        config = loadConfig(safePath);
        configPath = safePath;
      } catch (e: any) {
        console.error(chalk.red(`Error: Cannot load config from ${opts.config}: ${e.message}`));
        process.exit(1);
      }
    } else {
      const auto = autoDetectConfig(true);
      if (!auto) {
        console.error(chalk.red('Error: No MCP configuration found.'));
        console.error(chalk.dim('Searched: Claude Desktop, VS Code, Cursor, .mcp/ directories'));
        console.error(chalk.dim('Use --config to specify a path, or set MCP_CONFIG_PATH env var.'));
        process.exit(1);
      }
      config = auto.config;
      configPath = auto.path;
    }

    const serverCount = Object.keys(config.mcpServers).length;
    if (serverCount === 0) {
      console.log(chalk.yellow('No MCP servers found in configuration.'));
      process.exit(0);
    }

    // Run scan
    const spinner = opts.spinner !== false
      ? ora(`Scanning ${serverCount} MCP server(s)${useRegistry ? ' (with registry checks)' : ''}...`).start()
      : null;

    const result = useRegistry
      ? await scanAllServersWithRegistry(config.mcpServers, configPath)
      : scanAllServers(config.mcpServers, configPath);

    if (spinner) spinner.stop();

    // AI evaluation (opt-in)
    const useAI = opts.ai || shieldConfig.ai || false;
    if (useAI) {
      const aiSpinner = opts.spinner !== false ? ora('Evaluating findings with AI...').start() : null;
      try {
        const aiConfig = resolveAIConfig({
          provider: opts.aiProvider || shieldConfig.aiProvider,
          model: opts.aiModel || shieldConfig.aiModel,
          baseUrl: opts.aiBaseUrl || shieldConfig.aiBaseUrl,
        });
        if (aiConfig) {
          const allFindings = result.servers.flatMap(s => s.findings);
          const aiResult = await evaluateWithAI(allFindings, config.mcpServers, aiConfig);
          // Apply AI verdicts back to findings
          for (const server of result.servers) {
            server.findings = applyAIEvaluations(server.findings, aiResult.evaluations);
          }
          if (aiSpinner) {
            if (aiResult.parseErrorCount > 0) {
              aiSpinner.warn(
                `AI evaluation complete (${aiResult.model}, ${aiResult.evaluations.length} evaluated, ` +
                `${aiResult.parseErrorCount} response(s) could not be parsed — see findings marked [AI: needs review])`
              );
            } else {
              aiSpinner.succeed(
                `AI evaluation complete (${aiResult.model}, ${aiResult.evaluations.length} findings evaluated)`
              );
            }
          }
        }
      } catch (e: any) {
        if (aiSpinner) aiSpinner.fail(`AI evaluation failed: ${e.message}`);
      }
    }

    // Apply confidence threshold filter
    const minConfidence = opts.minConfidence ?? shieldConfig.minConfidence;
    if (minConfidence !== undefined && minConfidence > 0) {
      const totalBefore = result.servers.flatMap(s => s.findings).length;
      for (const server of result.servers) {
        server.findings = filterByConfidence(server.findings, minConfidence);
      }
      const totalAfter = result.servers.flatMap(s => s.findings).length;
      if (totalAfter === 0 && totalBefore > 0) {
        console.warn(chalk.yellow(
          `[mcpshield] --min-confidence ${minConfidence} filtered all ${totalBefore} finding(s). ` +
          `No findings will be displayed.`
        ));
      }
    }

    // Apply severity threshold and ignore filters
    const filtered = applyFilters(result, severityThreshold, ignoreList);

    // Output results
    if (format === 'json') {
      console.log(JSON.stringify(filtered, null, 2));
    } else if (format === 'markdown') {
      printMarkdown(filtered);
    } else if (format === 'sarif') {
      console.log(JSON.stringify(toSarif(filtered, VERSION), null, 2));
    } else if (opts.quiet) {
      printQuiet(filtered);
    } else {
      printPretty(configPath, filtered);
    }

    // Exit code based on severity (use unfiltered result for exit codes)
    if (result.summary.critical > 0) process.exit(2);
    if (result.summary.high > 0) process.exit(1);
  });

program
  .command('list')
  .description('List discovered MCP configuration files')
  .action(() => {
    const configs = discoverConfigs();
    if (configs.length === 0) {
      console.log(chalk.yellow('No MCP configuration files found.'));
      return;
    }
    console.log(chalk.bold('MCP Configuration Files Found:\n'));
    for (const p of configs) {
      console.log(`  ${chalk.green('●')} ${p}`);
    }
  });

program
  .command('owasp')
  .description('Show OWASP MCP Top 10 security framework reference')
  .action(() => {
    console.log(chalk.bold.cyan('\n🛡️  OWASP MCP Top 10 Security Framework\n'));
    console.log(chalk.dim('Reference: https://owasp.org/www-project-mcp-top-10/\n'));
    for (const cat of OWASP_MCP_TOP_CATEGORIES) {
      console.log(`  ${chalk.yellow('▸')} ${cat}`);
    }
    console.log();
  });

program
  .command('fix')
  .description('Auto-fix common security issues in MCP config')
  .option('-c, --config <path>', 'Path to MCP config file')
  .option('--dry-run', 'Show what would be fixed without writing changes')
  .action(async (opts) => {
    let config;
    let configPath: string;

    if (opts.config) {
      const safePath = resolveSafeConfigPath(opts.config);
      if (!safePath) {
        console.error(chalk.red(`Error: Config path "${opts.config}" is outside allowed directories (cwd and home). Refusing to load.`));
        process.exit(1);
      }
      try {
        config = loadConfig(safePath);
        configPath = safePath;
      } catch (e: any) {
        console.error(chalk.red(`Error: Cannot load config from ${opts.config}: ${e.message}`));
        process.exit(1);
      }
    } else {
      const auto = autoDetectConfig(true);
      if (!auto) {
        console.error(chalk.red('Error: No MCP configuration found.'));
        process.exit(1);
      }
      config = auto.config;
      configPath = auto.path;
    }

    // Scan first
    const result = scanAllServers(config.mcpServers, configPath);
    const allFindings = result.servers.flatMap(s => s.findings);
    console.log(chalk.bold.cyan('\n🔧 MCPShield Auto-Fix\n'));
    console.log(chalk.dim(`Config: ${configPath}\n`));

    const { config: fixedConfig, result: fixResult } = applyFixes(config, allFindings);

    for (const applied of fixResult.applied) {
      console.log(`  ${chalk.green('✓')} ${applied}`);
    }
    for (const skipped of fixResult.skipped) {
      console.log(`  ${chalk.yellow('⊘')} ${skipped}`);
    }

    if (opts.dryRun) {
      console.log(chalk.dim('\n(Dry run — no changes written)'));
      if (fixResult.applied.length > 0 || fixResult.skipped.length > 0) {
        console.log(chalk.dim('\nFixed config preview:'));
        console.log(JSON.stringify(fixedConfig, null, 2));
      } else {
        console.log(chalk.green('✅ No auto-fixable issues found.'));
      }
    } else if (fixResult.applied.length > 0) {
      writeConfig(configPath, fixedConfig);
      console.log(chalk.green(`\n✅ Applied ${fixResult.applied.length} fix(es) to ${configPath}`));
      console.log(chalk.dim(`   Backup saved to: ${configPath}.bak`));
    } else {
      console.log(chalk.green('\n✅ No auto-fixable issues found.\n'));
    }
    console.log();
  });

program
  .command('watch')
  .description('Watch MCP config file for changes and re-scan automatically')
  .option('-c, --config <path>', 'Path to MCP config file')
  .option('-f, --format <fmt>', 'Output format: pretty, json, markdown, sarif', 'pretty')
  .action(async (opts) => {
    let configPath: string;

    if (opts.config) {
      const safePath = resolveSafeConfigPath(opts.config);
      if (!safePath) {
        console.error(chalk.red(`Error: Config path "${opts.config}" is outside allowed directories (cwd and home). Refusing to load.`));
        process.exit(1);
      }
      configPath = safePath;
    } else {
      const auto = autoDetectConfig(true);
      if (!auto) {
        console.error(chalk.red('Error: No MCP configuration found.'));
        process.exit(1);
      }
      configPath = auto.path;
    }

    console.log(chalk.bold.cyan('\n👁️  MCPShield Watch Mode'));
    console.log(chalk.dim(`Watching: ${configPath}\n`));
    console.log(chalk.dim('Press Ctrl+C to stop.\n'));

    // Validate file exists before entering watch mode
    if (!fs.existsSync(configPath)) {
      console.error(chalk.red(`Error: Config file not found: ${configPath}`));
      process.exit(1);
    }

    runWatchScan(configPath, opts.format);

    // Watch for changes
    let debounceTimer: ReturnType<typeof setTimeout> | null = null;
    watch(configPath, () => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        console.log(chalk.dim(`\n--- Config changed at ${new Date().toLocaleTimeString()} ---\n`));
        runWatchScan(configPath, opts.format);
      }, 500);
    });
  });

function printQuiet(result: ScanResult): void {
  const s = result.summary;
  const parts = [
    s.critical ? `${s.critical} critical` : null,
    s.high ? `${s.high} high` : null,
    s.medium ? `${s.medium} medium` : null,
    s.low ? `${s.low} low` : null,
    s.info ? `${s.info} info` : null,
  ].filter(Boolean);
  const scoreLabel = s.score >= 80 ? '✅' : s.score >= 60 ? '⚠️' : '🔴';
  const summary = parts.length ? parts.join(', ') : 'no findings';
  console.log(`${scoreLabel} Score: ${s.score}/100 — ${summary} (${result.servers.length} server(s) scanned)`);
}

function applyFilters(result: ScanResult, threshold: Severity, ignoreList: string[]): ScanResult {
  const ignoreLower = ignoreList.map(i => i.toLowerCase());

  const filteredServers = result.servers.map(server => {
    const filteredFindings = server.findings.filter(f => {
      if (!severityMeetsThreshold(f.severity, threshold)) return false;
      // Partial substring match: ignore value appears anywhere in ID or title
      const idLower = f.id.toLowerCase();
      const titleLower = f.title.toLowerCase();
      if (ignoreLower.some(ig => idLower.includes(ig) || titleLower.includes(ig))) return false;
      return true;
    });
    return { ...server, findings: filteredFindings };
  });

  const allFiltered = filteredServers.flatMap(s => s.findings);
  return {
    ...result,
    servers: filteredServers,
    summary: {
      total: allFiltered.length,
      critical: allFiltered.filter(f => f.severity === 'critical').length,
      high: allFiltered.filter(f => f.severity === 'high').length,
      medium: allFiltered.filter(f => f.severity === 'medium').length,
      low: allFiltered.filter(f => f.severity === 'low').length,
      info: allFiltered.filter(f => f.severity === 'info').length,
      score: result.summary.score, // Keep original score
    },
  };
}

function printPretty(configPath: string, result: ScanResult) {
  console.log();
  console.log(chalk.bold.cyan('🔒 MCPShield Security Report'));
  console.log(chalk.dim('─'.repeat(50)));
  console.log(`${chalk.dim('Config:')} ${configPath}`);
  console.log(`${chalk.dim('Date:')}  ${new Date(result.timestamp).toLocaleString()}`);
  console.log();

  // Summary
  const scoreStr = result.summary.score >= 80
    ? chalk.green.bold(`${result.summary.score}/100`)
    : result.summary.score >= 60
      ? chalk.yellow.bold(`${result.summary.score}/100`)
      : chalk.red.bold(`${result.summary.score}/100`);

  console.log(chalk.bold('Security Score: ') + scoreStr);
  console.log();

  const summaryLine = [
    result.summary.critical ? chalk.red(`${result.summary.critical} critical`) : null,
    result.summary.high ? chalk.hex('#FF6600')(`${result.summary.high} high`) : null,
    result.summary.medium ? chalk.yellow(`${result.summary.medium} medium`) : null,
    result.summary.low ? chalk.blue(`${result.summary.low} low`) : null,
    result.summary.info ? chalk.gray(`${result.summary.info} info`) : null,
  ].filter(Boolean).join('  ');

  console.log(`Findings: ${summaryLine || chalk.green('None')}`);
  console.log(chalk.dim('─'.repeat(50)));

  // Per-server results
  for (const server of result.servers) {
    const serverScoreColor = server.score >= 80 ? chalk.green : server.score >= 60 ? chalk.yellow : chalk.red;
    console.log();
    console.log(chalk.bold(`📦 ${server.name}`) + serverScoreColor(` [${server.score}/100]`));
    console.log(chalk.dim(`   Command: ${server.command} ${(server.findings.length === 0 ? '(no findings)' : '')}`));

    if (server.findings.length === 0) {
      console.log(chalk.green('   ✅ No security issues found'));
      continue;
    }

    for (const f of server.findings) {
      console.log();
      const confidenceStr = f.confidence !== undefined
        ? ` ${chalk.dim(`(confidence: ${Math.round(f.confidence * 100)}%)`)}`
        : '';
      const verdictStr = f.aiVerdict
        ? f.aiVerdict === 'confirmed' ? chalk.red(' [AI: confirmed]')
          : f.aiVerdict === 'likely-false-positive' ? chalk.yellow(' [AI: likely FP]')
          : chalk.gray(' [AI: needs review]')
        : '';
      console.log(`   ${severityIcon(f.severity)} ${chalk.bold(f.title)} ${chalk.dim(`[${f.id}]`)}${confidenceStr}${verdictStr}`);
      console.log(`   ${chalk.dim(f.description)}`);
      console.log(`   ${chalk.cyan('→ Fix:')} ${f.remediation}`);
      if (f.references?.length) {
        console.log(`   ${chalk.dim('Refs:')} ${f.references.join(', ')}`);
      }
    }
  }

  console.log();
  console.log(chalk.dim('─'.repeat(50)));
  console.log(chalk.dim(`Scanned ${result.servers.length} server(s) • MCPShield v${VERSION}`));
  console.log();
}

function printMarkdown(result: ScanResult) {
  console.log(`# 🔒 MCPShield Security Report\n`);
  console.log(`**Config:** \`${result.target}\``);
  console.log(`**Date:** ${result.timestamp}`);
  console.log(`**Score:** ${result.summary.score}/100\n`);
  console.log(`| Severity | Count |`);
  console.log(`|----------|-------|`);
  console.log(`| Critical | ${result.summary.critical} |`);
  console.log(`| High | ${result.summary.high} |`);
  console.log(`| Medium | ${result.summary.medium} |`);
  console.log(`| Low | ${result.summary.low} |`);
  console.log(`| Info | ${result.summary.info} |\n`);

  for (const server of result.servers) {
    console.log(`## ${server.name} (${server.score}/100)\n`);
    if (server.findings.length === 0) {
      console.log('✅ No issues found.\n');
      continue;
    }
    for (const f of server.findings) {
      console.log(`### ${severityIcon(f.severity)} ${f.title} [${f.id}]\n`);
      console.log(`**Severity:** ${f.severity}`);
      console.log(`**Description:** ${f.description}`);
      console.log(`**Remediation:** ${f.remediation}\n`);
    }
  }
}

function runWatchScan(configPath: string, format: string): void {
  try {
    const config = loadConfig(configPath);
    const result = scanAllServers(config.mcpServers, configPath);

    if (format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else if (format === 'markdown') {
      printMarkdown(result);
    } else if (format === 'sarif') {
      console.log(JSON.stringify(toSarif(result, VERSION), null, 2));
    } else {
      printPretty(configPath, result);
    }
  } catch (e: any) {
    console.error(chalk.red(`Error scanning config: ${e.message}`));
  }
}

program.parse();
