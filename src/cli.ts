#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { autoDetectConfig, discoverConfigs, loadConfig } from './scanners/config-loader.js';
import { scanAllServers } from './scanners/index.js';
import { severityIcon, scoreColor } from './utils/helpers.js';
import { ScanResult, OWASP_MCP_TOP_CATEGORIES } from './types/index.js';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('mcpshield')
  .description('🔒 Security scanner for MCP (Model Context Protocol) servers')
  .version(VERSION);

program
  .command('scan')
  .description('Scan MCP server configurations for security issues')
  .option('-c, --config <path>', 'Path to MCP config file')
  .option('-f, --format <fmt>', 'Output format: pretty, json, markdown', 'pretty')
  .option('--no-spinner', 'Disable progress spinner')
  .action(async (opts) => {
    // Load config
    let config;
    let configPath: string;

    if (opts.config) {
      try {
        config = loadConfig(opts.config);
        configPath = opts.config;
      } catch (e: any) {
        console.error(chalk.red(`Error: Cannot load config from ${opts.config}: ${e.message}`));
        process.exit(1);
      }
    } else {
      const auto = autoDetectConfig();
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
      ? ora(`Scanning ${serverCount} MCP server(s)...`).start()
      : null;

    const result = scanAllServers(config.mcpServers, configPath);

    if (spinner) spinner.stop();

    // Output results
    if (opts.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else if (opts.format === 'markdown') {
      printMarkdown(result);
    } else {
      printPretty(configPath, result);
    }

    // Exit code based on severity
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
    console.log(chalk.dim('Reference: https://owasp.org/www-project-mcp-top/\n'));
    for (const cat of OWASP_MCP_TOP_CATEGORIES) {
      console.log(`  ${chalk.yellow('▸')} ${cat}`);
    }
    console.log();
  });

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
      console.log(`   ${severityIcon(f.severity)} ${chalk.bold(f.title)} ${chalk.dim(`[${f.id}]`)}`);
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

program.parse();
