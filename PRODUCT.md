# Product

## Register

brand

## Users

Two audiences using MCPShield in different contexts:

**Solo developers** installing MCP servers into Claude Desktop, VS Code, or Cursor. They want quick confirmation that a server config is safe before running it. They're in a terminal, mid-workflow, and need fast trustworthy answers.

**Security teams in organizations** enforcing MCP policies across engineering. They integrate MCPShield into CI pipelines, review scan reports, and need clear evidence for accept/rject decisions. They're reviewing SARIF output in GitHub Security or evaluating dashboards.

Both users are technical. Both are security-conscious by nature of the problem. Neither wants to be marketed to; they want proof the tool works.

## Product Purpose

MCPShield is a security scanner for MCP (Model Context Protocol) server configurations. It detects supply chain risks, permission overreach, misconfigurations, and secrets exposure before those servers can compromise a system. It runs as a CLI tool with JSON, Markdown, and SARIF output formats.

Success looks like: a developer pastes an MCP server config, gets a clear verdict in seconds, and feels confident acting on it.

## Brand Personality

Sharp. Technical. Trustworthy.

Voice is direct and specific. No hedging, no marketing filler. The interface should feel like a well-made audit report, not a sales page. Confidence comes from precision and depth, not from decoration.

Emotional goals: confidence, clarity, control. Users should feel like they have visibility into risks they couldn't see before.

## Anti-references

- **Corporate security aesthetic**: navy backgrounds, blue gradients, shield icons, stock photos of locked padlocks. Avoid anything that looks like it could be an enterprise SOC dashboard vendor.
- **AI startup landing page**: purple gradients, floating particle effects, "powered by AI" badges, abstract neural network illustrations. The product uses AI for evaluation but does not lead with it as a differentiator.
- **Playful dev tools**: hand-drawn illustrations, rounded everything, confetti, emoji-heavy UI, mascot characters. Security is serious and the interface should reflect that gravity without being somber.

## Design Principles

1. **Earn trust through restraint.** No decorative elements. No visual hype. Trust comes from information density, precise language, and clear visual hierarchy.
2. **Show the work.** Demonstrate security expertise through specific findings, code references, and actionable severity ratings. Never make claims without evidence on screen.
3. **Terminal-native confidence.** The visual language should feel adjacent to the CLI output: monospace details, structured data, clear signal/noise separation. The web presence extends the tool's identity, not decorates it.
4. **Security is engineering.** Treat findings as engineering artifacts. Severity ratings, package versions, and config paths are the content. Structure the interface around those, not around marketing sections.

## Accessibility & Inclusion

Target WCAG 2.1 AA. High contrast is non-negotiable given the security context. Ensure severity indicators (critical, high, medium, low) are distinguishable by more than color alone. Support reduced motion for any animations.
