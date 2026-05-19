# Claude Code Usage Advisor

[![Node.js 18+](https://img.shields.io/badge/node-%3E%3D18-339933)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)

Stop guessing which Claude Code model and settings to use.

Claude Code Usage Advisor analyzes your local Claude Code history and recommends practical launch profiles for `sonnet`, `opusplan`, `opus[1m]`, `haiku`, effort level, permission mode, sandboxing, and prompt caching.

It is read-only, zero-dependency, and runs locally against `~/.claude`.

## Install

Run without installing:

```bash
npx claude-code-usage-advisor
```

Or install globally:

```bash
npm install -g claude-code-usage-advisor
cc-advisor
```

From a clone:

```bash
git clone https://github.com/LZong-tw/claude-code-usage-advisor.git
cd claude-code-usage-advisor
npm test
node bin/claude-code-usage-advisor.js
```

## What It Answers

- Which model should be your default for daily Claude Code work?
- When should you use `sonnet`, `opusplan`, `opus[1m]`, `haiku`, or fast mode?
- Should `effortLevel` be global or task-specific?
- Is `permissions.defaultMode` appropriate for your actual usage?
- Are risky allow rules accumulating in `settings.json`?
- Should you configure `autoMode.environment`, sandboxing, prompt caching, or subprocess env scrubbing?
- Which launch profiles should you use for planning, implementation, autonomous work, and cheap triage?
- Where are tool errors, hooks, status lines, project hotspots, MCP calls, or global context creating friction?

## Usage

```bash
cc-advisor
cc-advisor --days 7
cc-advisor --json
cc-advisor --html reports/claude-code-insights.html
cc-advisor --no-snippets
cc-advisor --claude-dir ~/.claude
cc-advisor --max-files 100
```

Without installing:

```bash
npx claude-code-usage-advisor --days 7
```

Options:

```text
--claude-dir <path>   Claude Code directory (default: ~/.claude)
--days <n>            Analyze JSONL records from the last n days (default: 30, 0 = all)
--max-files <n>       Cap scanned JSONL files, newest first (default: unlimited)
--json                Print machine-readable JSON
--html <path>         Write a self-contained HTML report
--no-snippets         Hide settings snippets in text output
--help                Show help
```

## Example Output

```text
Recommended launch profiles
---------------------------
- Daily implementation: `claude --model sonnet --permission-mode acceptEdits`
  Normal code edits, tests, refactors with a clear target.
- Deep planning then execution: `claude --model opusplan --permission-mode plan`
  Ambiguous architecture, incident diagnosis, large refactors, migrations.
- Trusted autonomous work: `claude --model sonnet --permission-mode auto`
  Only after `autoMode.environment`, risky permissions, and sandboxing are configured.
```

The text report also includes evidence-backed recommendations and settings snippets. The JSON report includes the same data for dashboards or automation.

The `Additional investigations` section flags workflow and local-environment issues such as high tool error rates, hook/status-line overhead, allowlist drift, oversized global `CLAUDE.md`, MCP-heavy sessions, and subagent usage patterns.

## Data Sources

The tool reads local files only:

- `~/.claude/settings.json`
- `~/.claude/stats-cache.json`
- `~/.claude/projects/**/*.jsonl`

It does not call Anthropic APIs, GitHub APIs, or any network service. It does not modify your settings.

## How Recommendations Work

The advisor combines:

- Lifetime model token totals from `stats-cache.json`
- Recent model/tool/permission mode patterns from JSONL transcripts
- Risk classification for current `permissions.allow` rules
- Heuristics from Claude Code's current model and settings behavior

Core routing policy:

- `sonnet`: daily implementation, tests, straightforward refactors
- `opusplan`: ambiguous planning, architecture, migrations, high-stakes debugging
- `opus[1m]`: large-context planning when your account supports it
- `haiku`: summaries, classification, cheap triage
- fast mode: explicit, urgent Opus sessions only, not a global default

## Privacy

This tool is designed for public use on private machines:

- No telemetry
- No dependency install scripts
- No external network calls
- No settings writes
- No transcript content is printed by default, only aggregate counts and command families

The JSON output may include project paths, command families, model names, tool names, and settings keys. Review it before sharing publicly.

## Development

```bash
npm test
npm run smoke
```

No build step is required.

## License

MIT
