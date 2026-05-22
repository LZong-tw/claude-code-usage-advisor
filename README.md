# Claude Code Usage Advisor

[![Node.js 18+](https://img.shields.io/badge/node-%3E%3D18-339933)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)

Stop guessing which Claude Code model and settings to use.

Claude Code Usage Advisor analyzes your local Claude Code history and recommends practical launch profiles for Sonnet, Opus plan mode, Haiku, effort level, permission mode, sandboxing, and prompt caching.

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
- When should you use Sonnet, Opus plan mode, Haiku, or fast mode?
- Should `effortLevel` be global or task-specific?
- Is `permissions.defaultMode` appropriate for your actual usage?
- Are risky allow rules accumulating in `settings.json`?
- Should you configure `autoMode.environment`, sandboxing, prompt caching, or subprocess env scrubbing?
- Which launch profiles should you use for planning, implementation, autonomous work, and cheap triage?
- Where are tool errors, hooks, status lines, project hotspots, MCP calls, or global context creating friction?

## Usage

First run, full report against your real `~/.claude`:

```bash
npx claude-code-usage-advisor
```

That's the answer for most people. The sections below cover the rest.

### Common scenarios

**Audit only your recent shift in workflow.** Default window is 30 days; narrow when you've changed how you use Claude Code lately and want recommendations based on that, not on history.

```bash
cc-advisor --days 7
```

**Share the report with a teammate or paste into a ticket.** Produces a self-contained HTML file (no external assets) you can open in a browser or upload as an artifact.

```bash
cc-advisor --html reports/claude-code-insights.html
```

**Feed it into a dashboard or pipeline.** JSON contains the same recommendations, evidence, and investigations as the text report.

```bash
cc-advisor --json > advisor.json
jq '.recommendations[] | select(.severity=="high")' advisor.json
```

**Speed up runs on a huge `~/.claude`.** Scans newest JSONL files first.

```bash
cc-advisor --days 14 --max-files 200
```

**Point at a non-default Claude Code directory** (e.g. the macOS app data dir, or a teammate's exported dump):

```bash
cc-advisor --claude-dir ~/Library/Application\ Support/ClaudeCode
```

**Skip the settings snippets** when you just want the diagnosis, not the suggested JSON:

```bash
cc-advisor --no-snippets
```

### Options

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

Abridged from a real run. The full report also includes Current settings, Lifetime model usage, Recent usage patterns, Top tools / Bash command families, and (unless `--no-snippets`) ready-to-paste `settings.json` blocks.

```text
Additional investigations
-------------------------
[high] workflow-friction: Investigate tool error hot spots
  evidence: Tool error rate is 33.3% (1/3). Bash 50.0% (1/2)
  action: Look at failed Bash/Edit/WebFetch patterns first. Repeated tool errors
    usually mean missing project scripts, stale permissions, brittle hooks, or
    prompts that ask Claude to guess commands instead of inspecting repo affordances.

Recommended launch profiles
---------------------------
- Daily implementation: `claude --model sonnet --permission-mode acceptEdits --effort medium`
- Deep planning then execution: `claude --model opus --permission-mode plan --effort xhigh`
- Trusted autonomous work: `claude --model sonnet --permission-mode auto --effort high`
- Large-context planning: `claude --model opus --permission-mode plan --effort xhigh --add-dir <extra-dir>`
- Cheap/simple triage: `claude --model haiku --permission-mode default --effort low`

Recommendations
---------------
[high] model: Make Sonnet the execution default and reserve Opus for planning
  evidence: Opus is 99.7% of non-cache tokens while recent sessions are
    tool-heavy (1.50 tool calls/assistant call).
  action:   Use `claude --model opus --permission-mode plan --effort xhigh` for
    ambiguous work, then let execution run on Sonnet.

[high] permissions: Move risky always-allow permissions to ask/deny
  evidence: Detected 2 critical/high-risk allow rules, including destructive
    shell, cloud/cluster mutation, secret, or network pipe-to-shell patterns.
  action:   Keep read-only commands in `allow`; move deploy, destructive, secret,
    and broad network shell commands to `ask`.
```

Every recommendation cites the evidence it's based on, so you can decide whether a heuristic fits your situation before applying the suggested action.

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
- `opus` with `--permission-mode plan`: ambiguous planning, architecture, migrations, high-stakes debugging
- Opus large-context variants: large-context planning when your account and Claude Code CLI expose a supported full model id
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
