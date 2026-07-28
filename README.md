# Claude Code Usage Advisor

[![Node.js 18+](https://img.shields.io/badge/node-%3E%3D18-339933)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![No dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)

**Your settings say what you intended. Your transcripts say what you actually do.**

Claude Code Usage Advisor reads both and reports where they disagree — then recommends the model, effort level, permission mode, sandboxing, and launch profiles that fit your real workload rather than your assumed one.

It is read-only, zero-dependency, and runs locally against `~/.claude` (the Claude Code CLI default on macOS, Linux, and Windows).

Heuristics target Claude Code 2.1.220 (2026-07).

### What this is not

**Not a cost tracker.** To know what you spent, use [ccusage](https://github.com/ccusage/ccusage). It is the tool for token and cost accounting and this does not try to replace it — the lifetime token section here is context for the routing advice, not a bill.

**Not a repo config linter.** To check a project's committed `.claude/` — hooks pointing at missing scripts, hardcoded secrets in `.mcp.json`, a `settings.local.json` that got committed by mistake — use [cc-doctor](https://github.com/Hiro-012/cc-doctor). It does static configuration checks and secret scanning, and it covers cases this tool does not.

The three do not overlap much. ccusage answers *how much did this cost*, cc-doctor answers *is this repo's config sane*, and this answers *does my setup match how I actually work* — which needs the transcripts, and is the part neither of the others reads.

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

**Feed it into a dashboard or pipeline.** JSON carries the same evidence as the text report. It keeps `recommendations` and `additional_insights` as separate arrays — the single `Findings` list is a rendering choice, so merge them yourself to match what the report shows:

```bash
cc-advisor --json > advisor.json
jq '[.recommendations[], .additional_insights[]] | map(select(.priority == "high"))' advisor.json
```

**Speed up runs on a huge `~/.claude`.** Scans newest JSONL files first.

```bash
cc-advisor --days 14 --max-files 200
```

**Point at a non-default Claude Code directory** — for example a teammate's exported `~/.claude` snapshot, or a backup directory you're auditing offline:

```bash
cc-advisor --claude-dir ./teammate-claude-dump
cc-advisor --claude-dir /mnt/backup/2026-05/claude
```

**Skip the settings snippets** when you just want the diagnosis, not the suggested JSON:

```bash
cc-advisor --no-snippets
```

**Gate a pipeline on findings.** Exits `1` when any recommendation or investigation is at least that severe, `0` otherwise. A crash or a bad flag exits `2`, so a broken run never looks like a clean one. Without `--fail-on` a successful run always exits `0`, because findings are advisory by default.

Findings top out at `high`, so `high` is the gate to use; `medium` will fire on almost any real configuration.

```bash
cc-advisor --fail-on high --no-snippets
```

### Options

```text
--claude-dir <path>   Claude Code directory (default: ~/.claude)
--days <n>            Analyze JSONL records from the last n days (default: 30, 0 = all)
--max-files <n>       Cap scanned JSONL files, newest first (default: unlimited)
--json                Print machine-readable JSON
--html <path>         Write a self-contained HTML report
--no-snippets         Hide settings snippets in text output
--fail-on <priority>  Exit 1 when a finding is at least this severe (high|medium|low)
                      Exit 2 is reserved for errors, so it never looks like a finding
--help                Show help
```

## Example Output

Every finding — whether it asks you to change a setting or to go look at something — lands in one `Findings` list sorted by severity, so the worst thing is always first. After that come launch profiles, current settings, recent usage patterns, top tools / Bash command families, lifetime model usage, and (unless `--no-snippets`) ready-to-paste `settings.json` blocks.

Abridged from an actual run against a sample directory:

```text
Findings
--------
[high] model: Make Sonnet the execution default and reserve Opus for planning
  evidence: Opus is 99.6% of non-cache tokens while recent sessions are tool-heavy
    (1.00 tool calls/assistant call).
  action: Use `claude --model opus --permission-mode plan --effort xhigh` for
    ambiguous work, then let execution run on Sonnet.
[high] executed-risk: Add deny rules for the risky commands your sessions actually run
  evidence: Transcripts show 25 critical and 16 high-severity commands (force-push,
    recursive-delete, kubectl-delete, secret-manager-read) while 90.4% of records
    ran in auto or bypassPermissions.
  action: Your allow rules may look clean while risky commands still run unattended.
    Add targeted `deny` entries for the destructive patterns above, or scope them to
    `ask`, so unattended sessions cannot reach them.
[medium] effort: Do not keep high effort as a global default
  evidence: Current user setting has `effortLevel: xhigh`.
  action: Set global `effortLevel` to `medium`; use `--effort high` or `--effort
    xhigh` only for design, review, migrations, and production-risk decisions.
```

The second one is the whole point. A static config check reads that allowlist and sees two harmless rules. Only the transcripts show that 25 destructive commands ran anyway, almost always in a mode where nobody was asked.

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

The cross-join is the point. A static read of `settings.json` can tell you a rule looks risky; it cannot tell you that your Opus share is 99.7% of non-cache tokens while your sessions average 1.5 tool calls per turn (route execution to Sonnet), or that the hooks you configured are firing thousands of times per window against your real Bash/Edit/Write volume, or that 25 destructive commands ran in a window where 90% of your records were in an unattended permission mode. Those findings only exist if something reads the transcripts.

Every report footer stamps the Claude Code version the heuristics were written for, so you can tell when they have drifted.

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
