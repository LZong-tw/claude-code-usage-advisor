# Launch Notes

Use these snippets to announce Claude Code Usage Advisor.

## Short Pitch

Claude Code Usage Advisor is a zero-dependency CLI that reads your local Claude Code history and recommends which model/settings profile to use next.

It answers practical questions:

- Should daily coding use Sonnet or Opus?
- When should I use `opusplan`, `opus[1m]`, Haiku, or fast mode?
- Is my global `effortLevel` too high?
- Is `permissions.defaultMode=auto` actually safe in my setup?
- Which allow rules should move to ask/deny?

Run it without installing:

```bash
npx claude-code-usage-advisor
```

Repo: https://github.com/LZong-tw/claude-code-usage-advisor

## X / Threads

I built a small CLI for Claude Code users:

Claude Code Usage Advisor reads your local `~/.claude` history and recommends model/settings profiles: Sonnet vs Opus, `opusplan`, `opus[1m]`, Haiku, effort level, permission mode, sandboxing, and prompt caching.

Read-only. Zero dependencies. No telemetry.

```bash
npx claude-code-usage-advisor
```

https://github.com/LZong-tw/claude-code-usage-advisor

## LinkedIn

I published Claude Code Usage Advisor, a small local CLI for Claude Code users who want evidence-backed settings instead of guesswork.

It reads local Claude Code data from `~/.claude`, then recommends:

- daily implementation profile
- deep planning profile
- large-context profile
- cheap triage profile
- effort level strategy
- permission mode and sandboxing changes
- risky allow rules to review

It is read-only, zero-dependency, and does not call any external API.

Try it:

```bash
npx claude-code-usage-advisor
```

GitHub: https://github.com/LZong-tw/claude-code-usage-advisor

## Hacker News / Reddit

Title:

```text
Show HN: Claude Code Usage Advisor - local CLI for model/settings recommendations
```

Body:

```text
I built a small zero-dependency CLI that reads local Claude Code history and recommends model/settings profiles.

It looks at ~/.claude/settings.json, stats-cache.json, and projects/**/*.jsonl, then suggests when to use Sonnet, opusplan, opus[1m], Haiku, effort levels, permission modes, sandboxing, prompt caching, and which allow rules may be risky.

It is read-only and does not make network calls.

Run:

npx claude-code-usage-advisor

Repo:
https://github.com/LZong-tw/claude-code-usage-advisor
```

## One-Line Taglines

- Stop guessing your Claude Code settings.
- Evidence-backed model routing for Claude Code.
- A local, read-only advisor for Claude Code model and permission settings.
- Turn Claude Code usage history into launch profiles.
