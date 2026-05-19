# Agent Instructions

This repository is a public, zero-dependency Node.js CLI for analyzing local Claude Code usage and recommending model/settings profiles.

## Project Constraints

- Keep the CLI read-only. It must not modify `~/.claude`, user settings, transcripts, or project files.
- Keep the package dependency-free unless there is a strong reason to change that.
- Keep the runtime compatible with Node.js 18+.
- Do not add a build step. The shipped CLI is `bin/claude-code-usage-advisor.js`.
- Do not add telemetry, network calls, or API calls.
- Do not print raw transcript content by default. Reports should use aggregate counts, token totals, model names, tool names, command families, and settings keys.

## User-Facing Docs

- `README.md` is for users, not release operators.
- Do not put internal publishing checklists, maintainer-only notes, or temporary TODOs in `README.md`.
- Keep installation and usage examples short and copy-pasteable.
- Mention privacy behavior clearly when changing data collection or output fields.

## Testing

Run before committing:

```bash
npm test
```

Useful smoke check:

```bash
npm run smoke
```

When changing package metadata, also run:

```bash
npm pack --dry-run
```

## Fixtures

Tests use `test/fixtures/sample-claude` to simulate Claude Code local files:

- `settings.json`
- `stats-cache.json`
- `projects/**/*.jsonl`

Keep fixtures small and synthetic. Do not commit real user transcripts, secrets, internal paths, or company data.

## Recommendation Logic

The advisor should stay conservative and evidence-backed:

- Prefer Sonnet for daily implementation.
- Prefer `opusplan` for ambiguous planning, architecture, migrations, and high-stakes debugging.
- Prefer `opus[1m]` only for large-context planning when the account supports it.
- Prefer Haiku for simple summaries, classification, and cheap triage.
- Treat fast mode as explicit session-level behavior, not a global default.
- For permissions, distinguish read-only cloud/cluster access from mutation/destructive actions.

When adding new heuristics, include test coverage for false positives and false negatives.
