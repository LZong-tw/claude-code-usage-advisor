#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const readline = require("node:readline");

const TOKEN_FIELDS = [
  "input_tokens",
  "output_tokens",
  "cache_creation_input_tokens",
  "cache_read_input_tokens",
];

const STATS_TOKEN_FIELD_MAP = {
  inputTokens: "input_tokens",
  outputTokens: "output_tokens",
  cacheCreationInputTokens: "cache_creation_input_tokens",
  cacheReadInputTokens: "cache_read_input_tokens",
};

// Matched per shell statement, never across `;`/`&&`/newline: `echo aws && echo credentials` is not a secret read.
// `aws\b` also matches inside `aws-vault`, so every rule that means the AWS CLI uses AWS_CLI instead.
const AWS_CLI = String.raw`aws(?![-\w])`;
const RISKY_COMMAND_PATTERNS = [
  ["critical", "pipe-to-shell", /(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(bash|sh)\b/i],
  ["critical", "recursive-delete", /\brm\s+(-\S*r\S*f|-\S*f\S*r)\b/i],
  ["critical", "force-push", /\bgit\s+push\b[^\n]*\s(--force(?!-with-lease)|-f)\b/i],
  ["critical", "terraform-destroy", /\bterraform\s+destroy\b/i],
  ["high", "terraform-apply", /\bterraform\s+apply\b/i],
  ["high", "kubectl-delete", /\bkubectl\b[^\n]*\bdelete\b/i],
  ["high", "cloud-delete", new RegExp(String.raw`\b${AWS_CLI}\s+\S+[^\n]*\b(delete|terminate)\b|\b${AWS_CLI}\s+s3\s+(rm|rb)\b`, "i")],
  [
    "high",
    "secret-manager-read",
    new RegExp(
      String.raw`\b(${AWS_CLI}\s+(secretsmanager|ssm\s+get-parameter)|az\s+keyvault|gcloud\s+secrets|op\s+(item|read|signin)|(?<![-\w])vault\s+(read|kv))\b`,
      "i"
    ),
  ],
  ["high", "sudo", /(^|\s)sudo\s+/i],
  ["medium", "force-push-with-lease", /\bgit\s+push\b[^\n]*\s--force-with-lease\b/i],
  ["medium", "package-install", /\b(brew|npm|pnpm|yarn|pip|uv|gem|cargo)\s+[^\n]*\b(install|add)\b/i],
  ["medium", "network-fetch", /\b(curl|wget)\b/i],
];

const RISKY_PERMISSION_PATTERNS = [
  ["critical", "destructive shell", /^Bash\((rm|sudo|dd|mkfs|chmod\s+777|chown)\b/i],
  ["critical", "force push", /^Bash\(git\s+push\b.*(--force|-f|--force-with-lease)/i],
  ["high", "network pipe-to-shell", /^Bash\([^)]*(curl|wget)[^)]*\|[^)]*(bash|sh)/i],
  [
    "high",
    "cloud or cluster mutation",
    /^Bash\((kubectl\b.*\b(apply|delete|patch|scale|rollout|exec|cp|create|edit|replace|annotate|label)\b|(aws|az|gcloud)\b.*\b(delete|remove|terminate|put|update|create|set|write|deploy|apply)\b|terraform\s+(apply|destroy))/i,
  ],
  ["high", "cloud or cluster mutation", /^Bash\(aws\s+s3\s+(rm|rb|mv|sync\b[^)]*--delete)\b/i],
  ["high", "secret tooling", /^Bash\((op\s+item|op\s+vault|aws\s+secretsmanager|az\s+keyvault)\b/i],
  ["medium", "cloud or cluster access", /^Bash\((kubectl|aws|az|gcloud|terraform)\b/i],
  ["medium", "network fetch", /^Bash\((curl|wget)\b/i],
  ["medium", "package install", /^Bash\((brew|npm|pnpm|yarn|pip|uv|gem|cargo).*install\b/i],
  ["medium", "git remote mutation", /^Bash\(git\s+(push|remote)\b/i],
  ["low", "git local mutation", /^Bash\(git\s+(checkout|commit|reset|restore)\b/i],
  ["low", "one-off artifact", /^Bash\(([0-9a-f]{8}-[0-9a-f-]{27,}|EOF|done)\)?$/i],
];

const TARGETS_VERSION = "Claude Code 2.1.220 (2026-07)";
const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };

function usage() {
  return `Claude Code Usage Advisor

Usage:
  claude-code-usage-advisor [options]
  cc-advisor [options]

Options:
  --claude-dir <path>   Claude Code directory (default: ~/.claude)
  --days <n>            Analyze JSONL records from the last n days (default: 30, 0 = all)
  --max-files <n>       Cap scanned JSONL files, newest first (default: unlimited)
  --json                Print machine-readable JSON
  --html <path>         Write a self-contained HTML report
  --no-snippets         Hide settings snippets in text output
  --fail-on <priority>  Exit 1 when a finding is at least this severe (high|medium|low).
                        Findings top out at high, so high is the CI gate.
                        Errors exit 2, so a broken run never looks like a finding.
  --help                Show help

Examples:
  npx claude-code-usage-advisor
  npx claude-code-usage-advisor --days 7 --json
  cc-advisor --claude-dir ./teammate-claude-dump
  cc-advisor --fail-on high --no-snippets

Heuristics target ${TARGETS_VERSION}.`;
}

function parseArgs(argv) {
  const args = {
    claudeDir: path.join(os.homedir(), ".claude"),
    days: 30,
    maxFiles: 0,
    json: false,
    htmlPath: null,
    snippets: true,
    failOn: null,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--html") {
      args.htmlPath = requireValue(argv, ++i, "--html");
    } else if (arg.startsWith("--html=")) {
      args.htmlPath = arg.slice("--html=".length);
    } else if (arg === "--no-snippets") {
      args.snippets = false;
    } else if (arg === "--claude-dir") {
      args.claudeDir = requireValue(argv, ++i, "--claude-dir");
    } else if (arg.startsWith("--claude-dir=")) {
      args.claudeDir = arg.slice("--claude-dir=".length);
    } else if (arg === "--days") {
      args.days = parseNonNegativeInteger(requireValue(argv, ++i, "--days"), "--days");
    } else if (arg.startsWith("--days=")) {
      args.days = parseNonNegativeInteger(arg.slice("--days=".length), "--days");
    } else if (arg === "--max-files") {
      args.maxFiles = parseNonNegativeInteger(requireValue(argv, ++i, "--max-files"), "--max-files");
    } else if (arg.startsWith("--max-files=")) {
      args.maxFiles = parseNonNegativeInteger(arg.slice("--max-files=".length), "--max-files");
    } else if (arg === "--fail-on") {
      args.failOn = parsePriority(requireValue(argv, ++i, "--fail-on"));
    } else if (arg.startsWith("--fail-on=")) {
      args.failOn = parsePriority(arg.slice("--fail-on=".length));
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  args.claudeDir = expandHome(args.claudeDir);
  if (args.htmlPath) args.htmlPath = path.resolve(expandHome(args.htmlPath));
  return args;
}

function requireValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
}

function parsePriority(value) {
  if (!(value in PRIORITY_ORDER)) {
    throw new Error(`--fail-on must be one of: ${Object.keys(PRIORITY_ORDER).join(", ")}`);
  }
  return value;
}

// Findings are advisory, so a run only fails when the caller opts in with --fail-on.
function failOnExitCode(report, threshold) {
  if (!threshold) return 0;
  const limit = PRIORITY_ORDER[threshold];
  const findings = [...(report.recommendations || []), ...(report.additional_insights || [])];
  return findings.some((finding) => (PRIORITY_ORDER[finding.priority] ?? 9) <= limit) ? 1 : 0;
}

function parseNonNegativeInteger(value, flag) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0 || String(parsed) !== String(value)) {
    throw new Error(`${flag} must be a non-negative integer`);
  }
  return parsed;
}

function expandHome(input) {
  if (input === "~") return os.homedir();
  if (input.startsWith("~/")) return path.join(os.homedir(), input.slice(2));
  return path.resolve(input);
}

function readJson(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(content);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    if (error.code === "ENOENT") return {};
    return { _error: String(error.message || error) };
  }
}

function tokenStats() {
  return {
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
  };
}

function addUsage(target, usage) {
  for (const field of TOKEN_FIELDS) {
    if (Number.isInteger(usage[field])) target[field] += usage[field];
  }
}

function statsCacheModelUsage(statsCache) {
  const modelUsage = statsCache.modelUsage;
  const output = {};
  if (!modelUsage || typeof modelUsage !== "object" || Array.isArray(modelUsage)) return output;

  for (const [model, values] of Object.entries(modelUsage)) {
    if (!values || typeof values !== "object" || Array.isArray(values)) continue;
    const normalized = tokenStats();
    for (const [sourceKey, destKey] of Object.entries(STATS_TOKEN_FIELD_MAP)) {
      if (Number.isInteger(values[sourceKey])) normalized[destKey] += values[sourceKey];
    }
    output[model] = normalized;
  }
  return output;
}

function parseTimestamp(value) {
  if (typeof value !== "string" || value.length === 0) return null;
  const millis = Date.parse(value);
  if (Number.isNaN(millis)) return null;
  return millis;
}

function listJsonlFiles(root, maxFiles) {
  const files = [];
  if (!fs.existsSync(root)) return files;
  walk(root, files);
  files.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return maxFiles > 0 ? files.slice(0, maxFiles).map((item) => item.file) : files.map((item) => item.file);
}

function walk(dir, files) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, files);
    } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
      try {
        const stat = fs.statSync(fullPath);
        files.push({ file: fullPath, mtimeMs: stat.mtimeMs });
      } catch {
        // Ignore files that disappear while scanning.
      }
    }
  }
}

function emptyJsonlStats() {
  return {
    files_scanned: 0,
    records_scanned: 0,
    records_in_window: 0,
    parse_errors: 0,
    sessions: new Set(),
    first_timestamp: null,
    last_timestamp: null,
    message_types: new Map(),
    permission_modes: new Map(),
    cwd: new Map(),
    entrypoints: new Map(),
    versions: new Map(),
    models: new Map(),
    model_tokens: new Map(),
    speeds: new Map(),
    service_tiers: new Map(),
    tool_use: new Map(),
    tool_errors: new Map(),
    mcp_servers: new Map(),
    skills: new Map(),
    bash_commands: new Map(),
    bash_risks: new Map(),
    thinking_blocks: 0,
    image_blocks: 0,
    sidechain_records: 0,
    assistant_calls: 0,
  };
}

async function analyzeJsonl(claudeDir, days, maxFiles) {
  const now = Date.now();
  const cutoff = days <= 0 ? null : now - days * 24 * 60 * 60 * 1000;
  const state = emptyJsonlStats();

  const toolUseIds = new Map();
  const files = listJsonlFiles(path.join(claudeDir, "projects"), maxFiles);
  for (const file of files) {
    state.files_scanned += 1;
    await readJsonlLines(file, (record) => {
      state.records_scanned += 1;
      if (!record || typeof record !== "object" || Array.isArray(record)) return;
      const timestamp = parseTimestamp(record.timestamp);
      if (cutoff !== null && timestamp !== null && timestamp < cutoff) return;

      state.records_in_window += 1;
      if (timestamp !== null) {
        if (state.first_timestamp === null || timestamp < state.first_timestamp) state.first_timestamp = timestamp;
        if (state.last_timestamp === null || timestamp > state.last_timestamp) state.last_timestamp = timestamp;
      }

      if (typeof record.sessionId === "string") state.sessions.add(record.sessionId);
      if (record.isSidechain === true) state.sidechain_records += 1;
      incrementIfString(state.message_types, record.type);
      incrementIfString(state.permission_modes, record.permissionMode);
      incrementIfString(state.cwd, record.cwd);
      incrementIfString(state.entrypoints, record.entrypoint);
      incrementIfString(state.versions, record.version);

      const message = record.message;
      if (message && typeof message === "object" && !Array.isArray(message)) {
        const model = message.model;
        if (typeof model === "string") increment(state.models, model);

        const usage = message.usage;
        if (usage && typeof usage === "object" && !Array.isArray(usage)) {
          state.assistant_calls += 1;
          if (typeof model === "string") {
            if (!state.model_tokens.has(model)) state.model_tokens.set(model, tokenStats());
            addUsage(state.model_tokens.get(model), usage);
          }
          incrementIfString(state.speeds, usage.speed);
          incrementIfString(state.service_tiers, usage.service_tier);
        }

        if (Array.isArray(message.content)) {
          analyzeContentBlocks(message.content, state, toolUseIds);
        }
      }
    }, () => {
      state.parse_errors += 1;
    });
  }

  return state;
}

async function readJsonlLines(filePath, onRecord, onParseError) {
  const stream = fs.createReadStream(filePath, { encoding: "utf8" });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (!line.trim()) continue;
      try {
        onRecord(JSON.parse(line));
      } catch {
        onParseError();
      }
    }
  } catch {
    onParseError();
  }
}

function analyzeContentBlocks(blocks, state, toolUseIds) {
  for (const block of blocks) {
    if (!block || typeof block !== "object" || Array.isArray(block)) continue;
    if (block.type === "thinking") {
      state.thinking_blocks += 1;
    } else if (block.type === "image") {
      state.image_blocks += 1;
    } else if (block.type === "tool_use") {
      const toolName = typeof block.name === "string" ? block.name : "<unknown>";
      increment(state.tool_use, toolName);
      if (typeof block.id === "string") toolUseIds.set(block.id, toolName);
      analyzeToolUse(toolName, block.input, state);
    } else if (block.type === "tool_result" && block.is_error === true) {
      const toolName = typeof block.tool_use_id === "string" ? toolUseIds.get(block.tool_use_id) || "<unknown>" : "<unknown>";
      increment(state.tool_errors, toolName);
    }
  }
}

function analyzeToolUse(toolName, input, state) {
  if (toolName === "Bash") {
    const command = input && typeof input === "object" && typeof input.command === "string" ? input.command : "";
    increment(state.bash_commands, shellCommandKey(command));
    for (const [severity, label] of commandRisks(command)) increment(state.bash_risks, `${severity}:${label}`);
  } else if (toolName === "Skill") {
    const skill = input && typeof input === "object" && typeof input.skill === "string" ? input.skill : null;
    if (skill) increment(state.skills, skill);
  } else if (toolName.startsWith("mcp__")) {
    const parts = toolName.split("__");
    if (parts.length >= 3) increment(state.mcp_servers, parts[1]);
  }
}

// Split on statement separators outside quotes. Pipes stay inside a statement so pipe-to-shell still matches.
function shellStatements(command) {
  const statements = [];
  let current = "";
  let quote = null;
  for (let i = 0; i < command.length; i += 1) {
    const char = command[i];
    if (quote) {
      if (char === quote) quote = null;
      current += char;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      current += char;
      continue;
    }
    const two = command.slice(i, i + 2);
    if (char === ";" || char === "\n" || two === "&&" || two === "||") {
      statements.push(current);
      current = "";
      if (two === "&&" || two === "||") i += 1;
      continue;
    }
    current += char;
  }
  statements.push(current);
  return statements.filter((statement) => statement.trim());
}

function commandRisks(command) {
  const statements = shellStatements(command);
  const seen = new Set();
  const risks = [];
  for (const [severity, label, pattern] of RISKY_COMMAND_PATTERNS) {
    if (seen.has(label)) continue;
    if (statements.some((statement) => pattern.test(statement))) {
      seen.add(label);
      risks.push([severity, label]);
    }
  }
  return risks;
}

function permissionRisks(rule) {
  return RISKY_PERMISSION_PATTERNS.filter(([, , pattern]) => pattern.test(rule)).map(([severity, label]) => [severity, label]);
}

function shellCommandKey(command) {
  const parts = splitShellish(command);
  if (parts.length === 0) return "<empty>";
  let index = 0;
  const wrappers = new Set(["env", "time", "timeout", "gtimeout", "nice", "nohup", "command"]);
  while (index < parts.length) {
    const token = parts[index];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
      index += 1;
      continue;
    }
    if (wrappers.has(token)) {
      index += 1;
      while (index < parts.length && parts[index].startsWith("-")) index += 1;
      if ((token === "timeout" || token === "gtimeout") && index < parts.length) index += 1;
      continue;
    }
    break;
  }
  if (index >= parts.length) return parts[0];
  const cmd = path.basename(parts[index]);
  const rest = parts.slice(index + 1);

  if (["git", "gh", "glab", "kubectl", "docker", "terraform", "go", "cargo"].includes(cmd) && rest[0]) {
    return `${cmd} ${rest[0]}`;
  }
  if (["npm", "pnpm", "yarn"].includes(cmd) && rest[0]) {
    if (rest[0] === "run" && rest[1]) return `${cmd} run ${rest[1]}`;
    return `${cmd} ${rest[0]}`;
  }
  if (cmd === "aws" && rest.length >= 2) return `aws ${rest[0]} ${rest[1]}`;
  if (["python", "python3", "node", "ruby", "bash", "zsh", "sh"].includes(cmd)) return cmd;
  return cmd;
}

function splitShellish(input) {
  const parts = [];
  let current = "";
  let quote = null;
  let escaping = false;
  for (const char of input) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }
    if (char === "\\") {
      escaping = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        parts.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) parts.push(current);
  return parts;
}

function analyzeSettings(settings) {
  const permissions = objectOrEmpty(settings.permissions);
  const env = objectOrEmpty(settings.env);
  const hooks = objectOrEmpty(settings.hooks);
  const allowRules = Array.isArray(permissions.allow) ? permissions.allow : [];
  const askRules = Array.isArray(permissions.ask) ? permissions.ask : [];
  const denyRules = Array.isArray(permissions.deny) ? permissions.deny : [];
  const riskyAllow = new Map();
  const riskyExamples = {};

  for (const rule of allowRules) {
    if (typeof rule !== "string") continue;
    for (const [severity, label] of permissionRisks(rule)) {
      const key = `${severity}:${label}`;
      increment(riskyAllow, key);
      if (!riskyExamples[key]) riskyExamples[key] = [];
      if (riskyExamples[key].length < 3) riskyExamples[key].push(rule);
    }
  }

  return {
    model: settings.model ?? null,
    effortLevel: settings.effortLevel ?? null,
    fastMode: settings.fastMode ?? null,
    autoMode_configured: isPlainObject(settings.autoMode) && "environment" in settings.autoMode,
    sandbox_configured: isPlainObject(settings.sandbox),
    permissions_defaultMode: permissions.defaultMode ?? null,
    permissions_allow_count: allowRules.length,
    permissions_ask_count: askRules.length,
    permissions_deny_count: denyRules.length,
    risky_allow: mapToObject(riskyAllow),
    risky_allow_examples: riskyExamples,
    env_keys: Object.keys(env).sort(),
    has_prompt_cache_1h: env.ENABLE_PROMPT_CACHING_1H === "1" || env.ENABLE_PROMPT_CACHING_1H === 1,
    has_subprocess_env_scrub: env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB === "1" || env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB === 1,
    autocompact_pct: env.CLAUDE_AUTOCOMPACT_PCT_OVERRIDE ?? null,
    statusLine: isPlainObject(settings.statusLine) ? settings.statusLine : null,
    statusline_uses_npx_latest: statusLineUsesNpxLatest(settings.statusLine),
    hooks_command_count: countHookCommands(hooks),
    hooks_matchers: summarizeHookMatchers(hooks),
  };
}

function objectOrEmpty(value) {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function statusLineUsesNpxLatest(statusLine) {
  if (!isPlainObject(statusLine) || typeof statusLine.command !== "string") return false;
  return /\bnpx\b.*(@latest|-y)/.test(statusLine.command);
}

function countHookCommands(hooks) {
  let count = 0;
  for (const entries of Object.values(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) continue;
      count += entry.hooks.filter((hook) => isPlainObject(hook) && typeof hook.command === "string").length;
    }
  }
  return count;
}

function summarizeHookMatchers(hooks) {
  const summary = [];
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!isPlainObject(entry)) continue;
      summary.push({
        event,
        matcher: typeof entry.matcher === "string" ? entry.matcher : "*",
        commands: Array.isArray(entry.hooks)
          ? entry.hooks.filter((hook) => isPlainObject(hook) && typeof hook.command === "string").length
          : 0,
      });
    }
  }
  return summary;
}

function buildRecommendations(settingsInfo, jsonlStats, lifetimeUsage) {
  const recommendations = [];
  const familyTotals = familyTokenTotals(Object.keys(lifetimeUsage).length ? lifetimeUsage : mapValuesToObject(jsonlStats.model_tokens));
  const totalFresh = Object.values(familyTotals).reduce((sum, values) => sum + freshTotal(values), 0);
  const opusFresh = freshTotal(familyTotals.opus || tokenStats());
  const sonnetFresh = freshTotal(familyTotals.sonnet || tokenStats());
  const toolCalls = mapValueSum(jsonlStats.tool_use);
  const assistantCalls = jsonlStats.assistant_calls || 0;
  const toolPerCall = assistantCalls ? toolCalls / assistantCalls : 0;

  if (totalFresh && opusFresh / totalFresh > 0.45 && toolPerCall > 0.5) {
    recommendations.push({
      priority: "high",
      category: "model",
      title: "Make Sonnet the execution default and reserve Opus for planning",
      evidence: `Opus is ${pct(opusFresh, totalFresh)} of non-cache tokens while recent sessions are tool-heavy (${toolPerCall.toFixed(2)} tool calls/assistant call).`,
      action: "Use `claude --model opus --permission-mode plan --effort xhigh` for ambiguous work, then let execution run on Sonnet. Use `claude --model sonnet --permission-mode acceptEdits --effort medium` for normal implementation.",
    });
  } else if (totalFresh && sonnetFresh / totalFresh > 0.55) {
    recommendations.push({
      priority: "medium",
      category: "model",
      title: "Keep Sonnet as the default daily coding model",
      evidence: `Sonnet is ${pct(sonnetFresh, totalFresh)} of non-cache tokens.`,
      action: "Use `claude --model sonnet --permission-mode acceptEdits --effort medium` for implementation; escalate to `claude --model opus --permission-mode plan --effort xhigh` for architecture, incident diagnosis, and high-ambiguity refactors.",
    });
  } else {
    recommendations.push({
      priority: "medium",
      category: "model",
      title: "Use task routing instead of one global model",
      evidence: "Your history mixes model families enough that one permanent model is less useful than launch profiles.",
      action: "Use Sonnet for implementation, Opus in plan mode for deep planning, Haiku for simple summaries/classification, and the largest Opus context your account exposes only for large-context planning.",
    });
  }

  if (["high", "xhigh", "max"].includes(settingsInfo.effortLevel)) {
    recommendations.push({
      priority: "medium",
      category: "effort",
      title: "Do not keep high effort as a global default",
      evidence: `Current user setting has \`effortLevel: ${settingsInfo.effortLevel}\`.`,
      action: "Set global `effortLevel` to `medium`; use `--effort high` or `--effort xhigh` only for design, review, migrations, and production-risk decisions.",
    });
  }

  if (settingsInfo.permissions_defaultMode === "auto" && !settingsInfo.autoMode_configured) {
    recommendations.push({
      priority: "high",
      category: "permissions",
      title: "Configure autoMode.environment before defaulting to auto",
      evidence: "`permissions.defaultMode` is `auto`, but no `autoMode` block was found in user settings.",
      action: "Either change default mode to `acceptEdits`, or add an `autoMode.environment` block naming trusted source-control orgs, internal domains, cloud buckets, and services.",
    });
  }

  const riskyAllow = settingsInfo.risky_allow || {};
  const highRisky = Object.entries(riskyAllow)
    .filter(([key]) => key.startsWith("critical:") || key.startsWith("high:"))
    .reduce((sum, [, count]) => sum + count, 0);
  if (highRisky) {
    recommendations.push({
      priority: "high",
      category: "permissions",
      title: "Move risky always-allow permissions to ask/deny",
      evidence: `Detected ${highRisky} critical/high-risk allow rules, including destructive shell, cloud/cluster mutation, secret, or network pipe-to-shell patterns.`,
      action: "Keep read-only and deterministic commands in `allow`; move deploy, destructive, secret, and broad network shell commands to `ask` unless scoped to exact safe arguments.",
    });
  }

  // The allowlist says what is permitted; the transcripts say what ran. Only the pair is actionable.
  const executed = severityTotals(jsonlStats.bash_risks);
  const unattended = mapValueSum(jsonlStats.permission_modes)
    ? (jsonlStats.permission_modes.get("auto") || 0) + (jsonlStats.permission_modes.get("bypassPermissions") || 0)
    : 0;
  const unattendedShare = unattended / (mapValueSum(jsonlStats.permission_modes) || 1);
  if (executed.critical.total && unattendedShare > 0.5) {
    const named = [...executed.critical.labels, ...executed.high.labels].slice(0, 4).join(", ");
    recommendations.push({
      priority: "high",
      category: "executed-risk",
      title: "Add deny rules for the risky commands your sessions actually run",
      evidence:
        `Transcripts show ${executed.critical.total} critical and ${executed.high.total} high-severity commands ` +
        `(${named}) while ${pct(unattended, mapValueSum(jsonlStats.permission_modes))} of records ran in auto or bypassPermissions.`,
      action:
        "Your allow rules may look clean while risky commands still run unattended. Add targeted `deny` entries for the destructive patterns above, or scope them to `ask`, so unattended sessions cannot reach them.",
    });
  }

  if (["auto", "acceptEdits"].includes(settingsInfo.permissions_defaultMode) && !settingsInfo.sandbox_configured) {
    recommendations.push({
      priority: "medium",
      category: "sandbox",
      title: "Enable Bash sandboxing for low-friction modes",
      evidence: `Default mode is \`${settingsInfo.permissions_defaultMode}\` and no \`sandbox\` block was found.`,
      action: "Turn on `sandbox.enabled` and deny reads of credential directories; this lets common commands proceed with less risk.",
    });
  }

  if (!settingsInfo.has_subprocess_env_scrub) {
    recommendations.push({
      priority: "medium",
      category: "env",
      title: "Scrub model/API credentials from subprocesses",
      evidence: "`CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` is not enabled.",
      action: "Add `\"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB\": \"1\"` under `env`, especially if your setup uses Bash, MCP, cloud CLIs, or secret tooling.",
    });
  }

  const cacheCreation = Object.values(lifetimeUsage).reduce((sum, values) => sum + (values.cache_creation_input_tokens || 0), 0);
  const cacheRead = Object.values(lifetimeUsage).reduce((sum, values) => sum + (values.cache_read_input_tokens || 0), 0);
  const cacheRatio = cacheCreation > 0 ? cacheRead / cacheCreation : 0;
  if (cacheCreation > 100_000_000 || cacheRead > 1_000_000_000) {
    const churnAdvice =
      "Avoid switching models mid-session when the context is large, and start large-context work in the right profile instead of rebuilding the cache.";
    recommendations.push({
      priority: settingsInfo.has_prompt_cache_1h ? "low" : "medium",
      category: "context",
      title: settingsInfo.has_prompt_cache_1h ? "Keep 1-hour prompt caching enabled" : "Enable 1-hour prompt caching for repeated large contexts",
      evidence:
        `Lifetime cache creation/read tokens are high (${compactNumber(cacheCreation)} create, ${compactNumber(cacheRead)} read` +
        `${cacheRatio ? `, ${cacheRatio.toFixed(1)}x read/create` : ""}).`,
      action: settingsInfo.has_prompt_cache_1h
        ? `Keep \`ENABLE_PROMPT_CACHING_1H=1\`. ${churnAdvice}`
        : `Add \`"ENABLE_PROMPT_CACHING_1H": "1"\` under \`env\` if your billing/plan supports it. ${churnAdvice}`,
    });
  }

  const fastCalls = jsonlStats.speeds.get("fast") || 0;
  if (fastCalls === 0) {
    recommendations.push({
      priority: "low",
      category: "speed",
      title: "Use fast mode only as an explicit Opus profile",
      evidence: "Recent logs show no fast-mode responses.",
      action: "Do not set `fastMode: true` globally. For urgent interactive debugging, start an Opus session and run `/fast` at the beginning.",
    });
  }

  const records = jsonlStats.records_in_window || 0;
  if (records && jsonlStats.sidechain_records / records > 0.05) {
    recommendations.push({
      priority: "medium",
      category: "subagents",
      title: "Set a default subagent model and track what it buys you",
      evidence: `Sidechain/subagent records are ${pct(jsonlStats.sidechain_records, records)} of recent JSONL records.`,
      action:
        "Use `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` for code-changing subagents, or `haiku` for search/summarize/classify subagents, to avoid accidental Opus spend. " +
        "Then check whether subagents actually reduce wall-clock time or just multiply context and tool usage — reserve Opus for synthesis decisions.",
    });
  }

  return recommendations;
}

function buildAdditionalInsights(settingsInfo, jsonlStats, lifetimeUsage, localState) {
  const insights = [];
  const toolCalls = mapValueSum(jsonlStats.tool_use);
  const toolErrors = mapValueSum(jsonlStats.tool_errors);
  const bashCalls = jsonlStats.tool_use.get("Bash") || 0;
  const bashErrors = jsonlStats.tool_errors.get("Bash") || 0;
  const editCalls = jsonlStats.tool_use.get("Edit") || 0;
  const editErrors = jsonlStats.tool_errors.get("Edit") || 0;
  const webFetchCalls = jsonlStats.tool_use.get("WebFetch") || 0;
  const webFetchErrors = jsonlStats.tool_errors.get("WebFetch") || 0;

  if (toolCalls && toolErrors / toolCalls > 0.03) {
    const highErrorTools = [
      ["Bash", bashErrors, bashCalls],
      ["Edit", editErrors, editCalls],
      ["WebFetch", webFetchErrors, webFetchCalls],
    ]
      .filter(([, errors, calls]) => errors > 0 && calls > 0)
      .map(([name, errors, calls]) => `${name} ${pct(errors, calls)} (${errors}/${calls})`)
      .join(", ");
    insights.push({
      priority: "high",
      category: "workflow-friction",
      title: "Investigate tool error hot spots",
      evidence: `Tool error rate is ${pct(toolErrors, toolCalls)} (${toolErrors}/${toolCalls}). ${highErrorTools || "Top tool errors are present."}`,
      action: "Look at failed Bash/Edit/WebFetch patterns first. Repeated tool errors usually mean missing project scripts, stale permissions, brittle hooks, or prompts that ask Claude to guess commands instead of inspecting repo affordances.",
    });
  }

  const hookEstimate = estimateHookTriggers(settingsInfo, jsonlStats);
  if (hookEstimate.total > 1000 || settingsInfo.statusline_uses_npx_latest) {
    const statusLineNote = settingsInfo.statusline_uses_npx_latest
      ? " Status line uses `npx`/`@latest`, which can add latency or network/cache noise."
      : "";
    insights.push({
      priority: "medium",
      category: "local-overhead",
      title: "Measure hook and status line overhead",
      evidence: `Configured hooks: ${settingsInfo.hooks_command_count}; estimated recent hook invocations: ${compactNumber(hookEstimate.total)}.${statusLineNote}`,
      action: "Time each hook, cache expensive checks, and consider replacing `npx ...@latest` status lines with a pinned/local command. Hooks are useful, but high-frequency Bash/Edit hooks become part of every coding loop.",
    });
  }

  const cwdTotal = [...jsonlStats.cwd.values()].reduce((sum, count) => sum + count, 0);
  const topCwd = topCounter(jsonlStats.cwd, 1)[0];
  if (topCwd && cwdTotal && topCwd.count / cwdTotal > 0.35) {
    insights.push({
      priority: "medium",
      category: "project-hotspot",
      title: "Create project-specific Claude Code profiles",
      evidence: `Top working directory accounts for ${pct(topCwd.count, cwdTotal)} of recent records: ${topCwd.name}.`,
      action: "Move repo-specific gotchas, common commands, deny rules, and MCP expectations into project-level `CLAUDE.md`/settings instead of global settings. Heavy projects deserve their own launch alias and permission profile.",
    });
  }

  const lowRisky = Object.entries(settingsInfo.risky_allow || {})
    .filter(([key]) => key.startsWith("low:"))
    .reduce((sum, [, count]) => sum + count, 0);
  const bulkyAllowlist = settingsInfo.permissions_allow_count > 100;
  if (bulkyAllowlist || lowRisky > 20) {
    // Name the condition that actually tripped, so the evidence is not led by the number that did not.
    const reasons = [];
    if (bulkyAllowlist) reasons.push(`the global allowlist has grown to ${settingsInfo.permissions_allow_count} rules`);
    if (lowRisky > 20) reasons.push(`${lowRisky} of them are low-signal one-off rules`);
    insights.push({
      priority: "medium",
      category: "permission-hygiene",
      title: "Prune allowlist drift",
      evidence: `Flagged because ${reasons.join(" and ")}.`,
      action: "Delete UUID/EOF/done one-off allows and move project-specific or temporary permissions out of global settings. A large allowlist makes `auto` less predictable and harder to audit.",
    });
  }

  const claudeMd = localState.claude_md || {};
  if (claudeMd.exists && claudeMd.lines > 300) {
    insights.push({
      priority: "medium",
      category: "context-hygiene",
      title: "Review global CLAUDE.md size",
      evidence: `Global CLAUDE.md is ${claudeMd.lines} lines (${compactNumber(claudeMd.bytes)}B).`,
      action: "Keep only durable global rules there. Move project/team workflows into project `CLAUDE.md`, skills, or slash commands so every session does not inherit stale context.",
    });
  }


  const mcpCalls = [...jsonlStats.tool_use.entries()]
    .filter(([name]) => name.startsWith("mcp__"))
    .reduce((sum, [, count]) => sum + count, 0);
  if (mcpCalls > 100) {
    const topMcp = topCounter(jsonlStats.mcp_servers, 3).map((item) => `${item.name} ${item.count}`).join(", ");
    insights.push({
      priority: "medium",
      category: "mcp-dependency",
      title: "Treat MCP-heavy work as a separate operating mode",
      evidence: `MCP tool calls in window: ${mcpCalls}. Top servers: ${topMcp}.`,
      action: "Use a planning-first profile for incident/Jira/PagerDuty/Sentry work, keep MCP auth health visible, and avoid mixing high-risk infrastructure actions into the same always-auto allowlist.",
    });
  }

  if (localState.telemetry_failed_events_count > 20 || jsonlStats.parse_errors > 0) {
    insights.push({
      priority: "low",
      category: "local-health",
      title: "Inspect local telemetry/log health",
      evidence: `Failed telemetry event files: ${localState.telemetry_failed_events_count}; JSONL parse errors: ${jsonlStats.parse_errors}.`,
      action: "This usually does not affect model choice directly, but it can indicate stale local state, broken telemetry upload, or partially written JSONL. Keep it visible when debugging CLI/report discrepancies.",
    });
  }


  return insights;
}

// bash_risks keys are "severity:label" counters; roll them up per severity and keep the labels.
function severityTotals(risks) {
  const out = { critical: { total: 0, labels: [] }, high: { total: 0, labels: [] } };
  for (const [key, count] of risks || []) {
    const [severity, label] = key.split(":");
    if (!out[severity]) continue;
    out[severity].total += count;
    out[severity].labels.push(label);
  }
  for (const bucket of Object.values(out)) bucket.labels.sort();
  return out;
}

function estimateHookTriggers(settingsInfo, jsonlStats) {
  const bash = jsonlStats.tool_use.get("Bash") || 0;
  const edit = jsonlStats.tool_use.get("Edit") || 0;
  const write = jsonlStats.tool_use.get("Write") || 0;
  const stop = jsonlStats.sessions ? jsonlStats.sessions.size : 0;
  let total = 0;
  for (const hook of settingsInfo.hooks_matchers || []) {
    if (!hook.commands) continue;
    if (hook.matcher === "*" && hook.event === "Stop") total += hook.commands * stop;
    else if (/Bash/.test(hook.matcher)) total += hook.commands * bash;
    else if (/Edit|Write/.test(hook.matcher)) total += hook.commands * (edit + write);
  }
  return { total };
}

function launchProfiles() {
  return [
    {
      name: "Daily implementation",
      command: "claude --model sonnet --permission-mode acceptEdits --effort medium",
      use_when: "Normal code edits, tests, refactors with a clear target.",
    },
    {
      name: "Deep planning then execution",
      command: "claude --model opus --permission-mode plan --effort xhigh",
      use_when: "Ambiguous architecture, incident diagnosis, large refactors, migrations.",
    },
    {
      name: "Trusted autonomous work",
      command: "claude --model sonnet --permission-mode auto --effort high",
      use_when: "Only after `autoMode.environment`, risky permissions, and sandboxing are configured.",
    },
    {
      name: "Large-context planning",
      command: "claude --model opus --permission-mode plan --effort xhigh --add-dir <extra-dir>",
      use_when: "Large repo exploration or cross-service analysis. Use the largest Opus context your Claude Code account exposes; pass a full model id only if your CLI/account supports it.",
    },
    {
      name: "Cheap/simple triage",
      command: "claude --model haiku --permission-mode default --effort low",
      use_when: "Summaries, classification, log triage, simple Q&A without code changes.",
    },
  ];
}

function settingsSnippets() {
  const systemWritePaths = process.platform === "win32"
    ? ["C:/Windows", "C:/Program Files"]
    : ["/etc", "/usr/local/bin"];
  return {
    balanced_user_settings: {
      $schema: "https://json.schemastore.org/claude-code-settings.json",
      model: "sonnet",
      effortLevel: "medium",
      permissions: {
        defaultMode: "acceptEdits",
        ask: [
          "Bash(git push *)",
          "Bash(curl *)",
          "Bash(wget *)",
          "Bash(kubectl *)",
          "Bash(aws *)",
          "Bash(az *)",
          "Bash(gcloud *)",
          "Bash(terraform apply *)",
          "Bash(terraform destroy *)",
          "Bash(op *)",
        ],
        deny: [
          "Read(./.env)",
          "Read(./.env.*)",
          "Read(./secrets/**)",
          "Read(./config/credentials.json)",
          "Read(~/.aws/credentials)",
          "Read(~/.ssh/**)",
        ],
      },
      env: {
        ENABLE_PROMPT_CACHING_1H: "1",
        CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "1",
      },
      sandbox: {
        enabled: true,
        autoAllowBashIfSandboxed: true,
        filesystem: {
          denyRead: ["~/.aws", "~/.ssh", "~/.kube", "~/.mcp-auth"],
          denyWrite: [...systemWritePaths, "~/.ssh", "~/.aws"],
        },
      },
    },
    auto_mode_overlay: {
      permissions: { defaultMode: "auto" },
      autoMode: {
        environment: [
          "$defaults",
          "Organization: {COMPANY_OR_TEAM}. Primary use: software development and infrastructure operations",
          "Source control: {GITHUB_OR_GITLAB_ORG_AND_HOSTS}",
          "Cloud provider(s): {AWS_GCP_AZURE_ACCOUNTS_OR_PROJECTS}",
          "Trusted cloud buckets: {S3_OR_GCS_BUCKETS}",
          "Trusted internal domains: {INTERNAL_DOMAINS}",
          "Key internal services: {CI_ARTIFACT_REGISTRY_DASHBOARDS}",
        ],
        soft_deny: [
          "$defaults",
          "Never deploy to production unless the user explicitly asks for that exact production deployment.",
          "Never run database migrations unless the user names the migration target and environment.",
        ],
        hard_deny: ["$defaults", "Never exfiltrate repository contents or credentials to third-party APIs."],
      },
    },
    subagent_overlay: {
      env: { CLAUDE_CODE_SUBAGENT_MODEL: "sonnet" },
    },
  };
}

function analyzeLocalState(claudeDir) {
  return {
    claude_md: fileLineStats(path.join(claudeDir, "CLAUDE.md")),
    settings_local: summarizeSettingsFile(path.join(claudeDir, "settings.local.json")),
    telemetry_failed_events_count: countFiles(path.join(claudeDir, "telemetry"), (name) => name.startsWith("1p_failed_events") && name.endsWith(".json")),
  };
}

function summarizeSettingsFile(filePath) {
  const settings = readJson(filePath);
  const permissions = objectOrEmpty(settings.permissions);
  return {
    exists: fs.existsSync(filePath),
    permissions_allow_count: Array.isArray(permissions.allow) ? permissions.allow.length : 0,
    permissions_ask_count: Array.isArray(permissions.ask) ? permissions.ask.length : 0,
    permissions_deny_count: Array.isArray(permissions.deny) ? permissions.deny.length : 0,
  };
}

function fileLineStats(filePath) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    return {
      exists: true,
      bytes: Buffer.byteLength(content, "utf8"),
      lines: content.length ? content.split(/\r?\n/).length : 0,
    };
  } catch {
    return { exists: false, bytes: 0, lines: 0 };
  }
}

function countFiles(root, predicate) {
  let count = 0;
  function visit(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(fullPath);
      else if (entry.isFile() && predicate(entry.name, fullPath)) count += 1;
    }
  }
  visit(root);
  return count;
}

async function makeReport(options) {
  const settings = readJson(path.join(options.claudeDir, "settings.json"));
  const statsCache = readJson(path.join(options.claudeDir, "stats-cache.json"));
  const settingsInfo = analyzeSettings(settings);
  const lifetimeUsage = statsCacheModelUsage(statsCache);
  const jsonlStats = await analyzeJsonl(options.claudeDir, options.days, options.maxFiles);
  const localState = analyzeLocalState(options.claudeDir);
  return {
    claude_dir: options.claudeDir,
    window_days: options.days,
    heuristics_target_version: TARGETS_VERSION,
    settings: settingsInfo,
    local_state: localState,
    stats_cache: {
      version: statsCache.version ?? null,
      totalSessions: statsCache.totalSessions ?? null,
      totalMessages: statsCache.totalMessages ?? null,
      lastComputedDate: statsCache.lastComputedDate ?? null,
      modelUsage: lifetimeUsage,
    },
    jsonl: summarizeJsonlStats(jsonlStats),
    recommendations: buildRecommendations(settingsInfo, jsonlStats, lifetimeUsage),
    additional_insights: buildAdditionalInsights(settingsInfo, jsonlStats, lifetimeUsage, localState),
    launch_profiles: launchProfiles(),
    settings_snippets: settingsSnippets(),
  };
}

function summarizeJsonlStats(stats) {
  return {
    files_scanned: stats.files_scanned,
    records_scanned: stats.records_scanned,
    records_in_window: stats.records_in_window,
    parse_errors: stats.parse_errors,
    session_count: stats.sessions.size,
    first_timestamp: stats.first_timestamp === null ? null : new Date(stats.first_timestamp).toISOString(),
    last_timestamp: stats.last_timestamp === null ? null : new Date(stats.last_timestamp).toISOString(),
    assistant_calls: stats.assistant_calls,
    sidechain_records: stats.sidechain_records,
    thinking_blocks: stats.thinking_blocks,
    image_blocks: stats.image_blocks,
    message_types: mapToObject(stats.message_types),
    permission_modes: mapToObject(stats.permission_modes),
    models: mapToObject(stats.models),
    model_tokens: mapValuesToObject(stats.model_tokens),
    speeds: mapToObject(stats.speeds),
    service_tiers: mapToObject(stats.service_tiers),
    top_cwd: topCounter(stats.cwd, 8),
    top_tools: topCounter(stats.tool_use, 15),
    top_tool_errors: topCounter(stats.tool_errors, 10),
    top_mcp_servers: topCounter(stats.mcp_servers, 10),
    top_skills: topCounter(stats.skills, 10),
    top_bash_commands: topCounter(stats.bash_commands, 15),
    bash_risks: mapToObject(stats.bash_risks),
  };
}

function printTextReport(report, options = {}) {
  const includeSnippets = options.snippets !== false;
  const lines = [];
  const push = (line = "") => lines.push(line);
  const priorityOrder = PRIORITY_ORDER;
  push("Claude Code Usage Advisor");
  push("=========================");
  push(`Claude dir: ${report.claude_dir}`);
  push(`JSONL window: ${report.window_days <= 0 ? "all history" : `${report.window_days} days`}`);
  push();

  // One severity-sorted list: a high-severity investigation must never sit below a medium recommendation.
  const findings = [...report.recommendations, ...(report.additional_insights || [])].sort(
    (a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9)
  );
  push("Findings");
  push("--------");
  for (const finding of findings) {
    push(`[${finding.priority}] ${finding.category}: ${finding.title}`);
    push(`  evidence: ${finding.evidence}`);
    push(`  action: ${finding.action}`);
  }
  push();

  push("Recommended launch profiles");
  push("---------------------------");
  for (const profile of report.launch_profiles) {
    push(`- ${profile.name}: \`${profile.command}\``);
    push(`  ${profile.use_when}`);
  }
  push();

  const settings = report.settings;
  push("Current settings");
  push("----------------");
  push(`model: ${settings.model || "(default/account recommended)"}`);
  push(`effortLevel: ${settings.effortLevel || "(not set)"}`);
  push(`permissions.defaultMode: ${settings.permissions_defaultMode || "(not set)"}`);
  push(`permissions allow/ask/deny: ${settings.permissions_allow_count}/${settings.permissions_ask_count}/${settings.permissions_deny_count}`);
  push(`autoMode configured: ${settings.autoMode_configured}`);
  push(`sandbox configured: ${settings.sandbox_configured}`);
  push(`env keys: ${settings.env_keys.length ? settings.env_keys.join(", ") : "(none)"}`);
  push();

  const jsonl = report.jsonl;
  push("Recent usage patterns");
  push("---------------------");
  push(`files=${jsonl.files_scanned}, records_in_window=${jsonl.records_in_window}, sessions=${jsonl.session_count}, assistant_calls=${jsonl.assistant_calls}`);
  if (jsonl.first_timestamp && jsonl.last_timestamp) push(`range=${jsonl.first_timestamp} -> ${jsonl.last_timestamp}`);
  push(`permission modes: ${JSON.stringify(jsonl.permission_modes)}`);
  push(`speeds: ${JSON.stringify(jsonl.speeds)}`);
  push();

  push("Top tools");
  for (const item of jsonl.top_tools.slice(0, 10)) push(`- ${item.name}: ${item.count}`);
  push();

  push("Top Bash command families");
  for (const item of jsonl.top_bash_commands.slice(0, 10)) push(`- ${item.name}: ${item.count}`);
  if (Object.keys(jsonl.bash_risks).length) push(`bash risk hits: ${JSON.stringify(jsonl.bash_risks)}`);
  push();

  const usageEntries = Object.entries(report.stats_cache.modelUsage || {}).sort((a, b) => freshTotal(b[1]) - freshTotal(a[1]));
  push("Lifetime model usage from stats-cache");
  push("-------------------------------------");
  if (usageEntries.length) {
    const totalFresh = usageEntries.reduce((sum, [, values]) => sum + freshTotal(values), 0);
    for (const [model, values] of usageEntries) {
      push(`${model}: fresh=${compactNumber(freshTotal(values))} (${pct(freshTotal(values), totalFresh)}), cache_read=${compactNumber(values.cache_read_input_tokens || 0)}, output=${compactNumber(values.output_tokens || 0)}`);
    }
  } else {
    push("No stats-cache modelUsage found.");
  }
  push("For per-model spend and billing blocks, use ccusage. This section is context, not accounting.");

  if (includeSnippets) {
    push();
    push("Settings snippets");
    push("-----------------");
    push("Balanced ~/.claude/settings.json baseline:");
    push(JSON.stringify(report.settings_snippets.balanced_user_settings, null, 2));
    push();
    push("Auto mode overlay, fill placeholders before using:");
    push(JSON.stringify(report.settings_snippets.auto_mode_overlay, null, 2));
    push();
    push("Optional subagent overlay:");
    push(JSON.stringify(report.settings_snippets.subagent_overlay, null, 2));
  }
  push();
  push(`Heuristics target ${report.heuristics_target_version}.`);
  return lines.join("\n");
}

function renderHtmlReport(report) {
  const settings = report.settings;
  const jsonl = report.jsonl;
  const priorityOrder = PRIORITY_ORDER;
  const findings = [...(report.recommendations || []), ...(report.additional_insights || [])].sort(
    (a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9)
  );
  const usageEntries = Object.entries(report.stats_cache.modelUsage || {}).sort((a, b) => freshTotal(b[1]) - freshTotal(a[1]));
  const totalFresh = usageEntries.reduce((sum, [, values]) => sum + freshTotal(values), 0);
  const generatedAt = new Date().toISOString();

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Claude Code Usage Insights</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --panel-2: #f0f3f6;
      --text: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee5;
      --accent: #2457c5;
      --high: #b42318;
      --medium: #9a6700;
      --low: #3b6f2a;
      --code: #0f172a;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #101317;
        --panel: #171b21;
        --panel-2: #20262e;
        --text: #eef2f7;
        --muted: #a8b0bb;
        --line: #303842;
        --accent: #8ab4ff;
        --code: #e7edf7;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }
    main {
      width: min(1180px, calc(100% - 32px));
      margin: 0 auto;
      padding: 36px 0 64px;
    }
    header {
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel);
    }
    h1, h2, h3 { line-height: 1.15; margin: 0; }
    h1 { font-size: clamp(30px, 4vw, 46px); letter-spacing: 0; }
    h2 { font-size: 24px; margin-bottom: 14px; }
    h3 { font-size: 17px; margin-bottom: 8px; }
    p { margin: 0; }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: var(--code);
    }
    pre {
      overflow: auto;
      padding: 14px;
      border-radius: 8px;
      background: var(--panel-2);
      border: 1px solid var(--line);
      font-size: 13px;
    }
    section {
      margin-top: 22px;
      padding: 22px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th, td {
      padding: 10px 8px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 650; }
    .lede { max-width: 760px; margin-top: 12px; color: var(--muted); font-size: 17px; }
    .meta { margin-top: 16px; color: var(--muted); font-size: 14px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }
    .metric, .card {
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel-2);
    }
    .metric .label { color: var(--muted); font-size: 13px; }
    .metric .value { display: block; margin-top: 4px; font-size: 22px; font-weight: 750; }
    .cards { display: grid; gap: 12px; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      border: 1px solid var(--line);
      margin-right: 8px;
    }
    .badge.high { color: var(--high); }
    .badge.medium { color: var(--medium); }
    .badge.low { color: var(--low); }
    .muted { color: var(--muted); }
    .split {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }
    .command {
      display: block;
      margin-top: 8px;
      padding: 10px;
      border-radius: 8px;
      background: var(--panel);
      border: 1px solid var(--line);
      overflow-wrap: anywhere;
    }
    details { margin-top: 12px; }
    summary { cursor: pointer; color: var(--accent); font-weight: 650; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Claude Code Usage Insights</h1>
      <p class="lede">A local, read-only report generated from Claude Code usage history. It includes model/settings recommendations, workflow diagnostics, and launch profiles.</p>
      <p class="meta">Generated: ${h(generatedAt)} | Claude dir: <code>${h(report.claude_dir)}</code> | Window: ${report.window_days <= 0 ? "all history" : `${h(String(report.window_days))} days`}</p>
      <div class="grid">
        ${metric("Sessions", jsonl.session_count)}
        ${metric("Assistant calls", compactNumber(jsonl.assistant_calls))}
        ${metric("Records", compactNumber(jsonl.records_in_window))}
        ${metric("Tool errors", compactNumber((jsonl.top_tool_errors || []).reduce((sum, item) => sum + item.count, 0)))}
        ${metric("Allow rules", settings.permissions_allow_count)}
        ${metric("Hooks", settings.hooks_command_count)}
      </div>
    </header>

    <section>
      <h2>Findings</h2>
      ${cards(findings)}
    </section>

    <section>
      <h2>Current Settings</h2>
      <div class="grid">
        ${metric("Model", settings.model || "default")}
        ${metric("Effort", settings.effortLevel || "not set")}
        ${metric("Permission mode", settings.permissions_defaultMode || "not set")}
        ${metric("Auto mode", settings.autoMode_configured ? "configured" : "missing")}
        ${metric("Sandbox", settings.sandbox_configured ? "configured" : "missing")}
        ${metric("Prompt cache 1h", settings.has_prompt_cache_1h ? "enabled" : "disabled")}
        ${metric("Env scrub", settings.has_subprocess_env_scrub ? "enabled" : "disabled")}
        ${metric("Global CLAUDE.md", report.local_state.claude_md.exists ? `${report.local_state.claude_md.lines} lines` : "missing")}
      </div>
    </section>

    <section>
      <h2>Launch Profiles</h2>
      <div class="cards">
        ${(report.launch_profiles || []).map((profile) => `
          <article class="card">
            <h3>${h(profile.name)}</h3>
            <p class="muted">${h(profile.use_when)}</p>
            <code class="command">${h(profile.command)}</code>
          </article>
        `).join("")}
      </div>
    </section>

    <section>
      <h2>Model Usage</h2>
      <table>
        <thead><tr><th>Model</th><th>Fresh tokens</th><th>Share</th><th>Cache read</th><th>Output</th></tr></thead>
        <tbody>
          ${usageEntries.map(([model, values]) => `
            <tr>
              <td><code>${h(model)}</code></td>
              <td>${h(compactNumber(freshTotal(values)))}</td>
              <td>${h(pct(freshTotal(values), totalFresh))}</td>
              <td>${h(compactNumber(values.cache_read_input_tokens || 0))}</td>
              <td>${h(compactNumber(values.output_tokens || 0))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </section>

    <section>
      <h2>Usage Patterns</h2>
      <div class="split">
        ${listTable("Top tools", jsonl.top_tools)}
        ${listTable("Top tool errors", jsonl.top_tool_errors)}
        ${listTable("Top Bash commands", jsonl.top_bash_commands)}
        ${listTable("Top MCP servers", jsonl.top_mcp_servers)}
        ${listTable("Top skills", jsonl.top_skills)}
        ${objectTable("Permission modes", jsonl.permission_modes)}
      </div>
      <details>
        <summary>Bash risk hits</summary>
        <pre>${h(JSON.stringify(jsonl.bash_risks, null, 2))}</pre>
      </details>
      <details>
        <summary>Risky allow examples</summary>
        <pre>${h(JSON.stringify(settings.risky_allow_examples, null, 2))}</pre>
      </details>
    </section>

    <section>
      <h2>Settings Snippets</h2>
      <details open>
        <summary>Balanced baseline</summary>
        <pre>${h(JSON.stringify(report.settings_snippets.balanced_user_settings, null, 2))}</pre>
      </details>
      <details>
        <summary>Auto mode overlay</summary>
        <pre>${h(JSON.stringify(report.settings_snippets.auto_mode_overlay, null, 2))}</pre>
      </details>
      <details>
        <summary>Subagent overlay</summary>
        <pre>${h(JSON.stringify(report.settings_snippets.subagent_overlay, null, 2))}</pre>
      </details>
    </section>
    <p class="meta">Heuristics target ${h(report.heuristics_target_version)}.</p>
  </main>
</body>
</html>`;
}

function metric(label, value) {
  return `<div class="metric"><span class="label">${h(label)}</span><span class="value">${h(String(value))}</span></div>`;
}

function cards(items) {
  if (!items || !items.length) return `<p class="muted">No items.</p>`;
  return `<div class="cards">${items.map((item) => `
    <article class="card">
      <h3><span class="badge ${h(item.priority)}">${h(item.priority)}</span>${h(item.category)}: ${h(item.title)}</h3>
      <p><strong>Evidence:</strong> ${h(item.evidence)}</p>
      <p><strong>Action:</strong> ${h(item.action)}</p>
    </article>
  `).join("")}</div>`;
}

function listTable(title, rows) {
  return `<div><h3>${h(title)}</h3><table><tbody>${(rows || []).map((row) => `<tr><td><code>${h(row.name)}</code></td><td>${h(String(row.count))}</td></tr>`).join("")}</tbody></table></div>`;
}

function objectTable(title, values) {
  return `<div><h3>${h(title)}</h3><table><tbody>${Object.entries(values || {}).map(([name, count]) => `<tr><td><code>${h(name)}</code></td><td>${h(String(count))}</td></tr>`).join("")}</tbody></table></div>`;
}

function h(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function familyTokenTotals(modelUsage) {
  const totals = {};
  for (const [model, values] of Object.entries(modelUsage || {})) {
    const family = modelFamily(model);
    if (!totals[family]) totals[family] = tokenStats();
    for (const field of TOKEN_FIELDS) totals[family][field] += values[field] || 0;
  }
  return totals;
}

function modelFamily(model) {
  const lowered = String(model).toLowerCase();
  if (lowered.includes("opus")) return "opus";
  if (lowered.includes("sonnet")) return "sonnet";
  if (lowered.includes("haiku")) return "haiku";
  if (model === "<synthetic>") return "synthetic";
  return "other";
}

function freshTotal(values) {
  return (values.input_tokens || 0) + (values.output_tokens || 0) + (values.cache_creation_input_tokens || 0);
}

function compactNumber(value) {
  let number = Number(value) || 0;
  for (const suffix of ["", "K", "M", "B", "T"]) {
    if (Math.abs(number) < 1000 || suffix === "T") {
      return suffix ? `${number.toFixed(1)}${suffix}` : String(Math.trunc(number));
    }
    number /= 1000;
  }
  return String(value);
}

function pct(part, total) {
  if (!total) return "0%";
  return `${((part / total) * 100).toFixed(1)}%`;
}

function increment(map, key, amount = 1) {
  map.set(key, (map.get(key) || 0) + amount);
}

function incrementIfString(map, value) {
  if (typeof value === "string" && value.length) increment(map, value);
}

function mapToObject(map) {
  return Object.fromEntries([...map.entries()]);
}

function mapValuesToObject(map) {
  return Object.fromEntries([...map.entries()].map(([key, value]) => [key, { ...value }]));
}

function mapValueSum(map) {
  let sum = 0;
  for (const value of map.values()) sum += value;
  return sum;
}

function topCounter(map, limit) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name, count]) => ({ name, count }));
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      console.log(usage());
      return 0;
    }
    const report = await makeReport(args);
    if (args.htmlPath) {
      fs.mkdirSync(path.dirname(args.htmlPath), { recursive: true });
      fs.writeFileSync(args.htmlPath, renderHtmlReport(report), "utf8");
    }
    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(printTextReport(report, { snippets: args.snippets }));
      if (args.htmlPath) console.log(`\nHTML report written to ${args.htmlPath}`);
    }
    return failOnExitCode(report, args.failOn);
  } catch (error) {
    console.error(`Error: ${error.message || error}`);
    console.error();
    console.error(usage());
    // 2, not 1: a broken invocation must stay distinguishable from a --fail-on policy hit.
    return 2;
  }
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  });
}

module.exports = {
  analyzeSettings,
  buildAdditionalInsights,
  buildRecommendations,
  commandRisks,
  emptyJsonlStats,
  failOnExitCode,
  familyTokenTotals,
  freshTotal,
  makeReport,
  modelFamily,
  parseArgs,
  permissionRisks,
  printTextReport,
  renderHtmlReport,
  shellCommandKey,
  splitShellish,
  statsCacheModelUsage,
};
