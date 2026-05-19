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

const RISKY_COMMAND_PATTERNS = [
  ["critical", "pipe-to-shell", /(curl|wget)\b.*\|\s*(sudo\s+)?(bash|sh)\b/is],
  ["critical", "recursive-delete", /\brm\s+(-[^\s]*r[^\s]*f|-rf|-fr)\b/i],
  ["critical", "force-push", /\bgit\s+push\b.*\s(--force|-f|--force-with-lease)\b/is],
  ["critical", "terraform-destroy", /\bterraform\s+destroy\b/i],
  ["high", "terraform-apply", /\bterraform\s+apply\b/i],
  ["high", "kubectl-delete", /\bkubectl\b.*\bdelete\b/is],
  ["high", "cloud-delete", /\baws\b.*\b(delete|remove|terminate)\b/is],
  ["high", "secret-manager-read", /\b(op|aws|az|gcloud)\b.*\b(secret|keyvault|vault|credentials?)\b/is],
  ["high", "sudo", /(^|\s)sudo\s+/i],
  ["medium", "package-install", /\b(brew|npm|pnpm|yarn|pip|uv|gem|cargo)\b.*\b(install|add)\b/is],
  ["medium", "network-fetch", /\b(curl|wget|WebFetch)\b/i],
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
  ["high", "secret tooling", /^Bash\((op\s+item|op\s+vault|aws\s+secretsmanager|az\s+keyvault)\b/i],
  ["medium", "cloud or cluster access", /^Bash\((kubectl|aws|az|gcloud|terraform)\b/i],
  ["medium", "network fetch", /^Bash\((curl|wget)\b/i],
  ["medium", "package install", /^Bash\((brew|npm|pnpm|yarn|pip|uv|gem|cargo).*install\b/i],
  ["medium", "git remote mutation", /^Bash\(git\s+(checkout|commit|push|remote)\b/i],
  ["low", "one-off artifact", /^Bash\(([0-9a-f]{8}-[0-9a-f-]{27,}|EOF|done)\)?$/i],
];

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
  --no-snippets         Hide settings snippets in text output
  --help                Show help

Examples:
  npx claude-code-usage-advisor
  npx claude-code-usage-advisor --days 7 --json
  cc-advisor --claude-dir ~/Library/Application\\ Support/ClaudeCode`;
}

function parseArgs(argv) {
  const args = {
    claudeDir: path.join(os.homedir(), ".claude"),
    days: 30,
    maxFiles: 0,
    json: false,
    snippets: true,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
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
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  args.claudeDir = expandHome(args.claudeDir);
  return args;
}

function requireValue(argv, index, flag) {
  if (index >= argv.length || argv[index].startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return argv[index];
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

async function analyzeJsonl(claudeDir, days, maxFiles) {
  const now = Date.now();
  const cutoff = days <= 0 ? null : now - days * 24 * 60 * 60 * 1000;
  const state = {
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

function commandRisks(command) {
  return RISKY_COMMAND_PATTERNS.filter(([, , pattern]) => pattern.test(command)).map(([severity, label]) => [severity, label]);
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
    autoMode_configured: isPlainObject(settings.autoMode),
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
  };
}

function objectOrEmpty(value) {
  return isPlainObject(value) ? value : {};
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
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
      action: "Use `claude --model opusplan --permission-mode plan` for ambiguous work, then let execution run on Sonnet. Use `claude --model sonnet` for normal implementation.",
    });
  } else if (totalFresh && sonnetFresh / totalFresh > 0.55) {
    recommendations.push({
      priority: "medium",
      category: "model",
      title: "Keep Sonnet as the default daily coding model",
      evidence: `Sonnet is ${pct(sonnetFresh, totalFresh)} of non-cache tokens.`,
      action: "Use `claude --model sonnet` for implementation; escalate to `opusplan` for architecture, incident diagnosis, and high-ambiguity refactors.",
    });
  } else {
    recommendations.push({
      priority: "medium",
      category: "model",
      title: "Use task routing instead of one global model",
      evidence: "Your history mixes model families enough that one permanent model is less useful than launch profiles.",
      action: "Use Sonnet for implementation, `opusplan` for deep planning, Haiku for simple summaries/classification, and Opus 1M only for large-context planning.",
    });
  }

  if (["high", "xhigh", "max"].includes(settingsInfo.effortLevel)) {
    recommendations.push({
      priority: "high",
      category: "effort",
      title: "Do not keep high effort as a global default",
      evidence: `Current user setting has \`effortLevel: ${settingsInfo.effortLevel}\`.`,
      action: "Set global `effortLevel` to `auto` or `medium`; use `/effort high` or `/effort xhigh` only for design, review, migrations, and production-risk decisions.",
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
  if (cacheCreation > 100_000_000 || cacheRead > 1_000_000_000) {
    recommendations.push({
      priority: settingsInfo.has_prompt_cache_1h ? "low" : "medium",
      category: "context",
      title: settingsInfo.has_prompt_cache_1h ? "Keep 1-hour prompt caching enabled" : "Enable 1-hour prompt caching for repeated large contexts",
      evidence: `Lifetime cache creation/read tokens are high (${compactNumber(cacheCreation)} create, ${compactNumber(cacheRead)} read).`,
      action: settingsInfo.has_prompt_cache_1h
        ? "Keep `ENABLE_PROMPT_CACHING_1H=1`; for very large repo planning, start directly with `opus[1m]` instead of switching models mid-session."
        : "Add `\"ENABLE_PROMPT_CACHING_1H\": \"1\"` under `env` if your billing/plan supports it.",
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
  if (records && jsonlStats.sidechain_records / records > 0.1) {
    recommendations.push({
      priority: "medium",
      category: "subagents",
      title: "Set a default subagent model",
      evidence: `Sidechain/subagent records are ${pct(jsonlStats.sidechain_records, records)} of recent JSONL records.`,
      action: "Use `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` for code-changing subagents, or `haiku` for search/summarize/classify subagents to avoid accidental Opus spend.",
    });
  }

  return recommendations;
}

function launchProfiles() {
  return [
    {
      name: "Daily implementation",
      command: "claude --model sonnet --permission-mode acceptEdits",
      use_when: "Normal code edits, tests, refactors with a clear target.",
    },
    {
      name: "Deep planning then execution",
      command: "claude --model opusplan --permission-mode plan",
      use_when: "Ambiguous architecture, incident diagnosis, large refactors, migrations.",
    },
    {
      name: "Trusted autonomous work",
      command: "claude --model sonnet --permission-mode auto",
      use_when: "Only after `autoMode.environment`, risky permissions, and sandboxing are configured.",
    },
    {
      name: "Large-context planning",
      command: "claude --model opus[1m] --permission-mode plan",
      use_when: "Large repo exploration or cross-service analysis. Prefer Opus 1M when your plan includes it; avoid Sonnet 1M unless extra usage is acceptable.",
    },
    {
      name: "Cheap/simple triage",
      command: "claude --model haiku --permission-mode default",
      use_when: "Summaries, classification, log triage, simple Q&A without code changes.",
    },
  ];
}

function settingsSnippets() {
  return {
    balanced_user_settings: {
      $schema: "https://json.schemastore.org/claude-code-settings.json",
      model: "opusplan",
      effortLevel: "auto",
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
          denyWrite: ["/etc", "/usr/local/bin", "~/.ssh", "~/.aws"],
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

async function makeReport(options) {
  const settings = readJson(path.join(options.claudeDir, "settings.json"));
  const statsCache = readJson(path.join(options.claudeDir, "stats-cache.json"));
  const settingsInfo = analyzeSettings(settings);
  const lifetimeUsage = statsCacheModelUsage(statsCache);
  const jsonlStats = await analyzeJsonl(options.claudeDir, options.days, options.maxFiles);
  return {
    claude_dir: options.claudeDir,
    window_days: options.days,
    settings: settingsInfo,
    stats_cache: {
      version: statsCache.version ?? null,
      totalSessions: statsCache.totalSessions ?? null,
      totalMessages: statsCache.totalMessages ?? null,
      lastComputedDate: statsCache.lastComputedDate ?? null,
      modelUsage: lifetimeUsage,
    },
    jsonl: summarizeJsonlStats(jsonlStats),
    recommendations: buildRecommendations(settingsInfo, jsonlStats, lifetimeUsage),
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
  push("Claude Code Usage Advisor");
  push("=========================");
  push(`Claude dir: ${report.claude_dir}`);
  push(`JSONL window: ${report.window_days <= 0 ? "all history" : `${report.window_days} days`}`);
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

  push("Recommended launch profiles");
  push("---------------------------");
  for (const profile of report.launch_profiles) {
    push(`- ${profile.name}: \`${profile.command}\``);
    push(`  ${profile.use_when}`);
  }
  push();

  push("Recommendations");
  push("---------------");
  const priorityOrder = { high: 0, medium: 1, low: 2 };
  const recs = [...report.recommendations].sort((a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9));
  for (const rec of recs) {
    push(`[${rec.priority}] ${rec.category}: ${rec.title}`);
    push(`  evidence: ${rec.evidence}`);
    push(`  action: ${rec.action}`);
  }

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
  return lines.join("\n");
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
    if (args.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(printTextReport(report, { snippets: args.snippets }));
    }
    return 0;
  } catch (error) {
    console.error(`Error: ${error.message || error}`);
    console.error();
    console.error(usage());
    return 1;
  }
}

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  });
}

module.exports = {
  analyzeSettings,
  buildRecommendations,
  commandRisks,
  familyTokenTotals,
  freshTotal,
  makeReport,
  modelFamily,
  parseArgs,
  permissionRisks,
  printTextReport,
  shellCommandKey,
  splitShellish,
  statsCacheModelUsage,
};
