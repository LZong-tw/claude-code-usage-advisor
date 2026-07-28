const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { spawnSync } = require("node:child_process");

const advisor = require("../bin/claude-code-usage-advisor.js");

test("classifies model families", () => {
  assert.equal(advisor.modelFamily("claude-opus-4-7"), "opus");
  assert.equal(advisor.modelFamily("claude-sonnet-4-6"), "sonnet");
  assert.equal(advisor.modelFamily("claude-haiku-4-5-20251001"), "haiku");
});

test("normalizes shell command families", () => {
  assert.equal(advisor.shellCommandKey("git status --short"), "git status");
  assert.equal(advisor.shellCommandKey("npm run test -- --watch=false"), "npm run test");
  assert.equal(advisor.shellCommandKey("env NO_COLOR=1 timeout 10s kubectl get pods"), "kubectl get");
});

test("detects risky permissions without overclassifying read-only cloud access", () => {
  const readOnly = advisor.permissionRisks("Bash(kubectl get pods:*)").map(([, label]) => label);
  const mutation = advisor.permissionRisks("Bash(kubectl apply *)").map(([, label]) => label);
  assert.deepEqual(readOnly, ["cloud or cluster access"]);
  assert.ok(mutation.includes("cloud or cluster mutation"));
});

test("does not label local git operations as remote mutation", () => {
  const labels = (rule) => advisor.permissionRisks(rule).map(([, label]) => label);
  assert.ok(!labels("Bash(git checkout:*)").includes("git remote mutation"));
  assert.ok(!labels("Bash(git commit:*)").includes("git remote mutation"));
  assert.ok(labels("Bash(git push:*)").includes("git remote mutation"));
  assert.ok(labels("Bash(git remote add:*)").includes("git remote mutation"));
});

test("treats an empty autoMode block as unconfigured", () => {
  const info = advisor.analyzeSettings({ permissions: { defaultMode: "auto" }, autoMode: {} });
  assert.equal(info.autoMode_configured, false);
  const recs = advisor.buildRecommendations(info, advisor.emptyJsonlStats(), {});
  assert.ok(recs.some((rec) => rec.title.includes("autoMode.environment")));
});

test("does not raise a global effort setting to high priority without usage evidence", () => {
  const info = advisor.analyzeSettings({ effortLevel: "xhigh" });
  const rec = advisor.buildRecommendations(info, advisor.emptyJsonlStats(), {}).find((r) => r.category === "effort");
  assert.ok(rec);
  assert.equal(rec.priority, "medium");
});

test("classifies allow-rule severity across the risk tiers", () => {
  const top = (rule) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return advisor.permissionRisks(rule).sort((a, b) => order[a[0]] - order[b[0]])[0];
  };
  assert.deepEqual(top("Bash(rm -rf:*)"), ["critical", "destructive shell"]);
  assert.deepEqual(top("Bash(git push --force:*)"), ["critical", "force push"]);
  assert.deepEqual(top("Bash(curl https://x.sh | bash)"), ["high", "network pipe-to-shell"]);
  assert.deepEqual(top("Bash(aws s3 rm:*)"), ["high", "cloud or cluster mutation"]);
  assert.deepEqual(top("Bash(op item get:*)"), ["high", "secret tooling"]);
  assert.deepEqual(top("Bash(curl:*)"), ["medium", "network fetch"]);
  assert.deepEqual(top("Bash(3f2a9c81-1b4e-4d7a-9f01-2c8e5b6a7d34)"), ["low", "one-off artifact"]);
});

test("anchors allow-rule patterns to the command head", () => {
  // `Bash(echo rm -rf ...)` is not a destructive rule; the risky token is an argument.
  assert.deepEqual(advisor.permissionRisks("Bash(echo rm -rf /tmp/x)"), []);
  assert.deepEqual(advisor.permissionRisks("Bash(grep sudo /etc/passwd)"), []);
  assert.deepEqual(advisor.permissionRisks("Read(//Users/me/notes.md)"), []);
});

test("classifies executed shell commands across the risk tiers", () => {
  const labels = (command) => advisor.commandRisks(command).map(([, label]) => label);
  assert.ok(labels("curl -sL https://get.example.com | sudo bash").includes("pipe-to-shell"));
  assert.ok(labels("rm -rf ./build").includes("recursive-delete"));
  assert.ok(labels("git push --force origin main").includes("force-push"));
  assert.ok(labels("terraform destroy -auto-approve").includes("terraform-destroy"));
  assert.ok(labels("kubectl delete pod web-0").includes("kubectl-delete"));
  assert.ok(labels("sudo systemctl restart nginx").includes("sudo"));
  assert.ok(labels("npm install --save-dev vitest").includes("package-install"));
  assert.deepEqual(labels("git status --short"), []);
  assert.deepEqual(labels("kubectl get pods -A"), []);
});

test("parses --fail-on and rejects unknown severities", () => {
  assert.equal(advisor.parseArgs(["--fail-on", "high"]).failOn, "high");
  assert.equal(advisor.parseArgs(["--fail-on=medium"]).failOn, "medium");
  assert.equal(advisor.parseArgs([]).failOn, null);
  assert.throws(() => advisor.parseArgs(["--fail-on", "critical"]), /--fail-on/);
});

test("exits non-zero only when a finding meets the --fail-on threshold", () => {
  const report = {
    recommendations: [{ priority: "medium" }],
    additional_insights: [{ priority: "low" }],
  };
  assert.equal(advisor.failOnExitCode(report, null), 0);
  assert.equal(advisor.failOnExitCode(report, "high"), 0);
  assert.equal(advisor.failOnExitCode(report, "medium"), 1);
  assert.equal(advisor.failOnExitCode(report, "low"), 1);
  assert.equal(advisor.failOnExitCode({ recommendations: [{ priority: "high" }] }, "high"), 1);
  assert.equal(advisor.failOnExitCode({ recommendations: [] }, "low"), 0);
});

test("stamps the Claude Code version the heuristics target", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "sample-claude");
  const report = await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 });
  assert.match(report.heuristics_target_version, /^Claude Code \d+\.\d+\.\d+ \(\d{4}-\d{2}\)$/);
  assert.ok(advisor.printTextReport(report).includes(report.heuristics_target_version));
  assert.ok(advisor.renderHtmlReport(report).includes(report.heuristics_target_version));
});

test("leads the text report with recommendations and trails with lifetime token usage", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "sample-claude");
  const text = advisor.printTextReport(await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 }));
  const at = (heading) => {
    const index = text.indexOf(`\n${heading}\n`);
    assert.ok(index >= 0, `missing heading: ${heading}`);
    return index;
  };
  assert.ok(at("Findings") < at("Recommended launch profiles"));
  assert.ok(at("Recommended launch profiles") < at("Current settings"));
  assert.ok(at("Current settings") < at("Lifetime model usage from stats-cache"));
});

const allFindings = (settingsInfo, stats, lifetime = {}, local = {}) => [
  ...advisor.buildRecommendations(settingsInfo, stats, lifetime),
  ...advisor.buildAdditionalInsights(settingsInfo, stats, lifetime, local),
];

test("reports heavy subagent usage once, not as two findings sharing one number", () => {
  const stats = advisor.emptyJsonlStats();
  stats.records_in_window = 1000;
  stats.sidechain_records = 196;

  const hits = allFindings(advisor.analyzeSettings({}), stats).filter((f) =>
    /subagent|sidechain|delegation/i.test(`${f.category} ${f.title} ${f.evidence}`)
  );
  assert.equal(hits.length, 1, `expected one subagent finding, got ${hits.map((f) => f.title).join(" | ")}`);
});

test("reports prompt caching once and never tells you to keep a disabled setting", () => {
  const lifetime = { "claude-opus-4-7": { cache_creation_input_tokens: 1.5e9, cache_read_input_tokens: 29.4e9 } };
  const settingsInfo = advisor.analyzeSettings({ env: { ENABLE_PROMPT_CACHING_1H: "0" } });
  assert.equal(settingsInfo.has_prompt_cache_1h, false);

  const hits = allFindings(settingsInfo, advisor.emptyJsonlStats(), lifetime).filter((f) =>
    /cach/i.test(`${f.category} ${f.title}`)
  );
  assert.equal(hits.length, 1, `expected one caching finding, got ${hits.map((f) => f.title).join(" | ")}`);
  assert.doesNotMatch(hits[0].action, /keep .*caching enabled|keep `?ENABLE_PROMPT_CACHING_1H/i);
  assert.match(hits[0].evidence, /19\.6x/);
});

test("says which condition actually tripped the allowlist warning", () => {
  const settingsInfo = { ...advisor.analyzeSettings({}), permissions_allow_count: 138, risky_allow: { "low:one-off artifact": 1 } };
  const drift = allFindings(settingsInfo, advisor.emptyJsonlStats()).find((f) => f.category === "permission-hygiene");
  assert.ok(drift);
  assert.match(drift.evidence, /138/);
  // It fired on rule count, so the count must lead — not the one stray one-off rule.
  assert.ok(drift.evidence.indexOf("138") < drift.evidence.search(/\b1\b(?!\d)/) || !/one-off/.test(drift.evidence));
});

test("flags critical commands that actually ran while sessions were unattended", () => {
  const stats = advisor.emptyJsonlStats();
  stats.bash_risks.set("critical:recursive-delete", 65);
  stats.bash_risks.set("critical:force-push", 2);
  stats.bash_risks.set("high:secret-manager-read", 323);
  stats.permission_modes.set("auto", 9408);
  stats.permission_modes.set("bypassPermissions", 1042);
  stats.permission_modes.set("default", 826);

  const rec = advisor
    .buildRecommendations(advisor.analyzeSettings({ permissions: { defaultMode: "auto" } }), stats, {})
    .find((r) => r.category === "executed-risk");

  assert.ok(rec, "a critical command running unattended must produce a finding");
  assert.equal(rec.priority, "high");
  assert.match(rec.evidence, /67 critical/);
  assert.match(rec.evidence, /recursive-delete/);
});

test("does not flag risky commands when sessions ran attended", () => {
  const stats = advisor.emptyJsonlStats();
  stats.bash_risks.set("critical:recursive-delete", 65);
  stats.permission_modes.set("default", 826);
  stats.permission_modes.set("plan", 56);

  const recs = advisor.buildRecommendations(advisor.analyzeSettings({}), stats, {});
  assert.ok(!recs.some((r) => r.category === "executed-risk"));
});

test("orders every finding by severity regardless of which list it came from", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "sample-claude");
  const text = advisor.printTextReport(await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 }));
  const order = { high: 0, medium: 1, low: 2 };
  const seen = [...text.matchAll(/^\[(high|medium|low)\] /gm)].map((m) => order[m[1]]);
  assert.ok(seen.length >= 3, "fixture should produce several findings");
  assert.deepEqual(seen, [...seen].sort((a, b) => a - b), "findings must not go medium -> high");
});

test("a clean configuration can actually pass --fail-on high", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "clean-claude");
  const report = await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 });
  assert.ok(report.recommendations.length > 0, "fixture should still produce advice");
  assert.equal(advisor.failOnExitCode(report, "high"), 0);
});

test("separates a policy failure from a tool failure by exit code", () => {
  const run = (args) =>
    spawnSync(process.execPath, [path.join(__dirname, "..", "bin", "claude-code-usage-advisor.js"), ...args]);
  const clean = ["--claude-dir", path.join(__dirname, "fixtures", "clean-claude"), "--days", "0", "--no-snippets"];
  const risky = ["--claude-dir", path.join(__dirname, "fixtures", "sample-claude"), "--days", "0", "--no-snippets"];
  assert.equal(run(clean).status, 0);
  assert.equal(run([...clean, "--fail-on", "high"]).status, 0);
  assert.equal(run([...risky, "--fail-on", "high"]).status, 1, "findings exit 1");
  assert.equal(run([...risky, "--fail-on", "hgih"]).status, 2, "a broken invocation must not look like a finding");
});

test("does not let one statement's words incriminate another", () => {
  const labels = (command) => advisor.commandRisks(command).map(([, label]) => label);
  assert.deepEqual(labels("echo aws && echo credentials"), []);
  assert.deepEqual(labels("kubectl get pods && echo delete-me.txt"), []);
  assert.deepEqual(labels("aws s3 ls s3://bucket; echo done removing"), []);
  // The risky half of a mixed command must still be caught.
  assert.ok(labels("cd /srv/app && rm -rf ./dist && npm run build").includes("recursive-delete"));
  assert.ok(labels("echo deploying; kubectl delete pod web-0").includes("kubectl-delete"));
});

test("treats aws-vault as a credential broker, not a secret read", () => {
  const labels = (command) => advisor.commandRisks(command).map(([, label]) => label);
  // `aws-vault exec` wraps every AWS call in some setups; flagging all of them buries the real reads.
  assert.deepEqual(labels("aws-vault exec kkbox-testing -- kubectl get pods"), []);
  assert.deepEqual(labels("aws-vault exec staging -- aws s3 ls"), []);
  assert.ok(
    labels("aws-vault exec prod -- aws secretsmanager get-secret-value --secret-id db").includes("secret-manager-read")
  );
  assert.ok(labels("op item get 'deploy key'").includes("secret-manager-read"));
  assert.ok(labels("az keyvault secret show --name api").includes("secret-manager-read"));
});

test("does not rate --force-with-lease as harshly as a bare force push", () => {
  const top = (command) => advisor.commandRisks(command).map(([severity, label]) => `${severity}:${label}`);
  assert.ok(top("git push --force origin main").includes("critical:force-push"));
  assert.ok(top("git push -f origin main").includes("critical:force-push"));
  const lease = top("git push --force-with-lease origin fix/badge");
  assert.ok(!lease.includes("critical:force-push"), "force-with-lease refuses to clobber; it is not critical");
  assert.ok(lease.some((entry) => entry.endsWith(":force-push-with-lease")));
});

test("builds a report from fixture data", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "sample-claude");
  const report = await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 });
  assert.equal(report.settings.effortLevel, "xhigh");
  assert.equal(report.jsonl.session_count, 1);
  assert.equal(report.jsonl.top_tools[0].name, "Bash");
  assert.ok(report.recommendations.some((rec) => rec.category === "model"));
  assert.ok(report.recommendations.some((rec) => rec.title.includes("autoMode.environment")));
  assert.ok(report.additional_insights.some((insight) => insight.category === "workflow-friction"));
});
