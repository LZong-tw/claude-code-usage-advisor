const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");

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

test("builds a report from fixture data", async () => {
  const claudeDir = path.join(__dirname, "fixtures", "sample-claude");
  const report = await advisor.makeReport({ claudeDir, days: 0, maxFiles: 0 });
  assert.equal(report.settings.effortLevel, "xhigh");
  assert.equal(report.jsonl.session_count, 1);
  assert.equal(report.jsonl.top_tools[0].name, "Bash");
  assert.ok(report.recommendations.some((rec) => rec.category === "model"));
  assert.ok(report.recommendations.some((rec) => rec.title.includes("autoMode.environment")));
});
