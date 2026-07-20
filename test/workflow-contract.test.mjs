import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = fs.readFileSync(path.join(ROOT, ".github/workflows/bounded-soak.yml"), "utf8");
const CI_WORKFLOW = fs.readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8");
const ACTION_REFS = new Set(["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"]);
const assertPinnedActions = (source, count) => { const refs = [...source.matchAll(/\buses:\s*([^\s,}]+)/g)].map((match) => match[1]); assert.equal(refs.length, count); for (const ref of refs) assert.equal(ACTION_REFS.has(ref), true, `untrusted or mutable workflow action: ${ref}`); };

test("authority CI is a pinned read-only push and pull-request required check", () => {
  assert.match(CI_WORKFLOW, /^  push:\n    branches:\n      - main$/m);
  assert.match(CI_WORKFLOW, /^  pull_request:\n    branches:\n      - main$/m);
  assert.doesNotMatch(CI_WORKFLOW, /workflow_dispatch:|schedule:|secrets\.|contents: write|continue-on-error/);
  assert.match(CI_WORKFLOW, /^permissions:\n  contents: read$/m);
  assertPinnedActions(CI_WORKFLOW, 2);
  assert.match(CI_WORKFLOW, /persist-credentials: false/);
  assert.match(CI_WORKFLOW, /npm ci --ignore-scripts/);
  assert.match(CI_WORKFLOW, /npm test/);
  assert.match(CI_WORKFLOW, /npm run -s validate:fixture/);
  assert.match(CI_WORKFLOW, /git diff --exit-code/);
  assert.match(CI_WORKFLOW, /git status --porcelain/);
});

test("bounded soak workflow is manual-only with read-only default permissions", () => {
  const triggerBlock = WORKFLOW.match(/^on:\n([\s\S]*?)^permissions:/m)?.[1] ?? "";
  assert.match(triggerBlock, /^  workflow_dispatch:/m);
  for (const forbidden of ["push:", "pull_request:", "schedule:", "workflow_call:"]) {
    assert.equal(triggerBlock.includes(forbidden), false, `unexpected trigger ${forbidden}`);
  }
  assert.match(WORKFLOW, /^permissions:\n  contents: read$/m);
});

test("workflow pins actions, uses Node 24 lock, and disables checkout credentials", () => {
  assertPinnedActions(WORKFLOW, 4);
  assert.match(WORKFLOW, /node-version-file: \.nvmrc/);
  assert.match(WORKFLOW, /persist-credentials: false/);
  assert.match(WORKFLOW, /npm ci --ignore-scripts/);
});

test("paid phase needs explicit input, protected environment, and persistent self-hosted runner", () => {
  assert.match(WORKFLOW, /authorize_paid_execution:[\s\S]*?default: false/);
  assert.match(WORKFLOW, /environment:\n      name: bounded-soak/);
  assert.match(WORKFLOW, /- self-hosted/);
  assert.match(WORKFLOW, /- aionis-soak-persistent/);
  assert.match(WORKFLOW, /timeout-minutes: 2280/);
  assert.match(WORKFLOW, /--approval RUN_EXACT_FROZEN_BOUNDED_SOAK/);
  assert.match(WORKFLOW, /--execute/);
});

test("unimplemented publisher retains no write authority", () => {
  assert.doesNotMatch(WORKFLOW, /contents: write|packages: write|docker\/login-action|push: true/);
  assert.match(WORKFLOW, /evidence-publisher:[\s\S]*?needs: paid-preflight/);
  assert.match(WORKFLOW, /evidence-publisher:[\s\S]*?runs-on: ubuntu-24\.04/);
  assert.match(WORKFLOW, /evidence-publisher:[\s\S]*?name: bounded-soak-publisher/);
  assert.match(WORKFLOW, /EVIDENCE_PUBLISHER_UNAVAILABLE/);
});

test("workflow contains no fail-open or provider-value plumbing", () => {
  for (const forbidden of ["continue-on-error", "|| true", "set -x", "secrets.", "push:", "pull_request:", "schedule:"]) {
    assert.equal(WORKFLOW.includes(forbidden), false, `workflow contains forbidden token ${forbidden}`);
  }
  assert.match(WORKFLOW, /config\/v0\.3\.12-release-lock\.json/);
});
