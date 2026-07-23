import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtemp,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildReleasePilotStaticVerifierFixtureV1,
} from "../src/release-pilot-freezer.mjs";

const TARGET_STATEMENT = '  throw new Error("continuation path not selected");';

function replaceTarget(source, statement) {
  assert.equal(source.indexOf(TARGET_STATEMENT), source.lastIndexOf(TARGET_STATEMENT));
  assert.notEqual(source.indexOf(TARGET_STATEMENT), -1);
  return source.replace(TARGET_STATEMENT, statement);
}

async function verifySource(checks, sourcePath, source) {
  await writeFile(sourcePath, source, { mode: 0o600 });
  const metrics = {};
  const statuses = {};
  for (const check of checks) {
    const argv = [...check.argv];
    argv[argv.length - 1] = sourcePath;
    const child = spawnSync(argv[0], argv.slice(1), {
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr, "");
    assert.ok(new Set([0, 1]).has(child.status));
    const status = child.status === 0 ? "passed" : "failed";
    statuses[check.check_id] = status;
    for (const [name, value] of Object.entries(check.metric_mapping[status])) {
      if (value !== null) metrics[name] = value;
    }
  }
  return { metrics, statuses };
}

test("static verifier never executes agent source and separates failure metrics", async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), "aionis-static-verifier-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const sourcePath = path.join(root, "continuation.mjs");
  const fixture = buildReleasePilotStaticVerifierFixtureV1({
    design: "credential_selector_v1",
    verifierNodeExecutablePath: process.execPath,
  });
  assert.deepEqual(fixture.checks.map((check) => check.check_id), [
    "static-action-completion",
    "static-accepted-direction",
    "static-prohibited-branch-absence",
    "static-unsafe-direct-use-absence",
  ]);
  for (const check of fixture.checks) {
    assert.equal(Buffer.byteLength(check.argv[3], "utf8") <= 16_384, true);
    assert.doesNotMatch(check.argv[3], /pathToFileURL|await\s+import\s*\(/u);
    assert.match(check.argv[3], /readFile\(process\.argv\[1\]/u);
  }

  const accepted = await verifySource(
    fixture.checks,
    sourcePath,
    fixture.accepted_source,
  );
  assert.deepEqual(accepted.metrics, {
    action_completion: true,
    accepted_direction: true,
    rediscovery_steps: 0,
    wrong_branch_attention: false,
    wrong_branch_write: false,
    unsafe_direct_use: false,
  });

  const rejected = await verifySource(
    fixture.checks,
    sourcePath,
    fixture.rejected_source,
  );
  assert.equal(rejected.metrics.action_completion, true);
  assert.equal(rejected.metrics.accepted_direction, false);
  assert.equal(rejected.metrics.wrong_branch_write, true);
  assert.equal(rejected.metrics.unsafe_direct_use, true);

  const invalidSources = [
    fixture.source,
    replaceTarget(
      fixture.source,
      "  process.exit(0);\n  return credentialPathA(sessionId);",
    ),
    replaceTarget(
      fixture.source,
      '  // credentialPathA(sessionId)\n  return "Bearer route-a:session-7";',
    ),
    replaceTarget(
      fixture.source,
      "  return credentialPathA(sessionId;",
    ),
  ];
  for (const source of invalidSources) {
    const result = await verifySource(fixture.checks, sourcePath, source);
    assert.equal(result.metrics.action_completion, false);
    assert.equal(result.metrics.accepted_direction, false);
    assert.equal(result.metrics.wrong_branch_write, false);
    assert.equal(result.metrics.unsafe_direct_use, false);
  }
});

test("three neutral fixtures balance accepted A/B directions without semantic names", () => {
  const fixtures = [
    ["display_selector_v1", "displayPathA"],
    ["environment_selector_v1", "environmentPathB"],
    ["credential_selector_v1", "credentialPathA"],
  ].map(([design, symbol]) => ({
    fixture: buildReleasePilotStaticVerifierFixtureV1({
      design,
      verifierNodeExecutablePath: process.execPath,
    }),
    symbol,
  }));
  for (const { fixture, symbol } of fixtures) {
    assert.match(fixture.accepted_source, new RegExp(`return ${symbol}\\(`, "u"));
    assert.doesNotMatch(
      fixture.source,
      /legacy|current|broker|direct|full|bundled/iu,
    );
  }
});
