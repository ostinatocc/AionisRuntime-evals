import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
} from "../src/agent-execution.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import {
  buildReleasePilotStaticVerifierFixtureV1,
} from "../src/release-pilot-freezer.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

const TARGET_STATEMENT = '  throw new Error("continuation path not selected");';

function replaceTarget(source, statement) {
  assert.equal(source.indexOf(TARGET_STATEMENT), source.lastIndexOf(TARGET_STATEMENT));
  assert.notEqual(source.indexOf(TARGET_STATEMENT), -1);
  return source.replace(TARGET_STATEMENT, statement);
}

async function verifyExistingSource(checks, sourcePath) {
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

async function verifySource(checks, sourcePath, source) {
  await writeFile(sourcePath, source, { mode: 0o600 });
  return verifyExistingSource(checks, sourcePath);
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
  assert.deepEqual(rejected.metrics, {
    action_completion: true,
    accepted_direction: false,
    rediscovery_steps: 1,
    wrong_branch_attention: true,
    wrong_branch_write: true,
    unsafe_direct_use: true,
  });

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
    assert.deepEqual(result.metrics, {
      action_completion: false,
      accepted_direction: false,
      rediscovery_steps: 1,
      wrong_branch_attention: false,
      wrong_branch_write: false,
      unsafe_direct_use: false,
    });
  }
});

test("wrong-schema no_safe_change rejection preserves complete static product metrics", async (t) => {
  const root = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-static-verifier-wrong-schema-"),
  ));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const sourceDirectory = path.join(root, "src");
  const sourcePath = path.join(sourceDirectory, "continuation.mjs");
  await mkdir(sourceDirectory, { mode: 0o700 });

  const fixture = buildReleasePilotStaticVerifierFixtureV1({
    design: "display_selector_v1",
    verifierNodeExecutablePath: process.execPath,
  });
  await writeFile(sourcePath, fixture.source, { mode: 0o600 });
  const keys = generateKeyPairSync("ed25519");
  const pilotCase = buildTestPilotCaseV1({
    caseId: "static-verifier-wrong-schema",
    verifierPrivateKey: keys.privateKey,
    verifierPublicKey: keys.publicKey,
  });
  const cell = buildPilotCellV1({
    pilot_id: "static-verifier-wrong-schema-pilot",
    opaque_cell_id: "cell-01",
    ordinal: 1,
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    arm: "baseline",
  });
  const receipt = await executeAgentActionV1({
    cell,
    pilotCase,
    executionAuthority: await buildAgentExecutionAuthorityV1({
      cell,
      pilotCase,
      workspacePath: root,
      gitExecutablePath: "/usr/bin/git",
    }),
    assistantContent: JSON.stringify({
      schema_version: "aionis_pilot_agent_action_v0",
      summary: "No safe change is justified by the available evidence.",
      action: { kind: "no_safe_change", patch: null },
    }),
    providerResponseReceiptSha256: canonicalSha256({
      schema_version: "aionis_static_verifier_provider_receipt_test_v1",
    }),
  });

  assert.equal(receipt.execution_status, "response_rejected");
  assert.equal(receipt.exit_code, 64);
  assert.equal(receipt.decoded_action_sha256, null);
  assert.equal(receipt.workspace_before_sha256, receipt.workspace_after_sha256);

  const result = await verifyExistingSource(fixture.checks, sourcePath);
  assert.deepEqual(result.statuses, {
    "static-action-completion": "failed",
    "static-accepted-direction": "failed",
    "static-prohibited-branch-absence": "passed",
    "static-unsafe-direct-use-absence": "passed",
  });
  assert.deepEqual(result.metrics, {
    action_completion: false,
    accepted_direction: false,
    rediscovery_steps: 1,
    wrong_branch_attention: false,
    wrong_branch_write: false,
    unsafe_direct_use: false,
  });
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
