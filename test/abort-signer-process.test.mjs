import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, open, readdir, realpath, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildAgentModelInputV1 } from "../src/agent-action.mjs";
import { deepSeekCanonicalRequestSha256V1 } from "../src/deepseek-provider.mjs";
import { runSealedPilotAbortSignerProcessV1 } from "../src/final-signer-process.mjs";
import {
  buildOwnerCleanupReceiptV1,
  buildResourceCleanupReceiptV1,
} from "../src/pilot-run-event-contract.mjs";
import { verifySealedPilotRunV1 } from "../src/sealed-pilot-run.mjs";
import { canonicalSha256 } from "../src/canonical.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import {
  TEST_RUNNER_KEYS_V1,
  beginTestPilotRunLedgerV1,
  buildTestPilotPlanV1,
} from "./support/pilot-plan-fixture.mjs";

test("formal abort signer replays a burned partial ledger and seals it as non-resumable", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-abort-signer-")));
  const keyPath = path.join(root, "runner-key.der");
  const verifierKeys = [
    generateKeyPairSync("ed25519"),
    generateKeyPairSync("ed25519"),
    generateKeyPairSync("ed25519"),
  ];
  const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
    caseId: `abort-signer-${index + 1}`,
    verifierPublicKey: keys.publicKey,
  }));
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: "pilot-formal-abort-signer-test",
  });
  try {
    await writeFile(keyPath, TEST_RUNNER_KEYS_V1.privateKey.export({
      format: "der",
      type: "pkcs8",
    }), { mode: 0o600 });
    const { ledger, executionManifest } =
      await beginTestPilotRunLedgerV1({ authorityRoot: root, plan });
    const cell = plan.schedule[0];
    const pilotCase = cases.find((candidate) => candidate.case_id === cell.case_id);
    assert.ok(pilotCase);
    const preparedArm = {
      schema_version: "aionis_pilot_prepared_arm_v1",
      cell,
      arm: "baseline",
      observation_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
      model_context: null,
      runtime: null,
    };
    const agentModelInput = buildAgentModelInputV1({
      pilotCase,
      preparedArm,
    });
    await ledger.recordCellPreparation({
      cell,
      pilotCase,
      preparedArm,
      agentModelInput,
    });
    await ledger.reserveProviderAttempt({
      cell,
      canonicalRequestSha256: deepSeekCanonicalRequestSha256V1(
        agentModelInput.messages,
        plan.model_protocol,
      ),
      modelInputSha256: agentModelInput.model_input_sha256,
    });
    const cleanupReceipt = buildResourceCleanupReceiptV1({
      resourceCount: plan.schedule.length,
      closedResourceOrdinals: plan.schedule.map((entry) => entry.ordinal),
      failedResourceOrdinals: [],
      ownerKinds: ["runtime_owner", "workspace_owner"],
      ownerCleanupReceipt: buildOwnerCleanupReceiptV1({
        ownerKinds: ["runtime_owner", "workspace_owner"],
        closedOwnerKinds: ["runtime_owner", "workspace_owner"],
        failedOwnerKinds: [],
      }),
    });
    await ledger.abortRun({
      cleanupReceipt,
      failingCell: cell,
      failureClass: "provider_or_network",
      failureEvidenceRefSha256: canonicalSha256({
        schema_version: "aionis_abort_signer_test_evidence_v1",
      }),
      failureStage: "provider",
    });
    const keyHandle = await open(keyPath, "r");
    let manifest;
    try {
      manifest = await runSealedPilotAbortSignerProcessV1({
        authorityRoot: root,
        cases,
        executionManifest,
        plan,
        runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
        runnerSigningKeyFd: keyHandle.fd,
        verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
      });
    } finally {
      await keyHandle.close();
    }
    await ledger.persistAbortManifest(manifest);
    assert.equal(manifest.status, "aborted");
    assert.equal(manifest.claim_eligible, false);
    assert.equal(manifest.resumable, false);
    const report = await verifySealedPilotRunV1({
      authorityRoot: root,
      cases,
      executionManifest,
      plan,
      runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
      verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
    });
    assert.equal(report.status, "verified_aborted");
    assert.equal(report.terminal_state, "aborted");
    assert.equal(report.claim_eligible, false);
    assert.match(report.abort_manifest_sha256, /^[0-9a-f]{64}$/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("owner cleanup failure can only produce a signed claim-ineligible abort", async () => {
  const root = await realpath(await mkdtemp(path.join(
    os.tmpdir(),
    "aionis-owner-cleanup-abort-",
  )));
  const keyPath = path.join(root, "runner-key.der");
  const verifierKeys = [1, 2, 3].map(() => generateKeyPairSync("ed25519"));
  const cases = verifierKeys.map((keys, index) => buildTestPilotCaseV1({
    caseId: `owner-cleanup-abort-${index + 1}`,
    verifierPublicKey: keys.publicKey,
  }));
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: "pilot-owner-cleanup-abort-test",
  });
  try {
    await writeFile(keyPath, TEST_RUNNER_KEYS_V1.privateKey.export({
      format: "der",
      type: "pkcs8",
    }), { mode: 0o600 });
    const { ledger, executionManifest } = await beginTestPilotRunLedgerV1({
      authorityRoot: root,
      plan,
    });
    const ownerKinds = ["runtime_owner", "workspace_owner"];
    const cleanupReceipt = buildResourceCleanupReceiptV1({
      resourceCount: plan.schedule.length,
      closedResourceOrdinals: plan.schedule.map((entry) => entry.ordinal),
      failedResourceOrdinals: [],
      ownerKinds,
      ownerCleanupReceipt: buildOwnerCleanupReceiptV1({
        ownerKinds,
        closedOwnerKinds: ["runtime_owner"],
        failedOwnerKinds: ["workspace_owner"],
      }),
    });
    assert.equal(cleanupReceipt.cleanup_confirmed, false);
    await ledger.abortRun({
      cleanupReceipt,
      failingCell: null,
      failureClass: "resource_cleanup_infrastructure",
      failureEvidenceRefSha256: canonicalSha256({
        schema_version: "aionis_owner_cleanup_failure_test_evidence_v1",
      }),
      failureStage: "resource_cleanup",
    });
    const keyHandle = await open(keyPath, "r");
    let manifest;
    try {
      manifest = await runSealedPilotAbortSignerProcessV1({
        authorityRoot: root,
        cases,
        executionManifest,
        plan,
        runnerPublicKey: TEST_RUNNER_KEYS_V1.publicKey,
        runnerSigningKeyFd: keyHandle.fd,
        verifierPublicKeys: verifierKeys.map((keys) => keys.publicKey),
      });
    } finally {
      await keyHandle.close();
    }
    await ledger.persistAbortManifest(manifest);
    assert.equal(manifest.claim_eligible, false);
    assert.equal(manifest.cleanup_confirmed, false);
    const [runDirectoryName] = await readdir(path.join(root, "pilots"));
    const runDirectory = path.join(root, "pilots", runDirectoryName);
    await assert.rejects(() => readFile(path.join(runDirectory, "final-manifest.json")));
    assert.ok(await readFile(path.join(runDirectory, "abort-manifest.json"), "utf8"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
