import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import {
  buildOwnerCleanupReceiptV1,
  buildResourceCleanupReceiptV1,
} from "../src/pilot-run-event-contract.mjs";
import {
  RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
  buildSignedRunnerAbortManifestForSignerV1,
  buildSignedRunnerExecutionAuthorizationV1,
  runnerAuthorityPublicKeyPrincipalSha256V1,
  verifySignedRunnerAbortManifestV1,
  verifySignedRunnerFinalManifestV1,
  verifySignedRunnerExecutionAuthorizationV1,
} from "../src/runner-signature.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);

function buildManifest(plan, overrides = {}) {
  const body = {
    schema_version: "aionis_pilot_execution_manifest_report_v1",
    status: "execution_manifest_verified",
    pilot_id: plan.pilot_id,
    plan_sha256: plan.plan_sha256,
    artifact_report_sha256: SHA_A,
    eval_binding_sha256: SHA_B,
    eval_repository_provenance_sha256: SHA_A,
    runtime_binding_sha256: SHA_A,
    provider_authority_sha256: SHA_B,
    oci_runtime_authority_sha256: SHA_A,
    case_authority_set_sha256: SHA_A,
    cell_authority_set_sha256: SHA_B,
    cell_count: 9,
    provider_request_attempt_limit: 9,
    cohort_installed: false,
    evidence_authority_class: "release_authority_v1",
    runner_authority: {
      schema_version: "aionis_test_runner_authority_v1",
      eval_repository_provenance: { provenance_sha256: SHA_A },
    },
    ...overrides,
  };
  return canonicalClone({
    ...body,
    manifest_report_sha256: canonicalSha256(body),
  });
}

function fixture() {
  const runnerKeys = generateKeyPairSync("ed25519");
  const cases = ["one", "two", "three"].map((caseId) => {
    const verifierKeys = generateKeyPairSync("ed25519");
    return buildTestPilotCaseV1({
      caseId,
      verifierPrivateKey: verifierKeys.privateKey,
      verifierPublicKey: verifierKeys.publicKey,
    });
  });
  const initialPlan = buildTestPilotPlanV1(cases, {
    pilotId: "pilot-runner-signature-test",
  });
  const plan = buildTestPilotPlanV1(cases, {
    pilotId: initialPlan.pilot_id,
    evalBinding: {
      ...initialPlan.eval_binding,
      runner_authority_public_key_principal_sha256:
        runnerAuthorityPublicKeyPrincipalSha256V1(runnerKeys.publicKey),
    },
  });
  const executionManifest = buildManifest(plan);
  const fixedLedgerAuthorityRoot = realpathSync(mkdtempSync(path.join(
    os.tmpdir(),
    "aionis-runner-signature-",
  )));
  return {
    executionManifest,
    fixedLedgerAuthorityRoot,
    plan,
    runnerKeys,
  };
}

function buildInput(value) {
  return {
    plan: value.plan,
    executionManifest: value.executionManifest,
    fixedLedgerAuthorityRoot: value.fixedLedgerAuthorityRoot,
    issuedAt: "2026-07-22T00:00:01.000Z",
  };
}

function verifyContext(value, overrides = {}) {
  return {
    plan: value.plan,
    executionManifest: value.executionManifest,
    fixedLedgerAuthorityRoot: value.fixedLedgerAuthorityRoot,
    publicKey: value.runnerKeys.publicKey,
    ...overrides,
  };
}

function completedRun(value, authorization) {
  const verdictBody = {
    pilot_id: value.plan.pilot_id,
    plan_sha256: value.plan.plan_sha256,
    verdict: "promote",
  };
  const verdict = {
    ...verdictBody,
    verdict_sha256: canonicalSha256(verdictBody),
  };
  const ledgerSnapshot = {
    schema_version: "aionis_pilot_run_ledger_snapshot_v1",
    pilot_id: value.plan.pilot_id,
    plan_sha256: value.plan.plan_sha256,
    execution_authorization_sha256: authorization.execution_authorization_sha256,
    run_started_event_sha256: SHA_A,
    event_count: 58,
    event_chain_head_sha256: SHA_B,
    completed_cell_count: 9,
    next_attempt_ordinal: 10,
    active_attempt_ordinal: null,
    verdict_sha256: verdict.verdict_sha256,
    closed: true,
    restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
  };
  const runClosure = {
    schema_version: "aionis_pilot_run_closed_v1",
    pilot_id: value.plan.pilot_id,
    plan_sha256: value.plan.plan_sha256,
    execution_authorization_sha256: authorization.execution_authorization_sha256,
    cleanup_receipt_sha256: SHA_A,
    verdict_sha256: verdict.verdict_sha256,
    counts: {
      provider_attempt_count: 9,
      cell_result_count: 9,
      runtime_observation_count: 6,
      treatment_ledger_closed_count: 3,
    },
    state: "closed_pending_runner_seal",
    run_closed_event_sha256: ledgerSnapshot.event_chain_head_sha256,
  };
  return {
    ledgerSnapshot,
    runClosure,
    sealedAt: "2026-07-22T00:00:10.000Z",
    verdict,
  };
}

function abortedRun(value, authorization) {
  const ownerKinds = ["runtime_owner", "workspace_owner"];
  const cleanupReceipt = buildResourceCleanupReceiptV1({
    resourceCount: 9,
    closedResourceOrdinals: [1, 2, 3, 4, 5, 6, 7, 8, 9],
    failedResourceOrdinals: [],
    ownerKinds,
    ownerCleanupReceipt: buildOwnerCleanupReceiptV1({
      ownerKinds,
      closedOwnerKinds: ownerKinds,
      failedOwnerKinds: [],
    }),
  });
  const ledgerSnapshot = {
    schema_version: "aionis_pilot_run_ledger_snapshot_v1",
    pilot_id: value.plan.pilot_id,
    plan_sha256: value.plan.plan_sha256,
    execution_authorization_sha256: authorization.execution_authorization_sha256,
    run_started_event_sha256: SHA_A,
    event_count: 8,
    event_chain_head_sha256: SHA_B,
    completed_cell_count: 1,
    next_attempt_ordinal: 2,
    active_attempt_ordinal: null,
    verdict_sha256: null,
    closed: true,
    restart_policy: "forbid_same_pilot_id_within_signed_authority_root",
  };
  return {
    ledgerSnapshot,
    runAbort: {
      schema_version: "aionis_pilot_run_aborted_v1",
      pilot_id: value.plan.pilot_id,
      plan_sha256: value.plan.plan_sha256,
      execution_authorization_sha256: authorization.execution_authorization_sha256,
      failure_stage: "harness",
      failure_class: "harness_infrastructure",
      failure_evidence_ref_sha256: SHA_A,
      failing_cell_ref: null,
      completed_cell_count: 1,
      next_attempt_ordinal: 2,
      active_attempt_ordinal: null,
      provider_attempt_reservation_count: 1,
      provider_attempt_completion_count: 1,
      active_provider_attempt_state: "no_active_attempt",
      cleanup_receipt: cleanupReceipt,
      cleanup_receipt_sha256: cleanupReceipt.cleanup_receipt_sha256,
      cleanup_confirmed: true,
      state: "aborted_claim_ineligible_no_resume",
      run_aborted_event_sha256: SHA_B,
    },
    sealedAt: "2026-07-22T00:00:10.000Z",
  };
}

test("runner authorization canonically binds plan, manifest, principal, ledger root, and time", () => {
  const value = fixture();
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );

  assert.deepEqual(
    verifySignedRunnerExecutionAuthorizationV1(authorization, verifyContext(value)),
    authorization,
  );
  assert.equal(authorization.pilot_id, value.plan.pilot_id);
  assert.equal(authorization.plan_sha256, value.plan.plan_sha256);
  assert.equal(
    authorization.runner_authority_public_key_principal_sha256,
    value.plan.eval_binding.runner_authority_public_key_principal_sha256,
  );
  assert.equal(
    authorization.execution_manifest_sha256,
    value.executionManifest.manifest_report_sha256,
  );
  assert.equal(
    authorization.fixed_ledger_authority_root,
    value.fixedLedgerAuthorityRoot,
  );
  assert.equal(authorization.signature_algorithm, "ed25519");
  assert.equal(authorization.claim_eligible, true);
  assert.deepEqual(
    authorization.runner_transport_authority,
    RELEASE_RUNNER_TRANSPORT_AUTHORITY_V1,
  );
  assert.equal(authorization.signature.length, 86);
  assert.match(authorization.execution_authorization_sha256, /^[0-9a-f]{64}$/u);
});

test("builder rejects caller-supplied derived fields and a key outside the plan authority", () => {
  const value = fixture();
  const callerDerived = {
    ...buildInput(value),
    runnerAuthorityPublicKeyPrincipalSha256:
      value.plan.eval_binding.runner_authority_public_key_principal_sha256,
  };
  assert.throws(
    () => buildSignedRunnerExecutionAuthorizationV1(
      callerDerived,
      value.runnerKeys.privateKey,
    ),
    /runner_signature_input_shape_invalid/u,
  );

  const wrongKeys = generateKeyPairSync("ed25519");
  assert.throws(
    () => buildSignedRunnerExecutionAuthorizationV1(
      buildInput(value),
      wrongKeys.privateKey,
    ),
    /runner_principal_plan_binding_invalid/u,
  );
});

test("runner authorization rejects tampering of every signed authority binding", () => {
  const value = fixture();
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );
  const mutations = [
    (record) => { record.pilot_id = "pilot-tampered"; },
    (record) => { record.plan_sha256 = SHA_A; },
    (record) => {
      record.runner_authority_public_key_principal_sha256 = SHA_A;
    },
    (record) => { record.execution_manifest_sha256 = SHA_A; },
    (record) => { record.fixed_ledger_authority_root = "/tmp/aionis-other-ledger"; },
    (record) => { record.ledger_authority_root_identity.inode = "1"; },
    (record) => { record.issued_at = "2026-07-22T00:00:02.000Z"; },
  ];

  for (const mutate of mutations) {
    const tampered = canonicalClone(authorization);
    mutate(tampered);
    assert.throws(
      () => verifySignedRunnerExecutionAuthorizationV1(tampered, verifyContext(value)),
      /execution_authorization_integrity_invalid/u,
    );
  }
});

test("verification rejects wrong key, wrong expected root, and wrong principal", () => {
  const value = fixture();
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );
  const wrongKeys = generateKeyPairSync("ed25519");
  assert.throws(
    () => verifySignedRunnerExecutionAuthorizationV1(
      authorization,
      verifyContext(value, { publicKey: wrongKeys.publicKey }),
    ),
    /public_key_invalid/u,
  );
  assert.throws(
    () => verifySignedRunnerExecutionAuthorizationV1(
      authorization,
      verifyContext(value, {
        fixedLedgerAuthorityRoot: "/tmp/aionis-pilot-ledgers/other-pilot",
      }),
    ),
    /fixed_ledger_authority_root_binding_invalid/u,
  );

  const principalTampered = canonicalClone(authorization);
  principalTampered.runner_authority_public_key_principal_sha256 = SHA_A;
  const body = Object.fromEntries(
    Object.entries(principalTampered).filter(([key]) => ![
      "execution_authorization_sha256",
      "signature",
      "signature_algorithm",
    ].includes(key)),
  );
  principalTampered.execution_authorization_sha256 = canonicalSha256(body);
  assert.throws(
    () => verifySignedRunnerExecutionAuthorizationV1(
      principalTampered,
      verifyContext(value),
    ),
    /runner_principal_plan_binding_invalid/u,
  );
});

test("execution manifest must be self-hashed and exactly bound to the plan", () => {
  const value = fixture();
  const corrupted = canonicalClone(value.executionManifest);
  corrupted.cell_authority_set_sha256 = SHA_A;
  assert.throws(
    () => buildSignedRunnerExecutionAuthorizationV1(
      { ...buildInput(value), executionManifest: corrupted },
      value.runnerKeys.privateKey,
    ),
    /execution_manifest_integrity_invalid/u,
  );

  const otherManifest = buildManifest(value.plan, { provider_authority_sha256: SHA_A });
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );
  assert.throws(
    () => verifySignedRunnerExecutionAuthorizationV1(
      authorization,
      verifyContext(value, { executionManifest: otherManifest }),
    ),
    /execution_manifest_binding_invalid/u,
  );
});

test("release final-manifest verification rejects any event count other than 58", () => {
  const value = fixture();
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );
  const completed = completedRun(value, authorization);
  completed.ledgerSnapshot.event_count = 57;
  const input = {
    plan: value.plan,
    executionManifest: value.executionManifest,
    executionAuthorization: authorization,
    fixedLedgerAuthorityRoot: value.fixedLedgerAuthorityRoot,
    ...completed,
  };
  assert.throws(() => verifySignedRunnerFinalManifestV1({}, {
    ...input,
    publicKey: value.runnerKeys.publicKey,
  }), /final_release_event_count_invalid/u);
});

test("abort manifest is signed as inconclusive, non-resumable, and binds the terminal abort ledger", () => {
  const value = fixture();
  const authorization = buildSignedRunnerExecutionAuthorizationV1(
    buildInput(value),
    value.runnerKeys.privateKey,
  );
  const aborted = abortedRun(value, authorization);
  const context = {
    plan: value.plan,
    executionManifest: value.executionManifest,
    executionAuthorization: authorization,
    fixedLedgerAuthorityRoot: value.fixedLedgerAuthorityRoot,
    ...aborted,
  };
  const manifest = buildSignedRunnerAbortManifestForSignerV1(
    context,
    value.runnerKeys.privateKey,
  );
  assert.equal(manifest.status, "aborted");
  assert.equal(manifest.outcome, "aborted_inconclusive");
  assert.equal(manifest.claim_eligible, false);
  assert.equal(manifest.resumable, false);
  assert.equal(manifest.cleanup_confirmed, true);
  assert.deepEqual(verifySignedRunnerAbortManifestV1(manifest, {
    ...context,
    publicKey: value.runnerKeys.publicKey,
  }), manifest);

  const tampered = canonicalClone(manifest);
  tampered.cleanup_confirmed = false;
  assert.throws(() => verifySignedRunnerAbortManifestV1(tampered, {
    ...context,
    publicKey: value.runnerKeys.publicKey,
  }), /abort_manifest_binding_invalid/u);
});
