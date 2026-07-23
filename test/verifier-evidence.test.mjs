import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalClone, canonicalSha256 } from "../src/canonical.mjs";
import {
  buildSignedVerifierEvidenceV1,
  verifySignedVerifierEvidenceV1,
} from "../src/verifier-evidence.mjs";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const SHA_C = "c".repeat(64);

function evidenceInput(overrides = {}) {
  return {
    cell_execution_ref: {
      pilot_id: "pilot-1",
      opaque_cell_id: "cell-01",
      arm: "treatment",
      case_id: "case-01",
      case_sha256: SHA_A,
      decision_id: "decision-01",
      contract_sha256: SHA_B,
      render_result_sha256: SHA_C,
      exposure_event_sha256: SHA_A,
    },
    verifier_authority_ref: {
      verifier_id: "workspace-verifier-v1",
      verifier_image_digest: `sha256:${SHA_B}`,
      verifier_contract_sha256: SHA_C,
      verifier_config_sha256: SHA_A,
    },
    temporal_fence: {
      agent_exit_authority_principal_sha256: SHA_A,
      agent_exit_receipt_sha256: SHA_B,
      agent_exit_sequence: 41,
      agent_exited_at: "2026-07-22T00:00:01.000Z",
      verifier_runner_parent_agent_exit_receipt_sha256: SHA_B,
      verifier_runner_receipt_sha256: SHA_C,
      verifier_runner_sequence: 42,
      verifier_started_at: "2026-07-22T00:00:02.000Z",
      fresh_process: true,
      after_agent_exit: true,
    },
    inputs: {
      workspace_before_sha256: SHA_A,
      workspace_after_sha256: SHA_B,
      diff_sha256: SHA_C,
      action_trace_sha256: SHA_A,
      task_fixture_sha256: SHA_B,
    },
    checks: [{
      check_id: "workspace-contract",
      command_argv_sha256: SHA_A,
      exit_code: 0,
      stdout_sha256: SHA_B,
      stderr_sha256: SHA_C,
      status: "passed",
    }],
    metrics: {
      action_completion: true,
      accepted_direction: true,
      wrong_branch_write: false,
      wrong_branch_attention: false,
      unsafe_direct_use: false,
      rediscovery_steps: 0,
    },
    verdict: "passed",
    failure_class: "none",
    runtime_outcome_mapping: {
      outcome: "succeeded",
      outcome_code: "external_verifier_passed",
    },
    ...overrides,
  };
}

test("verifier evidence binds cell, authority, receipt fence, self hash, and signature", () => {
  const keys = generateKeyPairSync("ed25519");
  const evidence = buildSignedVerifierEvidenceV1(evidenceInput(), keys.privateKey);

  assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);
  assert.match(
    evidence.verifier_authority_ref.public_key_principal_sha256,
    /^[0-9a-f]{64}$/u,
  );
  assert.equal(
    evidence.temporal_fence.verifier_runner_authority_principal_sha256,
    evidence.verifier_authority_ref.public_key_principal_sha256,
  );
  assert.equal(evidence.signature.length, 86);

  for (const mutate of [
    (value) => { value.cell_execution_ref.decision_id = "decision-tampered"; },
    (value) => { value.cell_execution_ref.exposure_event_sha256 = SHA_C; },
    (value) => { value.verifier_authority_ref.verifier_image_digest = `sha256:${SHA_A}`; },
    (value) => { value.temporal_fence.agent_exit_receipt_sha256 = SHA_A; },
  ]) {
    const tampered = canonicalClone(evidence);
    mutate(tampered);
    assert.throws(
      () => verifySignedVerifierEvidenceV1(tampered, keys.publicKey),
      /evidence_integrity_invalid/u,
    );
  }

  const otherKeys = generateKeyPairSync("ed25519");
  assert.throws(
    () => verifySignedVerifierEvidenceV1(evidence, otherKeys.publicKey),
    /public_key_invalid/u,
  );
});

test("passed evidence rejects every contradictory check and metric state", async (t) => {
  const keys = generateKeyPairSync("ed25519");
  const contradictions = [
    ["failed check", (input) => { input.checks[0].status = "failed"; }],
    ["indeterminate check", (input) => {
      input.checks[0].status = "indeterminate";
      input.checks[0].exit_code = null;
    }],
    ["incomplete action", (input) => { input.metrics.action_completion = false; }],
    ["unaccepted direction", (input) => { input.metrics.accepted_direction = false; }],
    ["wrong branch write", (input) => { input.metrics.wrong_branch_write = true; }],
    ["wrong branch attention", (input) => { input.metrics.wrong_branch_attention = true; }],
    ["unsafe direct use", (input) => { input.metrics.unsafe_direct_use = true; }],
  ];

  for (const [name, mutate] of contradictions) {
    await t.test(name, () => {
      const input = evidenceInput();
      mutate(input);
      assert.throws(
        () => buildSignedVerifierEvidenceV1(input, keys.privateKey),
        /passed_evidence_contradiction/u,
      );
    });
  }
});

test("temporal fence requires a post-exit receipt chain and verifier runner authority", () => {
  const keys = generateKeyPairSync("ed25519");
  const invalidInputs = [
    evidenceInput({
      temporal_fence: {
        ...evidenceInput().temporal_fence,
        verifier_started_at: "2026-07-22T00:00:01.000Z",
      },
    }),
    evidenceInput({
      temporal_fence: {
        ...evidenceInput().temporal_fence,
        verifier_runner_sequence: 41,
      },
    }),
    evidenceInput({
      temporal_fence: {
        ...evidenceInput().temporal_fence,
        verifier_runner_parent_agent_exit_receipt_sha256: SHA_A,
      },
    }),
    evidenceInput({
      temporal_fence: {
        ...evidenceInput().temporal_fence,
        verifier_runner_receipt_sha256: SHA_B,
      },
    }),
  ];

  for (const input of invalidInputs) {
    assert.throws(
      () => buildSignedVerifierEvidenceV1(input, keys.privateKey),
      /temporal_(?:order|receipt_chain)_invalid/u,
    );
  }

  const evidence = buildSignedVerifierEvidenceV1(evidenceInput(), keys.privateKey);
  const authorityTampered = canonicalClone(evidence);
  authorityTampered.temporal_fence.verifier_runner_authority_principal_sha256 = SHA_A;
  authorityTampered.evidence_sha256 = canonicalSha256(Object.fromEntries(
    Object.entries(authorityTampered).filter(([key]) => ![
      "evidence_sha256", "signature", "signature_algorithm",
    ].includes(key)),
  ));
  assert.throws(
    () => verifySignedVerifierEvidenceV1(authorityTampered, keys.publicKey),
    /temporal_runner_authority_invalid/u,
  );
});

test("builder refuses caller-supplied derived authority identities and duplicate checks", () => {
  const keys = generateKeyPairSync("ed25519");
  const spoofed = evidenceInput();
  spoofed.verifier_authority_ref.public_key_principal_sha256 = SHA_A;
  assert.throws(
    () => buildSignedVerifierEvidenceV1(spoofed, keys.privateKey),
    /verifier_authority_input_shape_invalid/u,
  );

  const duplicate = evidenceInput();
  duplicate.checks.push(canonicalClone(duplicate.checks[0]));
  assert.throws(
    () => buildSignedVerifierEvidenceV1(duplicate, keys.privateKey),
    /check_id_duplicate/u,
  );
});

test("control evidence uses null Runtime refs instead of fabricated decisions", () => {
  const keys = generateKeyPairSync("ed25519");
  const control = evidenceInput();
  Object.assign(control.cell_execution_ref, {
    arm: "observe_only",
    decision_id: null,
    contract_sha256: null,
    render_result_sha256: null,
    exposure_event_sha256: null,
  });
  const evidence = buildSignedVerifierEvidenceV1(control, keys.privateKey);
  assert.equal(evidence.cell_execution_ref.decision_id, null);
  assert.deepEqual(verifySignedVerifierEvidenceV1(evidence, keys.publicKey), evidence);

  const fabricated = evidenceInput();
  fabricated.cell_execution_ref.arm = "baseline";
  assert.throws(
    () => buildSignedVerifierEvidenceV1(fabricated, keys.privateKey),
    /control_runtime_ref_present/u,
  );
});
