import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalSha256 } from "../src/canonical.mjs";
import { startLocalRuntimeV1Fixture } from "../src/local-runtime-v1-fixture.mjs";
import { buildPilotCellV1 } from "../src/pilot-contract.mjs";
import { createRuntimeV1HostAdapter } from "../src/runtime-v1-host-adapter.mjs";
import { buildSignedVerifierEvidenceV1 } from "../src/verifier-evidence.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const runtimeRoot = path.resolve(
  process.env.AIONIS_RUNTIME_REPO ?? path.join(root, "..", "AionisRuntime-focused"),
);
const lockPath = path.join(root, "config/runtime-v1-lock.json");

function iso(offsetMs = 0) {
  return new Date(Date.now() + offsetMs).toISOString();
}

function evidence(label) {
  return canonicalSha256({
    schema_version: "aionis_eval_integration_evidence_v1",
    label,
  });
}

function observationBody(taskFamily) {
  const observedAt = iso(-30_000);
  const expiresAt = iso(45 * 60_000);
  return {
    schema_version: "record_observations_body_v1",
    host_task: {
      host_task_id: "task-eval-integration",
      episode_id: "episode-eval-integration",
      run_id: "run-eval-integration",
      consumer_agent_id: "agent-eval-integration",
      consumer_team_id: null,
      task_family: taskFamily,
      task_signature: "task-signature-eval-integration",
      workflow_signature: null,
      workspace_signature: "workspace-signature-eval-integration",
      source_task_sha256: evidence("source-task"),
      source_event_sha256: evidence("source-event"),
      issued_at: iso(-60_000),
      expires_at: iso(60 * 60_000),
    },
    memory_inputs: [{
      memory_input_id: "procedure-eval-integration",
      // A current-state input belongs to Runtime's verified-continuity lane.
      // A procedure is intentionally isolated as a governed-learning draft and
      // cannot be served by this no-cohort release integration.
      kind: "current_state",
      applicability: {
        task_signature: "task-signature-eval-integration",
        workflow_signature: null,
        workspace_signature: "workspace-signature-eval-integration",
      },
      projection: {
        summary: "Continue through the verifier-accepted implementation branch.",
        next_action: "Inspect the accepted target before applying the follow-up.",
        target_refs: [{ kind: "memory", ref: "eval-integration-active-branch" }],
        workflow_steps: [
          "Inspect the accepted target.",
          "Apply the bounded follow-up.",
          "Run the external verifier.",
        ],
        acceptance_statements: ["The external verifier accepts the follow-up."],
      },
      coverage_claims: [{
        obligation_kind: "required_state",
        target_refs: [{ kind: "memory", ref: "eval-integration-active-branch" }],
        evidence_requirement: "runtime_state",
        required_probe_ids: [],
      }],
      precondition_specs: [],
      evidence_observation_ids: ["observation-eval-integration"],
      expires_at: expiresAt,
    }],
    collector_observations: [{
      schema_version: "collector_observation_v1",
      observation_id: "observation-eval-integration",
      probe_id: "probe-eval-integration",
      probe_spec_sha256: evidence("probe-spec"),
      observed_at: observedAt,
      expires_at: expiresAt,
      value: {
        kind: "capability",
        capability_id: "external-workspace-verifier",
        version: "1.0.0",
        presence: "present",
      },
      evidence_sha256: evidence("collector-observation"),
    }],
    signed_observations: [],
  };
}

function obligation() {
  return {
    obligation_id: "obligation-eval-integration-active-branch",
    kind: "required_state",
    requirement: "hard",
    statement: "Recover the verifier-accepted implementation branch before acting.",
    target_refs: [{ kind: "memory", ref: "eval-integration-active-branch" }],
    required_probe_ids: [],
    evidence_requirement: "runtime_state",
    source_refs: ["episode-1:external-verifier"],
  };
}

test("observe-only and treatment share exact observations while treatment closes a real V1 ledger", {
  timeout: 360_000,
}, async () => {
  const verifierKeys = generateKeyPairSync("ed25519");
  const body = observationBody("coding");
  const obligations = [obligation()];
  const pilotCase = buildTestPilotCaseV1({
    caseId: "case-eval-integration",
    observationBody: body,
    obligations,
    verifierPublicKey: verifierKeys.publicKey,
    fixtureSha256: evidence("task-fixture"),
    workspaceSha256: evidence("workspace-before"),
    verifierContractSha256: evidence("verifier-contract"),
    verifierConfigSha256: evidence("verifier-config"),
    verifierImageDigest: `sha256:${evidence("verifier-image")}`,
  });
  const observeCell = buildPilotCellV1({
    pilot_id: "pilot-local-runtime-integration",
    opaque_cell_id: "cell-integration-observe-only",
    ordinal: 1,
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    arm: "observe_only",
  });
  const treatmentCell = buildPilotCellV1({
    pilot_id: "pilot-local-runtime-integration",
    opaque_cell_id: "cell-integration-treatment",
    ordinal: 2,
    case_id: pilotCase.case_id,
    case_sha256: pilotCase.case_sha256,
    arm: "treatment",
  });
  let observeFixture = null;
  let treatmentFixture = null;
  try {
    observeFixture = await startLocalRuntimeV1Fixture({
      runtimeRoot,
      lockPath,
      scope: observeCell.isolation.runtime_scope,
      taskFamily: "coding",
    });
    const observeAdapter = createRuntimeV1HostAdapter({
      cell: observeCell,
      client: observeFixture.client,
      pilotCase,
      scope: observeFixture.scope,
      verifierPublicKey: verifierKeys.publicKey,
    });
    const observed = await observeAdapter.prepareArm();
    await observeFixture.close();
    observeFixture = null;

    treatmentFixture = await startLocalRuntimeV1Fixture({
      runtimeRoot,
      lockPath,
      scope: treatmentCell.isolation.runtime_scope,
      taskFamily: "coding",
    });
    const treatmentAdapter = createRuntimeV1HostAdapter({
      cell: treatmentCell,
      client: treatmentFixture.client,
      pilotCase,
      scope: treatmentFixture.scope,
      verifierPublicKey: verifierKeys.publicKey,
    });
    const treatment = await treatmentAdapter.prepareArm();
    assert.equal(observed.observation_body_sha256, treatment.observation_body_sha256);
    assert.equal(observed.model_context, null);
    assert.equal(observed.runtime.continuation, null);
    assert.equal(observed.runtime.settlement, null);
    assert.equal(typeof treatment.model_context, "string");
    assert.match(treatment.model_context, /verifier-accepted implementation branch/u);
    assert.equal(treatment.runtime.continuation.serving_mode, "authoritative_unassigned");
    assert.equal(treatment.runtime.continuation.experiment_cohort_ref, null);
    assert.equal(treatment.runtime.continuation.serving_assignment_receipt, null);
    assert.ok(treatment.runtime.continuation.selected_capsules.length >= 1);

    const useObservedAt = iso();
    await new Promise((resolve) => setTimeout(resolve, 2));
    const agentExitedAt = iso();
    await new Promise((resolve) => setTimeout(resolve, 2));
    const verifierStartedAt = iso();
    await new Promise((resolve) => setTimeout(resolve, 2));
    const outcomeObservedAt = iso();
    const agentExitReceiptSha256 = evidence("agent-exit-receipt");
    const verifierEvidence = buildSignedVerifierEvidenceV1({
      cell_execution_ref: {
        pilot_id: treatmentCell.pilot_id,
        opaque_cell_id: treatmentCell.opaque_cell_id,
        arm: treatmentCell.arm,
        case_id: treatmentCell.case_id,
        case_sha256: treatmentCell.case_sha256,
        decision_id: treatment.runtime.continuation.decision_id,
        contract_sha256: treatment.runtime.continuation.contract_sha256,
        render_result_sha256: treatment.runtime.continuation.render_result_sha256,
        exposure_event_sha256: treatment.runtime.continuation.exposure_event_sha256,
      },
      verifier_authority_ref: {
        verifier_id: pilotCase.private_verifier.verifier_id,
        verifier_image_digest: pilotCase.private_verifier.verifier_image_digest,
        verifier_contract_sha256: pilotCase.private_verifier.verifier_contract_sha256,
        verifier_config_sha256: pilotCase.private_verifier.verifier_config_sha256,
      },
      temporal_fence: {
        agent_exit_authority_principal_sha256:
          treatmentCell.isolation.agent_exit_authority_principal_sha256,
        agent_exit_receipt_sha256: agentExitReceiptSha256,
        agent_exit_sequence: 1,
        agent_exited_at: agentExitedAt,
        verifier_runner_parent_agent_exit_receipt_sha256: agentExitReceiptSha256,
        verifier_runner_receipt_sha256: evidence("verifier-runner-receipt"),
        verifier_runner_sequence: 2,
        verifier_started_at: verifierStartedAt,
        fresh_process: true,
        after_agent_exit: true,
      },
      inputs: {
        workspace_before_sha256: pilotCase.workspace.prepared_tree_sha256,
        workspace_after_sha256: evidence("workspace-after"),
        diff_sha256: evidence("workspace-diff"),
        action_trace_sha256: evidence("action-trace"),
        task_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
      },
      checks: [{
        check_id: "real-runtime-http-chain",
        command_argv_sha256: evidence("verifier-command"),
        exit_code: 0,
        stdout_sha256: evidence("verifier-stdout"),
        stderr_sha256: evidence("verifier-stderr"),
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
        outcome_code: "local_runtime_integration_passed",
      },
    }, verifierKeys.privateKey);
    const settled = await treatmentAdapter.settleTreatment(treatment, {
      useObservedAt,
      outcomeObservedAt,
      verifierEvidence,
    });
    assert.equal(settled.runtime.settlement.effect_state, "not_applicable");
    assert.match(settled.runtime.settlement.ledger_head_event_sha256, /^[0-9a-f]{64}$/u);
    assert.equal(treatmentFixture.binding.cohort_installed, false);
    assert.equal(treatmentFixture.binding.runtime_git_commit_sha,
      "697204d508cae705d2a4671f31126a1807005bfb");
  } finally {
    if (observeFixture !== null) await observeFixture.close();
    if (treatmentFixture !== null) await treatmentFixture.close();
  }
});
