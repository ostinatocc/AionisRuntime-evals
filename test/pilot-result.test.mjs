import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildAgentModelInputV1 } from "../src/agent-action.mjs";
import {
  buildAgentExecutionAuthorityV1,
  executeAgentActionV1,
} from "../src/agent-execution.mjs";
import { canonicalClone, canonicalSha256, sha256Bytes } from "../src/canonical.mjs";
import { createDeepSeekProviderV1 } from "../src/deepseek-provider.mjs";
import { createNonReleaseProviderContractAuthorityV1 } from "../src/pilot-run-ledger.mjs";
import {
  buildPilotCellResultV1,
  buildPilotInfrastructureFailureV1,
  isPilotInfrastructureFailureV1,
  isPilotProductFailureV1,
  verifyPilotCellResultV1,
} from "../src/pilot-result.mjs";
import { buildSignedVerifierEvidenceV1 } from "../src/verifier-evidence.mjs";
import { captureWorkspaceEvidenceV1 } from "../src/workspace-evidence.mjs";
import { pilotCellOperationIdsV1 } from "../src/runtime-v1-host-adapter.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

function digest(label) {
  return canonicalSha256({ schema_version: "aionis_pilot_result_test_digest_v1", label });
}

function timestampClock(startSecond = 0) {
  let tick = 0;
  return () => new Date(Date.UTC(2026, 6, 22, 0, 0, startSecond + tick++)).toISOString();
}

function assistantContent(label) {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v2",
    summary: `No safe change for ${label}.`,
    action: { kind: "no_safe_change", patch: null },
  });
}

function providerHttpResponse(content, requestId) {
  return {
    status: 200,
    headers: { get: () => requestId },
    async text() {
      return JSON.stringify({
        id: requestId,
        object: "chat.completion",
        created: 1_784_678_400,
        model: "deepseek-v4-flash",
        system_fingerprint: "fp-deepseek-v4-flash-result",
        choices: [{
          index: 0,
          finish_reason: "stop",
          message: { role: "assistant", content },
        }],
        usage: {
          prompt_tokens: 12,
          prompt_cache_hit_tokens: 2,
          prompt_cache_miss_tokens: 10,
          completion_tokens: 8,
          total_tokens: 20,
          completion_tokens_details: { reasoning_tokens: 4 },
        },
      });
    },
  };
}

function modelInput(pilotCase, cell, runtimeContext) {
  return buildAgentModelInputV1({
    pilotCase,
    preparedArm: {
      schema_version: "aionis_pilot_prepared_arm_v1",
      cell,
      arm: cell.arm,
      observation_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
      model_context: runtimeContext,
      runtime: cell.arm === "baseline" ? null : {
        continuation: cell.arm === "treatment" ? {
          render_content_sha256: sha256Bytes(Buffer.from(runtimeContext, "utf8")),
        } : null,
        observation: runtimeObservation(pilotCase, cell),
        settlement: null,
      },
    },
  });
}

function runtimeObservation(pilotCase, cell) {
  if (cell.arm === "baseline") return null;
  const operationId = pilotCellOperationIdsV1(cell).observation;
  const operationRequestSha256 = digest(`${cell.opaque_cell_id}:observation-request`);
  const snapshot = {
    world_snapshot_id: operationId,
    world_snapshot_sha256: digest(`${cell.opaque_cell_id}:world-snapshot`),
    host_task_envelope_sha256: digest(`${cell.opaque_cell_id}:host-task-envelope`),
  };
  const result = {
    schema_version: "record_observations_result_v1",
    authority_branch_set: null,
    durable_job_set: null,
    memory_revision_ref: null,
    observation_snapshot_ref: snapshot,
  };
  const receipt = {
    schema_version: "continuation_runtime_operation_receipt_v1",
    tenant_id: "pilot-result-test-tenant",
    scope: cell.isolation.runtime_scope,
    operation_kind: "record_observations",
    operation_id: operationId,
    actor_kind: "trusted_host",
    actor_principal_sha256: digest(`${cell.opaque_cell_id}:host-principal`),
    request_sha256: operationRequestSha256,
    completed_at: "2026-07-22T00:00:00.000Z",
    result,
  };
  return {
    operation_id: operationId,
    scope: cell.isolation.runtime_scope,
    operation_receipt: receipt,
    operation_receipt_sha256: canonicalSha256(receipt),
    operation_request_sha256: operationRequestSha256,
    request_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
    ...snapshot,
  };
}

async function makePlanFixture() {
  const workspacePath = await realpath(await mkdtemp(
    path.join(os.tmpdir(), "aionis-pilot-result-"),
  ));
  const workspace = await captureWorkspaceEvidenceV1(workspacePath);
  const keys = [
    generateKeyPairSync("ed25519"),
    generateKeyPairSync("ed25519"),
    generateKeyPairSync("ed25519"),
  ];
  const cases = keys.map((key, index) => buildTestPilotCaseV1({
    caseId: `pilot-result-case-${index + 1}`,
    verifierPrivateKey: key.privateKey,
    verifierPublicKey: key.publicKey,
    workspaceSha256: workspace.workspace_sha256,
  }));
  const plan = buildTestPilotPlanV1(cases, { pilotId: "pilot-result-test" });
  return { cases, keys, plan, workspacePath };
}

async function completedProviderCalls(plan, pilotCase, count) {
  const content = assistantContent("provider completion");
  let request = 0;
  const provider = createDeepSeekProviderV1({
    apiKey: "test-deepseek-secret",
    attemptAuthority: createNonReleaseProviderContractAuthorityV1(plan.schedule),
    clock: timestampClock(0),
    fetchImpl: async () => {
      request += 1;
      return providerHttpResponse(content, `provider-request-${request}`);
    },
    modelProtocol: plan.model_protocol,
    pilotId: plan.pilot_id,
  });
  const calls = [];
  for (const cell of plan.schedule.slice(0, count)) {
    const runtimeContext = cell.arm === "treatment"
      ? "Verifier-safe continuation context for the treatment arm."
      : null;
    const input = modelInput(pilotCase, cell, runtimeContext);
    calls.push({
      cell,
      input,
      runtimeContext,
      providerResult: await provider.executeScoredRequest({
        cell,
        messages: input.messages,
      }),
    });
  }
  return calls;
}

function signedTreatmentEvidence({ agentReceipt, cell, keys, pilotCase, runtimeContextSha256 }) {
  const decisionId = "pilot-result-decision";
  const contractSha256 = digest("contract");
  const renderResultSha256 = digest("render-result");
  const exposureEventSha256 = digest("exposure-event");
  const evidence = buildSignedVerifierEvidenceV1({
    cell_execution_ref: {
      pilot_id: cell.pilot_id,
      opaque_cell_id: cell.opaque_cell_id,
      arm: cell.arm,
      case_id: cell.case_id,
      case_sha256: cell.case_sha256,
      decision_id: decisionId,
      contract_sha256: contractSha256,
      render_result_sha256: renderResultSha256,
      exposure_event_sha256: exposureEventSha256,
    },
    verifier_authority_ref: {
      verifier_id: pilotCase.private_verifier.verifier_id,
      verifier_image_digest: pilotCase.private_verifier.verifier_image_digest,
      verifier_contract_sha256: pilotCase.private_verifier.verifier_contract_sha256,
      verifier_config_sha256: pilotCase.private_verifier.verifier_config_sha256,
    },
    temporal_fence: {
      agent_exit_authority_principal_sha256:
        agentReceipt.agent_exit_authority_principal_sha256,
      agent_exit_receipt_sha256: agentReceipt.agent_exit_receipt_sha256,
      agent_exit_sequence: 10,
      agent_exited_at: agentReceipt.exited_at,
      verifier_runner_parent_agent_exit_receipt_sha256:
        agentReceipt.agent_exit_receipt_sha256,
      verifier_runner_receipt_sha256: digest("verifier-runner-receipt"),
      verifier_runner_sequence: 11,
      verifier_started_at: "2026-07-22T00:00:12.000Z",
      fresh_process: true,
      after_agent_exit: true,
    },
    inputs: {
      workspace_before_sha256: agentReceipt.workspace_before_sha256,
      workspace_after_sha256: agentReceipt.workspace_after_sha256,
      diff_sha256: digest("diff"),
      action_trace_sha256: agentReceipt.action_trace_sha256,
      task_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
    },
    checks: [{
      check_id: "pilot-result-verifier",
      command_argv_sha256: digest("verifier-command"),
      exit_code: 0,
      stdout_sha256: digest("verifier-stdout"),
      stderr_sha256: digest("verifier-stderr"),
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
  }, keys.privateKey);
  return {
    evidence,
    ledger: {
      state: "closed",
      decision_id: decisionId,
      contract_sha256: contractSha256,
      render_result_sha256: renderResultSha256,
      render_content_sha256: runtimeContextSha256,
      exposure_event_sha256: exposureEventSha256,
      record_outcome_operation_id: "pilot-result-outcome-operation",
      request_body_sha256: digest("outcome-body"),
      operation_request_sha256: digest("outcome-request"),
      operation_receipt_sha256: digest("outcome-operation-receipt"),
      use_receipt_sha256: digest("use-receipt"),
      outcome_evidence_sha256: evidence.evidence_sha256,
      ledger_head_event_sha256: digest("ledger-head"),
      full_decision_response_sha256: digest("full-decision-response"),
      effect_state: "not_applicable",
    },
  };
}

function resultBuildInput(result, overrides = {}) {
  return {
    cell: result.cell,
    observation_body_sha256: result.observation_body_sha256,
    runtime_context: result.runtime_context,
    runtime_observation: result.runtime_observation,
    agent_model_input: result.agent_model_input,
    assistant_message: result.assistant_message,
    provider_request_receipt: result.provider_request_receipt,
    provider_response_receipt: result.provider_response_receipt,
    agent_exit_receipt: result.agent_exit_receipt,
    verifier_evidence: result.verifier_evidence,
    infrastructure_failure: result.infrastructure_failure,
    treatment_ledger: result.treatment_ledger,
    ...overrides,
  };
}

test("cell result binds provider input, actual agent exit, signed verifier, and closed ledger", async () => {
  const fixture = await makePlanFixture();
  try {
    const calls = await completedProviderCalls(fixture.plan, fixture.cases[0], 3);
    const treatment = calls[2];
    assert.equal(treatment.cell.arm, "treatment");
    const agentReceipt = await executeAgentActionV1({
      cell: treatment.cell,
      pilotCase: fixture.cases[0],
      executionAuthority: await buildAgentExecutionAuthorityV1({
        cell: treatment.cell,
        pilotCase: fixture.cases[0],
        workspacePath: fixture.workspacePath,
        gitExecutablePath: "/usr/bin/git",
      }),
      assistantContent: treatment.providerResult.assistant_message.content,
      providerResponseReceiptSha256:
        treatment.providerResult.response_receipt.response_receipt_sha256,
      clock: timestampClock(10),
    });
    const signed = signedTreatmentEvidence({
      agentReceipt,
      cell: treatment.cell,
      keys: fixture.keys[0],
      pilotCase: fixture.cases[0],
      runtimeContextSha256: treatment.input.runtime_context_sha256,
    });
    const options = {
      plan: fixture.plan,
      pilotCase: fixture.cases[0],
      verifierPublicKey: fixture.keys[0].publicKey,
    };
    const result = buildPilotCellResultV1({
      cell: treatment.cell,
      observation_body_sha256:
        fixture.cases[0].runtime_input.record_observations_body_sha256,
      runtime_context: treatment.runtimeContext,
      runtime_observation: runtimeObservation(fixture.cases[0], treatment.cell),
      agent_model_input: treatment.input,
      assistant_message: treatment.providerResult.assistant_message,
      provider_request_receipt: treatment.providerResult.request_receipt,
      provider_response_receipt: treatment.providerResult.response_receipt,
      agent_exit_receipt: agentReceipt,
      verifier_evidence: signed.evidence,
      infrastructure_failure: null,
      treatment_ledger: signed.ledger,
    }, options);

    assert.deepEqual(verifyPilotCellResultV1(result, options), result);
    assert.equal(result.evaluation.state, "scored");
    assert.equal(result.evaluation.metrics.action_completion, true);
    assert.equal(result.treatment_ledger.state, "closed");
    assert.equal(isPilotInfrastructureFailureV1(result, options), false);
    assert.equal(isPilotProductFailureV1(result, options), false);

    assert.throws(
      () => buildPilotCellResultV1(resultBuildInput(result, {
        runtime_observation: null,
      }), options),
      /runtime_observation_shape_invalid/u,
    );
    const forgedObservation = canonicalClone(result.runtime_observation);
    forgedObservation.operation_receipt.operation_kind = "create_continuation";
    forgedObservation.operation_receipt_sha256 = canonicalSha256(
      forgedObservation.operation_receipt,
    );
    assert.throws(
      () => buildPilotCellResultV1(resultBuildInput(result, {
        runtime_observation: forgedObservation,
      }), options),
      /runtime_observation_receipt_binding_invalid/u,
    );

    const settlementFailure = buildPilotInfrastructureFailureV1({
      failure_class: "harness_infrastructure",
      stage: "runtime_settlement",
      observed_at: "2026-07-22T00:00:13.000Z",
      evidence_ref_sha256: digest("runtime-settlement-failure-log"),
    });
    const openLedger = {
      ...signed.ledger,
      state: "open",
      record_outcome_operation_id: null,
      request_body_sha256: null,
      operation_request_sha256: null,
      operation_receipt_sha256: null,
      use_receipt_sha256: null,
      outcome_evidence_sha256: null,
      ledger_head_event_sha256: null,
      full_decision_response_sha256: null,
      effect_state: null,
    };
    const settlementUnknown = buildPilotCellResultV1({
      cell: treatment.cell,
      observation_body_sha256:
        fixture.cases[0].runtime_input.record_observations_body_sha256,
      runtime_context: treatment.runtimeContext,
      runtime_observation: runtimeObservation(fixture.cases[0], treatment.cell),
      agent_model_input: treatment.input,
      assistant_message: treatment.providerResult.assistant_message,
      provider_request_receipt: treatment.providerResult.request_receipt,
      provider_response_receipt: treatment.providerResult.response_receipt,
      agent_exit_receipt: agentReceipt,
      verifier_evidence: signed.evidence,
      infrastructure_failure: settlementFailure,
      treatment_ledger: openLedger,
    }, options);
    assert.equal(settlementUnknown.evaluation.state, "unknown");
    assert.equal(settlementUnknown.evaluation.failure_class, "harness_infrastructure");
    assert.equal(settlementUnknown.evaluation.metrics.action_completion, null);
    assert.equal(isPilotProductFailureV1(settlementUnknown, options), false);

    const forgedEvaluation = canonicalClone(result);
    forgedEvaluation.evaluation.metrics.action_completion = false;
    forgedEvaluation.cell_result_sha256 = canonicalSha256(Object.fromEntries(
      Object.entries(forgedEvaluation).filter(([key]) => key !== "cell_result_sha256"),
    ));
    assert.throws(
      () => verifyPilotCellResultV1(forgedEvaluation, options),
      /derived_evaluation_mismatch/u,
    );

    const forgedAgentReceipt = canonicalClone(result);
    forgedAgentReceipt.agent_exit_receipt.workspace_after_sha256 = digest("forged-workspace");
    forgedAgentReceipt.agent_exit_receipt.agent_exit_receipt_sha256 = canonicalSha256(
      Object.fromEntries(Object.entries(forgedAgentReceipt.agent_exit_receipt)
        .filter(([key]) => key !== "agent_exit_receipt_sha256")),
    );
    forgedAgentReceipt.cell_result_sha256 = canonicalSha256(Object.fromEntries(
      Object.entries(forgedAgentReceipt).filter(([key]) => key !== "cell_result_sha256"),
    ));
    assert.throws(
      () => verifyPilotCellResultV1(forgedAgentReceipt, options),
      /(?:receipt_rejected_workspace_mutation|signed_verifier_evidence_binding_invalid)/u,
    );
  } finally {
    await rm(fixture.workspacePath, { recursive: true, force: true });
  }
});

test("provider infrastructure failure is unknown and never counted as product failure", async () => {
  const fixture = await makePlanFixture();
  try {
    const cell = fixture.plan.schedule[0];
    const input = modelInput(fixture.cases[0], cell, null);
    const provider = createDeepSeekProviderV1({
      apiKey: "test-deepseek-secret",
      attemptAuthority: createNonReleaseProviderContractAuthorityV1(fixture.plan.schedule),
      clock: timestampClock(0),
      fetchImpl: async () => { throw new Error("offline"); },
      modelProtocol: fixture.plan.model_protocol,
      pilotId: fixture.plan.pilot_id,
    });
    const providerResult = await provider.executeScoredRequest({
      cell,
      messages: input.messages,
    });
    const failure = buildPilotInfrastructureFailureV1({
      failure_class: "provider_or_network",
      stage: "provider",
      observed_at: providerResult.response_receipt.response_received_at,
      evidence_ref_sha256: providerResult.response_receipt.response_receipt_sha256,
    });
    const options = {
      plan: fixture.plan,
      pilotCase: fixture.cases[0],
      verifierPublicKey: fixture.keys[0].publicKey,
    };
    const result = buildPilotCellResultV1({
      cell,
      observation_body_sha256:
        fixture.cases[0].runtime_input.record_observations_body_sha256,
      runtime_context: null,
      runtime_observation: null,
      agent_model_input: input,
      assistant_message: null,
      provider_request_receipt: providerResult.request_receipt,
      provider_response_receipt: providerResult.response_receipt,
      agent_exit_receipt: null,
      verifier_evidence: null,
      infrastructure_failure: failure,
      treatment_ledger: null,
    }, options);

    assert.equal(result.evaluation.state, "unknown");
    assert.equal(result.evaluation.failure_class, "provider_or_network");
    assert.equal(result.evaluation.metrics.action_completion, null);
    assert.equal(isPilotInfrastructureFailureV1(result, options), true);
    assert.equal(isPilotProductFailureV1(result, options), false);
  } finally {
    await rm(fixture.workspacePath, { recursive: true, force: true });
  }
});

test("completed provider without signed verifier is reject-only and requires an audit ref", async () => {
  const fixture = await makePlanFixture();
  try {
    const [completed] = await completedProviderCalls(fixture.plan, fixture.cases[0], 1);
    const options = {
      plan: fixture.plan,
      pilotCase: fixture.cases[0],
      verifierPublicKey: fixture.keys[0].publicKey,
    };
    const common = {
      cell: completed.cell,
      observation_body_sha256:
        fixture.cases[0].runtime_input.record_observations_body_sha256,
      runtime_context: null,
      runtime_observation: null,
      agent_model_input: completed.input,
      assistant_message: completed.providerResult.assistant_message,
      provider_request_receipt: completed.providerResult.request_receipt,
      provider_response_receipt: completed.providerResult.response_receipt,
      agent_exit_receipt: null,
      verifier_evidence: null,
      treatment_ledger: null,
    };
    assert.throws(
      () => buildPilotCellResultV1({ ...common, infrastructure_failure: null }, options),
      /infrastructure_failure_evidence_missing/u,
    );

    const failure = buildPilotInfrastructureFailureV1({
      failure_class: "harness_infrastructure",
      stage: "agent_execution",
      observed_at: "2026-07-22T00:00:03.000Z",
      evidence_ref_sha256: digest("agent-spawn-failure-log"),
    });
    const result = buildPilotCellResultV1({
      ...common,
      infrastructure_failure: failure,
    }, options);
    assert.equal(result.evaluation.state, "unknown");
    assert.equal(result.evaluation.failure_class, "harness_infrastructure");
    assert.equal(isPilotProductFailureV1(result, options), false);
  } finally {
    await rm(fixture.workspacePath, { recursive: true, force: true });
  }
});
