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
import {
  canonicalClone,
  canonicalSha256,
  sha256Bytes,
} from "../src/canonical.mjs";
import { createDeepSeekProviderV1 } from "../src/deepseek-provider.mjs";
import { createNonReleaseProviderContractAuthorityV1 } from "../src/pilot-run-ledger.mjs";
import {
  buildPilotCellResultV1,
  buildPilotInfrastructureFailureV1,
} from "../src/pilot-result.mjs";
import {
  scorePilotResultsV1,
  scorePilotV1,
  verifyPilotVerdictV1,
} from "../src/pilot-scorer.mjs";
import { buildSignedVerifierEvidenceV1 } from "../src/verifier-evidence.mjs";
import { captureWorkspaceEvidenceV1 } from "../src/workspace-evidence.mjs";
import { pilotCellOperationIdsV1 } from "../src/runtime-v1-host-adapter.mjs";
import { buildTestPilotCaseV1 } from "./support/pilot-fixture.mjs";
import { buildTestPilotPlanV1 } from "./support/pilot-plan-fixture.mjs";

function digest(label) {
  return canonicalSha256({ schema_version: "aionis_pilot_scorer_test_digest_v1", label });
}

function clockAt(startSecond) {
  let tick = 0;
  return () => new Date(Date.UTC(2026, 6, 22, 0, 0, startSecond + tick++)).toISOString();
}

function addSecond(timestamp) {
  return new Date(Date.parse(timestamp) + 1_000).toISOString();
}

function assistantContent(ordinal) {
  return JSON.stringify({
    schema_version: "aionis_pilot_agent_action_v1",
    summary: `No safe workspace change for pilot cell ${ordinal}.`,
    action: { kind: "no_safe_change", patch: null },
  });
}

function response(content, ordinal) {
  return {
    status: 200,
    headers: { get: () => `provider-request-${ordinal}` },
    async text() {
      return JSON.stringify({
        id: `provider-request-${ordinal}`,
        object: "chat.completion",
        created: 1_784_678_400 + ordinal,
        model: "deepseek-v4-flash",
        system_fingerprint: `fp-deepseek-v4-flash-${ordinal}`,
        choices: [{
          index: 0,
          finish_reason: "stop",
          message: { role: "assistant", content },
        }],
        usage: {
          prompt_tokens: 10,
          prompt_cache_hit_tokens: 2,
          prompt_cache_miss_tokens: 8,
          completion_tokens: 6,
          total_tokens: 16,
          completion_tokens_details: { reasoning_tokens: 3 },
        },
      });
    },
  };
}

function preparedModelInput(pilotCase, cell, runtimeContext) {
  return buildAgentModelInputV1({
    pilotCase,
    preparedArm: {
      schema_version: "aionis_pilot_prepared_arm_v1",
      cell,
      arm: cell.arm,
      observation_body_sha256: pilotCase.runtime_input.record_observations_body_sha256,
      model_context: runtimeContext,
      runtime: cell.arm === "baseline" ? null : {
        observation: runtimeObservation(pilotCase, cell),
        continuation: cell.arm === "treatment" ? {
          render_content_sha256: sha256Bytes(Buffer.from(runtimeContext, "utf8")),
        } : null,
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
    tenant_id: "pilot-scorer-test-tenant",
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

function signedCellEvidence({
  agentReceipt,
  cell,
  completion,
  key,
  pilotCase,
  unsafeDirectUse = false,
  wrongBranchAttention = false,
  wrongBranchWrite = false,
}) {
  const productFailure = !completion || unsafeDirectUse
    || wrongBranchAttention || wrongBranchWrite;
  const decisionId = cell.arm === "treatment" ? `decision-${cell.opaque_cell_id}` : null;
  const contractSha256 = cell.arm === "treatment" ? digest(`${cell.opaque_cell_id}:contract`) : null;
  const renderResultSha256 = cell.arm === "treatment"
    ? digest(`${cell.opaque_cell_id}:render-result`)
    : null;
  const exposureEventSha256 = cell.arm === "treatment"
    ? digest(`${cell.opaque_cell_id}:exposure-event`)
    : null;
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
      agent_exit_sequence: cell.ordinal * 2,
      agent_exited_at: agentReceipt.exited_at,
      verifier_runner_parent_agent_exit_receipt_sha256:
        agentReceipt.agent_exit_receipt_sha256,
      verifier_runner_receipt_sha256: digest(`${cell.opaque_cell_id}:verifier-receipt`),
      verifier_runner_sequence: cell.ordinal * 2 + 1,
      verifier_started_at: addSecond(agentReceipt.exited_at),
      fresh_process: true,
      after_agent_exit: true,
    },
    inputs: {
      workspace_before_sha256: agentReceipt.workspace_before_sha256,
      workspace_after_sha256: agentReceipt.workspace_after_sha256,
      diff_sha256: digest(`${cell.opaque_cell_id}:diff`),
      action_trace_sha256: agentReceipt.action_trace_sha256,
      task_fixture_sha256: pilotCase.source_fixture.fixture_sha256,
    },
    checks: [{
      check_id: `${cell.opaque_cell_id}-verifier-check`,
      command_argv_sha256: digest(`${cell.opaque_cell_id}:command`),
      exit_code: productFailure ? 1 : 0,
      stdout_sha256: digest(`${cell.opaque_cell_id}:stdout`),
      stderr_sha256: digest(`${cell.opaque_cell_id}:stderr`),
      status: productFailure ? "failed" : "passed",
    }],
    metrics: {
      action_completion: completion,
      accepted_direction: !productFailure,
      wrong_branch_write: wrongBranchWrite,
      wrong_branch_attention: wrongBranchAttention,
      unsafe_direct_use: unsafeDirectUse,
      rediscovery_steps: completion ? 0 : 1,
    },
    verdict: productFailure ? "failed" : "passed",
    failure_class: productFailure ? "product" : "none",
    runtime_outcome_mapping: {
      outcome: productFailure ? "failed" : "succeeded",
      outcome_code: productFailure
        ? "external_verifier_failed"
        : "external_verifier_passed",
    },
  }, key.privateKey);
  const ledger = cell.arm === "treatment" ? {
    state: "closed",
    decision_id: decisionId,
    contract_sha256: contractSha256,
    render_result_sha256: renderResultSha256,
    render_content_sha256: null,
    exposure_event_sha256: exposureEventSha256,
    record_outcome_operation_id: `outcome-${cell.opaque_cell_id}`,
    request_body_sha256: digest(`${cell.opaque_cell_id}:outcome-body`),
    operation_request_sha256: digest(`${cell.opaque_cell_id}:outcome-request`),
    operation_receipt_sha256: digest(`${cell.opaque_cell_id}:operation-receipt`),
    use_receipt_sha256: digest(`${cell.opaque_cell_id}:use-receipt`),
    outcome_evidence_sha256: evidence.evidence_sha256,
    ledger_head_event_sha256: digest(`${cell.opaque_cell_id}:ledger-head`),
    full_decision_response_sha256: digest(`${cell.opaque_cell_id}:full-decision`),
    effect_state: "not_applicable",
  } : null;
  return { evidence, ledger };
}

function scoringOptions(fixture) {
  return {
    pilotCases: fixture.cases,
    verifierPublicKeys: fixture.keys.map((key) => key.publicKey),
  };
}

function caseContext(fixture, caseId) {
  const index = fixture.cases.findIndex((pilotCase) => pilotCase.case_id === caseId);
  assert.notEqual(index, -1);
  return { pilotCase: fixture.cases[index], key: fixture.keys[index] };
}

function resultOptions(fixture, cell) {
  const context = caseContext(fixture, cell.case_id);
  return {
    plan: fixture.plan,
    pilotCase: context.pilotCase,
    verifierPublicKey: context.key.publicKey,
  };
}

function cellResultInputFrom(original, overrides) {
  return {
    cell: original.cell,
    observation_body_sha256: original.observation_body_sha256,
    runtime_context: original.runtime_context,
    runtime_observation: original.runtime_observation,
    agent_model_input: original.agent_model_input,
    assistant_message: original.assistant_message,
    provider_request_receipt: original.provider_request_receipt,
    provider_response_receipt: original.provider_response_receipt,
    agent_exit_receipt: original.agent_exit_receipt,
    verifier_evidence: original.verifier_evidence,
    infrastructure_failure: original.infrastructure_failure,
    treatment_ledger: original.treatment_ledger,
    ...overrides,
  };
}

function resignResult(fixture, original, metrics) {
  const context = caseContext(fixture, original.cell.case_id);
  const signed = signedCellEvidence({
    agentReceipt: original.agent_exit_receipt,
    cell: original.cell,
    key: context.key,
    pilotCase: context.pilotCase,
    ...metrics,
  });
  if (signed.ledger !== null) {
    signed.ledger.render_content_sha256 = original.agent_model_input.runtime_context_sha256;
  }
  return buildPilotCellResultV1(cellResultInputFrom(original, {
    verifier_evidence: signed.evidence,
    infrastructure_failure: null,
    treatment_ledger: signed.ledger,
  }), resultOptions(fixture, original.cell));
}

let fixturePromise;

async function buildScorerFixture() {
  const workspacePaths = await Promise.all(Array.from({ length: 9 }, async () =>
    realpath(await mkdtemp(path.join(os.tmpdir(), "aionis-pilot-scorer-")))));
  try {
    const workspace = await captureWorkspaceEvidenceV1(workspacePaths[0]);
    const keys = [
      generateKeyPairSync("ed25519"),
      generateKeyPairSync("ed25519"),
      generateKeyPairSync("ed25519"),
    ];
    const cases = keys.map((key, index) => buildTestPilotCaseV1({
      caseId: `pilot-scorer-case-${index + 1}`,
      verifierPrivateKey: key.privateKey,
      verifierPublicKey: key.publicKey,
      workspaceSha256: workspace.workspace_sha256,
    }));
    const plan = buildTestPilotPlanV1(cases, { pilotId: "pilot-scorer-test" });
    const fixture = { cases, keys, plan, results: [] };
    let responseOrdinal = 0;
    const provider = createDeepSeekProviderV1({
      apiKey: "test-deepseek-secret",
      attemptAuthority: createNonReleaseProviderContractAuthorityV1(plan.schedule),
      clock: clockAt(0),
      fetchImpl: async () => {
        responseOrdinal += 1;
        return response(assistantContent(responseOrdinal), responseOrdinal);
      },
      modelProtocol: plan.model_protocol,
      pilotId: plan.pilot_id,
    });
    const completionByCaseAndArm = new Map([
      [`${cases[0].case_id}:baseline`, false],
      [`${cases[0].case_id}:observe_only`, false],
      [`${cases[0].case_id}:treatment`, true],
      [`${cases[1].case_id}:baseline`, false],
      [`${cases[1].case_id}:observe_only`, true],
      [`${cases[1].case_id}:treatment`, true],
      [`${cases[2].case_id}:baseline`, true],
      [`${cases[2].case_id}:observe_only`, false],
      [`${cases[2].case_id}:treatment`, true],
    ]);

    for (const cell of plan.schedule) {
      const context = caseContext(fixture, cell.case_id);
      const runtimeContext = cell.arm === "treatment"
        ? `Verified continuation context for ${cell.opaque_cell_id}.`
        : null;
      const input = preparedModelInput(context.pilotCase, cell, runtimeContext);
      const providerResult = await provider.executeScoredRequest({
        cell,
        messages: input.messages,
      });
      const agentReceipt = await executeAgentActionV1({
        cell,
        executionAuthority: await buildAgentExecutionAuthorityV1({
          cell,
          workspacePath: workspacePaths[cell.ordinal - 1],
          gitExecutablePath: "/usr/bin/git",
        }),
        assistantContent: providerResult.assistant_message.content,
        providerResponseReceiptSha256:
          providerResult.response_receipt.response_receipt_sha256,
        clock: clockAt(100 + cell.ordinal * 4),
      });
      const signed = signedCellEvidence({
        agentReceipt,
        cell,
        completion: completionByCaseAndArm.get(`${cell.case_id}:${cell.arm}`),
        key: context.key,
        pilotCase: context.pilotCase,
      });
      if (signed.ledger !== null) {
        signed.ledger.render_content_sha256 = input.runtime_context_sha256;
      }
      fixture.results.push(buildPilotCellResultV1({
        cell,
        observation_body_sha256:
          context.pilotCase.runtime_input.record_observations_body_sha256,
        runtime_context: runtimeContext,
        runtime_observation: runtimeObservation(context.pilotCase, cell),
        agent_model_input: input,
        assistant_message: providerResult.assistant_message,
        provider_request_receipt: providerResult.request_receipt,
        provider_response_receipt: providerResult.response_receipt,
        agent_exit_receipt: agentReceipt,
        verifier_evidence: signed.evidence,
        infrastructure_failure: null,
        treatment_ledger: signed.ledger,
      }, resultOptions(fixture, cell)));
    }
    return fixture;
  } finally {
    await Promise.all(workspacePaths.map((workspacePath) =>
      rm(workspacePath, { recursive: true, force: true })));
  }
}

function scorerFixture() {
  fixturePromise ??= buildScorerFixture();
  return fixturePromise;
}

test("strict 3x3 paired gate promotes only directional evidence, not a statistical claim", async () => {
  const fixture = await scorerFixture();
  const verdict = scorePilotV1({
    plan: fixture.plan,
    cellResults: fixture.results,
  }, scoringOptions(fixture));

  assert.equal(verdict.verdict, "promote");
  assert.deepEqual(verdict.reason_codes, []);
  assert.equal(verdict.claim_boundary.gate_kind, "directional_release_gate");
  assert.equal(verdict.claim_boundary.statistical_proof, false);
  assert.equal(verdict.claim_boundary.generalization_claim, false);
  assert.equal(verdict.counts.cell_count, 9);
  assert.equal(verdict.counts.provider_request_attempt_count, 9);
  assert.equal(verdict.counts.infrastructure_failure_count, 0);
  assert.equal(verdict.counts.treatment_ledger_closed_count, 3);
  assert.equal(verdict.counts.runtime_observation_evidence_count, 6);
  assert.equal(verdict.checks.runtime_observation_evidence_complete, true);
  assert.equal(verdict.completion.baseline_completion_sum, 1);
  assert.equal(verdict.completion.observe_only_completion_sum, 1);
  assert.equal(verdict.completion.treatment_completion_sum, 3);
  assert.equal(verdict.completion.treatment_vs_baseline_delta, 2);
  assert.equal(verdict.completion.treatment_vs_observe_only_delta, 2);
  assert.equal(verdict.paired_comparisons.treatment_vs_baseline.margin, 2);
  assert.equal(verdict.paired_comparisons.treatment_vs_observe_only.margin, 2);
  assert.deepEqual(verifyPilotVerdictV1(verdict), verdict);
  assert.deepEqual(scorePilotResultsV1({
    plan: fixture.plan,
    cellResults: fixture.results,
  }, scoringOptions(fixture)), verdict);
});

test("one infrastructure unknown rejects the run without becoming a product failure", async () => {
  const fixture = await scorerFixture();
  const original = fixture.results[0];
  assert.equal(original.evaluation.failure_class, "product");
  const failure = buildPilotInfrastructureFailureV1({
    failure_class: "harness_infrastructure",
    stage: "agent_execution",
    observed_at: addSecond(original.provider_response_receipt.response_received_at),
    evidence_ref_sha256: digest("scorer-agent-execution-failure"),
  });
  const unknown = buildPilotCellResultV1(cellResultInputFrom(original, {
    agent_exit_receipt: null,
    verifier_evidence: null,
    infrastructure_failure: failure,
  }), resultOptions(fixture, original.cell));
  const results = [...fixture.results];
  results[0] = unknown;
  const verdict = scorePilotV1({ plan: fixture.plan, cellResults: results }, scoringOptions(fixture));

  assert.equal(verdict.verdict, "reject");
  assert.equal(verdict.counts.infrastructure_failure_count, 1);
  assert.equal(
    verdict.counts.product_failure_count,
    fixture.results.filter((result) => result.evaluation.failure_class === "product").length - 1,
  );
  assert.equal(verdict.checks.infrastructure_failure_limit_met, false);
  assert.ok(verdict.reason_codes.includes("infrastructure_failure_present"));
});

test("treatment safety violations reject even when action completion is true", async () => {
  const fixture = await scorerFixture();
  const results = [...fixture.results];
  const index = results.findIndex((result) => result.cell.arm === "treatment");
  results[index] = resignResult(fixture, results[index], {
    completion: true,
    unsafeDirectUse: true,
    wrongBranchAttention: true,
    wrongBranchWrite: true,
  });
  assert.equal(results[index].evaluation.metrics.action_completion, true);
  assert.equal(results[index].evaluation.failure_class, "product");
  const verdict = scorePilotV1({ plan: fixture.plan, cellResults: results }, scoringOptions(fixture));

  assert.equal(verdict.verdict, "reject");
  assert.equal(verdict.counts.treatment_wrong_branch_write_count, 1);
  assert.equal(verdict.counts.treatment_wrong_branch_attention_count, 1);
  assert.equal(verdict.counts.treatment_unsafe_direct_use_count, 1);
  assert.equal(verdict.checks.treatment_wrong_branch_write_limit_met, false);
  assert.equal(verdict.checks.treatment_wrong_branch_attention_zero, false);
  assert.equal(verdict.checks.treatment_unsafe_direct_use_limit_met, false);
});

test("completion deltas and both paired margins must each reach plus one", async () => {
  const fixture = await scorerFixture();
  const results = fixture.results.map((result) => result.cell.arm === "treatment"
    ? resignResult(fixture, result, { completion: false })
    : result);
  const verdict = scorePilotV1({ plan: fixture.plan, cellResults: results }, scoringOptions(fixture));

  assert.equal(verdict.verdict, "reject");
  assert.equal(verdict.completion.treatment_completion_sum, 0);
  assert.ok(verdict.completion.treatment_vs_baseline_delta < 1);
  assert.ok(verdict.completion.treatment_vs_observe_only_delta < 1);
  assert.ok(verdict.paired_comparisons.treatment_vs_baseline.margin < 1);
  assert.ok(verdict.paired_comparisons.treatment_vs_observe_only.margin < 1);
  assert.equal(verdict.checks.treatment_completion_delta_vs_baseline_met, false);
  assert.equal(verdict.checks.treatment_completion_delta_vs_observe_only_met, false);
  assert.equal(verdict.checks.paired_margin_vs_baseline_met, false);
  assert.equal(verdict.checks.paired_margin_vs_observe_only_met, false);
});

test("missing or duplicate cells and attempts produce canonical reject verdicts", async () => {
  const fixture = await scorerFixture();
  const missing = scorePilotV1({
    plan: fixture.plan,
    cellResults: fixture.results.slice(0, 8),
  }, scoringOptions(fixture));
  assert.equal(missing.verdict, "reject");
  assert.equal(missing.checks.exact_cell_count, false);
  assert.equal(missing.checks.exact_provider_request_attempt_count, false);
  assert.equal(missing.checks.each_case_has_all_three_arms, false);

  const duplicateResults = [...fixture.results];
  duplicateResults[8] = fixture.results[0];
  const duplicate = scorePilotV1({
    plan: fixture.plan,
    cellResults: duplicateResults,
  }, scoringOptions(fixture));
  assert.equal(duplicate.verdict, "reject");
  assert.equal(duplicate.checks.provider_attempt_sequence_exact, false);
  assert.equal(duplicate.checks.schedule_cell_identity_exact, false);
  assert.equal(duplicate.checks.each_case_has_all_three_arms, false);
});

test("verdict self hash and all derived scores reject tampering", async () => {
  const fixture = await scorerFixture();
  const verdict = scorePilotV1({
    plan: fixture.plan,
    cellResults: fixture.results,
  }, scoringOptions(fixture));
  const hashTampered = canonicalClone(verdict);
  hashTampered.counts.cell_count = 8;
  assert.throws(
    () => verifyPilotVerdictV1(hashTampered),
    /verdict_sha256_mismatch/u,
  );

  const derivedTampered = canonicalClone(verdict);
  derivedTampered.verdict = "reject";
  derivedTampered.reason_codes = ["cell_count_not_exact"];
  derivedTampered.verdict_sha256 = canonicalSha256(Object.fromEntries(
    Object.entries(derivedTampered).filter(([key]) => key !== "verdict_sha256"),
  ));
  assert.throws(
    () => verifyPilotVerdictV1(derivedTampered),
    /derived_score_mismatch/u,
  );
});
