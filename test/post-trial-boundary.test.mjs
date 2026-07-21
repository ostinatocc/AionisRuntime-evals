import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { captureWorkloadRawResponseIdentity } from "../src/contracts.mjs";
import {
  createCanonicalProviderRequest,
  createProviderExecutionContract,
  parseOpenRouterChatCompletion,
} from "../src/provider-boundary.mjs";
import {
  POST_TRIAL_ROUTE_ORDER,
  assertCanonicalPostTrialRequest,
  createCanonicalPostTrialRequest,
  createPostTrialExecution,
  derivePostTrialSettlementFacts,
  parsePostTrialRuntimeResponse,
  verifyMeasureExactReplay,
} from "../src/post-trial-boundary.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RELEASE_LOCK_SOURCE = fs.readFileSync(path.join(ROOT, "config/v0.3.12-release-lock.json"));
const WORKLOAD_SOURCE = fs.readFileSync(path.join(ROOT, "fixtures/v0.3.12/workload-manifest.json"));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

function executionContract() {
  return createProviderExecutionContract({
    releaseLockSource: RELEASE_LOCK_SOURCE,
    workloadSource: WORKLOAD_SOURCE,
    frozenBindings: {
      release_lock_sha256: sha256(RELEASE_LOCK_SOURCE),
      workload_manifest_sha256: sha256(WORKLOAD_SOURCE),
    },
  });
}

function ledgerContext({
  group = "aionis",
  scenario = "branch_recovery",
  surface = "use_now",
} = {}) {
  const guideOperationId = `guide-${group}-${scenario}`;
  const tenantId = "default";
  const scope = `eval/contract/${scenario}`;
  const surfaceIds = {
    use_now_memory_ids: surface === "use_now" ? [`seed-${scenario}-1`] : [],
    inspect_before_use_memory_ids: surface === "inspect_before_use" ? [`seed-${scenario}-1`] : [],
    do_not_use_memory_ids: surface === "do_not_use" ? [`seed-${scenario}-1`] : [],
  };
  return {
    trial: {
      trial_id: `pilot:w1:${group}:${scenario}:r1`,
      phase: "pilot",
      wave: 1,
      group,
      scenario,
      repetition: 1,
      preclaim: {
        request_id: `request-${scenario}`,
        tenant_id: tenantId,
        guide_operation_id: guideOperationId,
        outcome_operation_id: `outcome-${scenario}`,
        feedback_operation_id: `feedback-${scenario}`,
        measure_operation_id: `measure-${scenario}`,
        scope,
      },
      status: "claimed",
    },
    guide_response: group === "aionis"
      ? {
          contract_version: "aionis_guide_result_v1",
          operation_id: guideOperationId,
          tenant_id: tenantId,
          scope,
          guide_trace_id: `trace-${scenario}`,
          agent_context: {
            prompt_text: "Use the prior verified execution branch.",
            ...surfaceIds,
          },
          guide_packet: {
            contract_version: "aionis_guide_packet_v1",
            task_signature: `bounded-soak:${scenario}`,
          },
        }
      : null,
  };
}

function parsedProviderBoundary(contract, context, choice = null) {
  const scenario = contract.workload.scenario_definitions
    .find((entry) => entry.id === context.trial.scenario);
  const selectedChoice = choice ?? scenario.expected_choice;
  const request = createCanonicalProviderRequest({ contract, ledgerContext: context });
  const raw = Buffer.from(JSON.stringify({
    id: `generation-${context.trial.scenario}`,
    model: contract.release_lock.providers.agent.requested_model,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: `call-${context.trial.scenario}`,
          type: "function",
          function: {
            name: contract.workload.tool_protocol.function.name,
            arguments: JSON.stringify({
              scenario_id: context.trial.scenario,
              choice: selectedChoice,
            }),
          },
        }],
      },
      finish_reason: "tool_calls",
    }],
    usage: {
      prompt_tokens: 100,
      completion_tokens: 7,
      total_tokens: 107,
      cost: 0.001,
    },
  }), "utf8");
  return parseOpenRouterChatCompletion({
    contract,
    ledgerContext: context,
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: raw,
  });
}

function postTrialExecution(options = {}) {
  const contract = executionContract();
  const context = ledgerContext(options);
  const providerBoundary = parsedProviderBoundary(contract, context, options.choice);
  return {
    contract,
    context,
    providerBoundary,
    execution: createPostTrialExecution({ contract, ledgerContext: context, providerBoundary }),
  };
}

function outcomeResponse(execution, nodes = [{
  client_id: "outcome-client-1",
  id: "outcome-memory-1",
}]) {
  return {
    contract_version: "aionis_observe_result_v1",
    operation_id: `outcome-${execution.tool_result.scenario_id}`,
    tenant_id: execution.tenant_id,
    scope: execution.scope,
    observed: {
      memory_written: true,
      handoff_stored: false,
      general_memory_count: 0,
      execution_memory_count: nodes.length,
      auto_text_memory_count: 0,
      execution_observation_count: 1,
    },
    memory_write: {
      tenant_id: execution.tenant_id,
      scope: execution.scope,
      commit_id: "commit-outcome",
      commit_hash: "1".repeat(64),
      nodes: nodes.map(({ client_id: clientId, id }) => ({
        id,
        uri: `aionis://memory/${id}`,
        client_id: clientId,
        type: "execution",
      })),
      edges: [],
    },
    post_commit_projections: {
      semantic_commit: "committed",
      embedding: "scheduled",
      ann_sync: "scheduled",
    },
  };
}

function feedbackResponse(execution, learningAttributionStatus = "legacy_unverified") {
  return {
    contract_version: "aionis_feedback_result_v1",
    operation_id: `feedback-${execution.tool_result.scenario_id}`,
    tenant_id: execution.tenant_id,
    scope: execution.scope,
    product_action: "feedback",
    operation: "activate",
    target: "memory",
    learning_attribution_status: learningAttributionStatus,
    learning_episode_id: `episode-${execution.tool_result.scenario_id}`,
    learning_feedback_event_id: `lfeedback-${execution.tool_result.scenario_id}`,
    forget_effect: { activated: 1 },
    result: { commit_id: "commit-feedback" },
  };
}

function measureResponse(execution) {
  return {
    contract_version: "aionis_measure_result_v1",
    operation_id: `measure-${execution.tool_result.scenario_id}`,
    tenant_id: execution.tenant_id,
    scope: execution.scope,
    measurement_id: `measurement:${execution.tool_result.scenario_id}`,
    measurement_digest: "2".repeat(64),
    measurement_persisted: true,
    evidence_assessment: { status: "sufficient" },
  };
}

function snapshotResponse(execution) {
  return {
    contract_version: "aionis_operator_snapshot_result_v1",
    tenant_id: execution.tenant_id,
    scope: execution.scope,
    operator_snapshot: {
      contract_version: "aionis_operator_snapshot_v1",
      guide_trace_id: execution.guide_trace_id,
    },
    source_map: { routes_used: ["/v1/operator/snapshot"] },
  };
}

function recorderResponse(execution) {
  return {
    contract_version: "aionis_agent_flight_recorder_result_v1",
    tenant_id: execution.tenant_id,
    scope: execution.scope,
    agent_flight_recorder: {
      contract_version: "aionis_agent_flight_recorder_v1",
      guide_trace_id: execution.guide_trace_id,
    },
    source_map: { routes_used: ["/v1/audit/flight-recorder"] },
  };
}

function parseStage(execution, stage, priorResponses, response, rawOverride = null) {
  const request = createCanonicalPostTrialRequest({ execution, stage, priorResponses });
  const raw = rawOverride ?? Buffer.from(JSON.stringify(response), "utf8");
  const checkpoint = parsePostTrialRuntimeResponse({
    execution,
    stage,
    priorResponses,
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: raw,
  });
  return { request, raw, checkpoint };
}

function completePostTrial(execution, learningAttributionStatus = "legacy_unverified") {
  const outcome = parseStage(execution, "outcome_observe", [], outcomeResponse(execution));
  const feedback = parseStage(
    execution,
    "feedback",
    [outcome.checkpoint],
    feedbackResponse(execution, learningAttributionStatus),
  );
  const measureBody = measureResponse(execution);
  const measure = parseStage(
    execution,
    "measure",
    [outcome.checkpoint, feedback.checkpoint],
    measureBody,
  );
  const replay = parseStage(
    execution,
    "measure_replay",
    [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
    measureBody,
    measure.raw,
  );
  const snapshot = parseStage(
    execution,
    "operator_snapshot",
    [outcome.checkpoint, feedback.checkpoint, measure.checkpoint, replay.checkpoint],
    snapshotResponse(execution),
  );
  const recorder = parseStage(
    execution,
    "flight_recorder",
    [
      outcome.checkpoint,
      feedback.checkpoint,
      measure.checkpoint,
      replay.checkpoint,
      snapshot.checkpoint,
    ],
    recorderResponse(execution),
  );
  return { outcome, feedback, measure, replay, snapshot, recorder };
}

test("post-trial execution joins the frozen Aionis trial, guide, provider result, and route order", () => {
  const { contract, context, providerBoundary, execution } = postTrialExecution();
  assert.equal(execution.schema_version, "aionis_post_trial_execution_v1");
  assert.equal(execution.trial_id, context.trial.trial_id);
  assert.equal(execution.guide_operation_id, context.trial.preclaim.guide_operation_id);
  assert.equal(execution.provider_request_id, providerBoundary.provider_request_id);
  assert.deepEqual(execution.served_memory_selection, {
    surface: "use_now",
    ids: ["seed-branch_recovery-1"],
  });
  assert.deepEqual(execution.route_order, POST_TRIAL_ROUTE_ORDER);
  assert.equal(Object.isFrozen(execution), true);
  assert.equal(Object.isFrozen(execution.tool_result), true);

  const drifted = structuredClone(providerBoundary);
  drifted.request_sha256 = "0".repeat(64);
  assert.throws(() => createPostTrialExecution({
    contract,
    ledgerContext: context,
    providerBoundary: drifted,
  }), /must come directly from parseOpenRouterChatCompletion/);

  const baselineContext = ledgerContext({ group: "baseline" });
  assert.throws(() => createPostTrialExecution({
    contract,
    ledgerContext: baselineContext,
    providerBoundary,
  }), /only for Aionis trials/);
});

test("canonical requests follow the frozen route order and consume only prior Runtime checkpoints", () => {
  const { execution } = postTrialExecution();
  const outcome = parseStage(execution, "outcome_observe", [], outcomeResponse(execution));
  assert.deepEqual(Object.keys(outcome.request.body).sort(), [
    "auto_embed",
    "execution",
    "input_text",
    "memory_kind",
    "operation_id",
    "scope",
    "tenant_id",
  ]);
  assert.equal(outcome.request.route, "/v1/observe");
  assert.equal(outcome.request.body.execution.evidence_ref, execution.provider_request_id);
  assert.equal(outcome.request.bytes.includes(0x0a), false);
  assert.equal(outcome.request.sha256, sha256(outcome.request.bytes));

  assert.throws(() => createCanonicalPostTrialRequest({
    execution,
    stage: "feedback",
    priorResponses: [],
  }), /requires the outcome_observe checkpoint/);
  const feedback = parseStage(execution, "feedback", [outcome.checkpoint], feedbackResponse(execution));
  assert.equal(feedback.request.route, "/v1/feedback");
  assert.deepEqual(feedback.request.body.used_memory_ids, ["seed-branch_recovery-1"]);
  assert.equal(feedback.request.body.used_surface, "use_now");
  assert.equal(feedback.request.body.outcome, "positive");
  assert.equal(feedback.checkpoint.learning_attribution_status, "legacy_unverified");
  assert.deepEqual(outcome.checkpoint.outcome_memory_bindings, [{
    client_id: "outcome-client-1",
    memory_id: "outcome-memory-1",
  }]);

  const measure = parseStage(
    execution,
    "measure",
    [outcome.checkpoint, feedback.checkpoint],
    measureResponse(execution),
  );
  assert.equal(measure.request.route, "/v1/measure");
  assert.equal(
    measure.request.body.product_trace.forget_result.learning_feedback_event_id,
    feedback.checkpoint.feedback_id,
  );
  const replay = createCanonicalPostTrialRequest({
    execution,
    stage: "measure_replay",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
  });
  assert.equal(replay.route, measure.request.route);
  assert.deepEqual(replay.bytes, measure.request.bytes);

  const snapshot = parseStage(
    execution,
    "operator_snapshot",
    [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
    snapshotResponse(execution),
  );
  assert.equal(snapshot.request.body.include_markdown, false);
  const recorder = createCanonicalPostTrialRequest({
    execution,
    stage: "flight_recorder",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint, snapshot.checkpoint],
  });
  assert.deepEqual(recorder.body.operator_snapshot, snapshotResponse(execution).operator_snapshot);
  assert.equal(recorder.body.feedback_result.learning_feedback_event_id, feedback.checkpoint.feedback_id);
});

test("exact Runtime bytes derive operation echoes, memory and learning IDs, content IDs, and exact replay", () => {
  const { execution } = postTrialExecution();
  const stages = completePostTrial(execution);
  const replayEvidence = verifyMeasureExactReplay({
    execution,
    measure: stages.measure.checkpoint,
    replay: stages.replay.checkpoint,
  });
  assert.deepEqual(replayEvidence, {
    replayed_operation_id: "measure-branch_recovery",
    original_request_sha256: stages.measure.checkpoint.request_sha256,
    replay_request_sha256: stages.measure.checkpoint.request_sha256,
    original_response_sha256: sha256(stages.measure.raw),
    replay_response_sha256: sha256(stages.measure.raw),
  });

  const facts = derivePostTrialSettlementFacts({
    execution,
    responses: Object.values(stages).map((entry) => entry.checkpoint),
  });
  const expectedSnapshot = captureWorkloadRawResponseIdentity(
    "snapshot",
    execution.trial_id,
    stages.snapshot.raw,
  );
  const expectedRecorder = captureWorkloadRawResponseIdentity(
    "recorder",
    execution.trial_id,
    stages.recorder.raw,
  );
  assert.deepEqual(facts, {
    runtime_echoed_outcome_operation_id: "outcome-branch_recovery",
    runtime_echoed_feedback_operation_id: "feedback-branch_recovery",
    runtime_echoed_measure_operation_id: "measure-branch_recovery",
    feedback_id: "lfeedback-branch_recovery",
    learning_attribution_status: "legacy_unverified",
    measure_id: "measurement:branch_recovery",
    snapshot_id: expectedSnapshot.snapshot_id,
    snapshot_response_sha256: expectedSnapshot.snapshot_response_sha256,
    recorder_id: expectedRecorder.recorder_id,
    recorder_response_sha256: expectedRecorder.recorder_response_sha256,
    runtime_tenant_id: execution.tenant_id,
    runtime_scope: execution.scope,
    outcome_response_sha256: sha256(stages.outcome.raw),
    feedback_response_sha256: sha256(stages.feedback.raw),
    measure_response_sha256: sha256(stages.measure.raw),
    outcome_memory_ids: ["outcome-memory-1"],
    outcome_memory_bindings: [{
      client_id: "outcome-client-1",
      memory_id: "outcome-memory-1",
    }],
    replay_evidence: {
      replayed_operation_id: "measure-branch_recovery",
      original_response_sha256: sha256(stages.measure.raw),
      replay_response_sha256: sha256(stages.measure.raw),
    },
  });
  assert.equal(Object.isFrozen(facts), true);
  assert.equal(Object.isFrozen(facts.outcome_memory_bindings), true);
  assert.equal(Object.isFrozen(facts.outcome_memory_bindings[0]), true);
  assert.equal(Object.isFrozen(facts.replay_evidence), true);
  assert.equal(Object.hasOwn(stages.snapshot.checkpoint, "operator_snapshot"), false);
  assert.equal(Object.hasOwn(stages.recorder.checkpoint, "agent_flight_recorder"), false);

  const driftedOutcome = structuredClone(stages.outcome.checkpoint);
  driftedOutcome.outcome_memory_bindings[0].memory_id = "drifted-outcome-memory";
  const driftedResponses = Object.values(stages).map((entry) => entry.checkpoint);
  driftedResponses[0] = driftedOutcome;
  assert.throws(() => derivePostTrialSettlementFacts({
    execution,
    responses: driftedResponses,
  }), /must be a module-issued/);
});

test("feedback attribution status remains explicit through checkpoints and settlement facts", () => {
  const legacyExecution = postTrialExecution().execution;
  const legacyStages = completePostTrial(legacyExecution, "legacy_unverified");
  assert.equal(legacyStages.feedback.checkpoint.learning_attribution_status, "legacy_unverified");
  assert.equal(derivePostTrialSettlementFacts({
    execution: legacyExecution,
    responses: Object.values(legacyStages).map((entry) => entry.checkpoint),
  }).learning_attribution_status, "legacy_unverified");

  const verifiedExecution = postTrialExecution().execution;
  const verifiedStages = completePostTrial(verifiedExecution, "verified_host_receipt");
  assert.equal(verifiedStages.feedback.checkpoint.learning_attribution_status, "verified_host_receipt");
  assert.equal(derivePostTrialSettlementFacts({
    execution: verifiedExecution,
    responses: Object.values(verifiedStages).map((entry) => entry.checkpoint),
  }).learning_attribution_status, "verified_host_receipt");
});

test("request and checkpoint authority rejects reserialization, forgery, cross-trial use, and duplicates", () => {
  const first = postTrialExecution();
  const outcome = parseStage(first.execution, "outcome_observe", [], outcomeResponse(first.execution));
  assert.throws(() => assertCanonicalPostTrialRequest({
    execution: first.execution,
    stage: "feedback",
    priorResponses: [outcome.checkpoint],
    requestBytes: Buffer.from(`${JSON.stringify(createCanonicalPostTrialRequest({
      execution: first.execution,
      stage: "feedback",
      priorResponses: [outcome.checkpoint],
    }).body, null, 2)}\n`),
  }), /not the exact canonical compact UTF-8 body/);

  assert.throws(() => createCanonicalPostTrialRequest({
    execution: first.execution,
    stage: "feedback",
    priorResponses: [structuredClone(outcome.checkpoint)],
  }), /module-issued/);
  assert.throws(() => createCanonicalPostTrialRequest({
    execution: first.execution,
    stage: "feedback",
    priorResponses: [outcome.checkpoint, outcome.checkpoint],
  }), /duplicate outcome_observe/);

  const second = postTrialExecution({ scenario: "summary_only_inspect", surface: "inspect_before_use" });
  assert.throws(() => createCanonicalPostTrialRequest({
    execution: second.execution,
    stage: "feedback",
    priorResponses: [outcome.checkpoint],
  }), /belongs to another/);
});

test("Runtime parser fails closed on HTTP, duplicate keys, BOM, identity drift, and missing durable facts", () => {
  const { execution } = postTrialExecution();
  const request = createCanonicalPostTrialRequest({ execution, stage: "outcome_observe" });
  const validOutcome = outcomeResponse(execution);
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 503,
    responseBytes: Buffer.from(JSON.stringify(validOutcome)),
  }), /HTTP status must be exactly 200/);

  const duplicate = JSON.stringify(validOutcome).replace(
    '"operation_id":"outcome-branch_recovery"',
    '"operation_id":"outcome-branch_recovery","operation_id":"outcome-branch_recovery"',
  );
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(duplicate),
  }), /duplicate object key/);

  const wrongEcho = structuredClone(validOutcome);
  wrongEcho.operation_id = "outcome-from-another-trial";
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(wrongEcho)),
  }), /does not echo/);

  const noMemory = structuredClone(validOutcome);
  noMemory.memory_write.nodes = [];
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(noMemory)),
  }), /exactly one outcome memory node/);

  const missingClientId = structuredClone(validOutcome);
  delete missingClientId.memory_write.nodes[0].client_id;
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(missingClientId)),
  }), /nodes\[0\]\.client_id must be a non-empty/);

  const missingMemoryId = structuredClone(validOutcome);
  delete missingMemoryId.memory_write.nodes[0].id;
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(missingMemoryId)),
  }), /nodes\[0\]\.id must be a non-empty/);

  const multipleMemories = structuredClone(validOutcome);
  multipleMemories.memory_write.nodes.push({
    id: "outcome-memory-2",
    uri: "aionis://memory/outcome-memory-2",
    client_id: "outcome-client-2",
    type: "execution",
  });
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(multipleMemories)),
  }), /exactly one outcome memory node/);

  const duplicateMemory = structuredClone(validOutcome);
  duplicateMemory.memory_write.nodes.push(structuredClone(duplicateMemory.memory_write.nodes[0]));
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(duplicateMemory)),
  }), /exactly one outcome memory node/);

  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "outcome_observe",
    requestBytes: request.bytes,
    httpStatus: 200,
    responseBytes: Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      Buffer.from(JSON.stringify(validOutcome)),
    ]),
  }), /must not contain a UTF-8 BOM/);

  const outcome = parseStage(execution, "outcome_observe", [], validOutcome);
  const feedbackRequest = createCanonicalPostTrialRequest({
    execution,
    stage: "feedback",
    priorResponses: [outcome.checkpoint],
  });
  const missingFeedbackId = feedbackResponse(execution);
  missingFeedbackId.learning_feedback_event_id = null;
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "feedback",
    priorResponses: [outcome.checkpoint],
    requestBytes: feedbackRequest.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(missingFeedbackId)),
  }), /learning_feedback_event_id must be a non-empty/);

  for (const invalidStatus of [undefined, "", "tool_decision", "trusted"]) {
    const invalidFeedback = feedbackResponse(execution);
    invalidFeedback.learning_attribution_status = invalidStatus;
    assert.throws(() => parsePostTrialRuntimeResponse({
      execution,
      stage: "feedback",
      priorResponses: [outcome.checkpoint],
      requestBytes: feedbackRequest.bytes,
      httpStatus: 200,
      responseBytes: Buffer.from(JSON.stringify(invalidFeedback)),
    }), /learning_attribution_status/);
  }

  for (const supportedStatus of [
    "not_attributed",
    "legacy_unverified",
    "verified_host_receipt",
  ]) {
    const supportedFeedback = feedbackResponse(execution);
    supportedFeedback.learning_attribution_status = supportedStatus;
    const parsed = parsePostTrialRuntimeResponse({
      execution,
      stage: "feedback",
      priorResponses: [outcome.checkpoint],
      requestBytes: feedbackRequest.bytes,
      httpStatus: 200,
      responseBytes: Buffer.from(JSON.stringify(supportedFeedback)),
    });
    assert.equal(parsed.learning_attribution_status, supportedStatus);
  }

  const feedback = parseStage(
    execution,
    "feedback",
    [outcome.checkpoint],
    feedbackResponse(execution),
  );
  const measureRequest = createCanonicalPostTrialRequest({
    execution,
    stage: "measure",
    priorResponses: [outcome.checkpoint, feedback.checkpoint],
  });
  const unpersistedMeasure = measureResponse(execution);
  unpersistedMeasure.measurement_persisted = false;
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "measure",
    priorResponses: [outcome.checkpoint, feedback.checkpoint],
    requestBytes: measureRequest.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(unpersistedMeasure)),
  }), /measurement_persisted must be true/);
});

test("measure replay is byte-exact and snapshot markdown cannot enter retained evidence", () => {
  const { execution } = postTrialExecution();
  const outcome = parseStage(execution, "outcome_observe", [], outcomeResponse(execution));
  const feedback = parseStage(execution, "feedback", [outcome.checkpoint], feedbackResponse(execution));
  const measure = parseStage(
    execution,
    "measure",
    [outcome.checkpoint, feedback.checkpoint],
    measureResponse(execution),
  );
  const replayRequest = createCanonicalPostTrialRequest({
    execution,
    stage: "measure_replay",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
  });
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "measure_replay",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
    requestBytes: replayRequest.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(`${JSON.stringify(measureResponse(execution))}\n`),
  }), /response bytes differ/);

  const snapshot = snapshotResponse(execution);
  snapshot.markdown = "# must not be retained";
  const snapshotRequest = createCanonicalPostTrialRequest({
    execution,
    stage: "operator_snapshot",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
  });
  assert.throws(() => parsePostTrialRuntimeResponse({
    execution,
    stage: "operator_snapshot",
    priorResponses: [outcome.checkpoint, feedback.checkpoint, measure.checkpoint],
    requestBytes: snapshotRequest.bytes,
    httpStatus: 200,
    responseBytes: Buffer.from(JSON.stringify(snapshot)),
  }), /markdown must remain absent/);
});
