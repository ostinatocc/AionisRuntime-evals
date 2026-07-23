import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectSha256,
  expectText,
  sha256Bytes,
} from "./canonical.mjs";
import { verifyAgentExitReceiptV1 } from "./agent-execution.mjs";
import { buildAgentModelInputV1 } from "./agent-action.mjs";
import {
  verifyDeepSeekRequestReceiptV1,
  verifyDeepSeekResponseReceiptV1,
} from "./deepseek-provider.mjs";
import {
  verifyPilotCaseV1,
  verifyPilotCellV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";
import { pilotCellOperationIdsV1 } from "./runtime-v1-host-adapter.mjs";
import {
  verifierPublicKeyPrincipalSha256V1,
  verifySignedVerifierEvidenceV1,
} from "./verifier-evidence.mjs";

const SCHEMA_VERSION = "aionis_pilot_cell_result_v1";
const FAILURE_RECEIPT_SCHEMA_VERSION = "aionis_pilot_infrastructure_failure_receipt_v1";

const BODY_KEYS = Object.freeze([
  "agent_exit_receipt",
  "agent_model_input",
  "assistant_message",
  "cell",
  "evaluation",
  "infrastructure_failure",
  "observation_body_sha256",
  "plan_sha256",
  "provider_request_receipt",
  "provider_response_receipt",
  "runtime_context",
  "runtime_observation",
  "schema_version",
  "treatment_ledger",
  "verifier_evidence",
]);

const BUILD_INPUT_KEYS = Object.freeze([
  "agent_exit_receipt",
  "agent_model_input",
  "assistant_message",
  "cell",
  "infrastructure_failure",
  "observation_body_sha256",
  "provider_request_receipt",
  "provider_response_receipt",
  "runtime_context",
  "runtime_observation",
  "treatment_ledger",
  "verifier_evidence",
]);

const RESULT_KEYS = Object.freeze([...BODY_KEYS, "cell_result_sha256"]);

const METRIC_KEYS = Object.freeze([
  "accepted_direction",
  "action_completion",
  "rediscovery_steps",
  "unsafe_direct_use",
  "wrong_branch_attention",
  "wrong_branch_write",
]);

const LEDGER_KEYS = Object.freeze([
  "contract_sha256",
  "decision_id",
  "effect_state",
  "exposure_event_sha256",
  "full_decision_response_sha256",
  "ledger_head_event_sha256",
  "operation_receipt_sha256",
  "operation_request_sha256",
  "outcome_evidence_sha256",
  "record_outcome_operation_id",
  "render_content_sha256",
  "render_result_sha256",
  "request_body_sha256",
  "state",
  "use_receipt_sha256",
]);

const INFRASTRUCTURE_FAILURE_CLASSES = new Set([
  "provider_or_network",
  "harness_infrastructure",
  "filesystem_infrastructure",
  "verifier_infrastructure",
]);

const FAILURE_STAGES = new Set([
  "provider",
  "agent_execution",
  "filesystem",
  "verifier",
  "runtime_settlement",
  "harness",
]);

function fail(code) {
  throw new Error(`aionis_eval_pilot_result_${code}`);
}

function sameCanonical(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function nullMetrics() {
  return {
    accepted_direction: null,
    action_completion: null,
    rediscovery_steps: null,
    unsafe_direct_use: null,
    wrong_branch_attention: null,
    wrong_branch_write: null,
  };
}

function verifyOptions(options, cell) {
  const context = expectExactRecord(options, [
    "pilotCase", "plan", "verifierPublicKey",
  ], "pilot_result_verification_options");
  const plan = verifyPilotPlanV1(context.plan);
  const pilotCase = verifyPilotCaseV1(context.pilotCase);
  if (cell.pilot_id !== plan.pilot_id
    || !plan.cases.some((ref) => ref.case_id === cell.case_id
      && ref.case_sha256 === cell.case_sha256)
    || pilotCase.case_id !== cell.case_id
    || pilotCase.case_sha256 !== cell.case_sha256
    || !plan.schedule.some((scheduled) => sameCanonical(scheduled, cell))) {
    fail("plan_case_cell_binding_invalid");
  }
  if (verifierPublicKeyPrincipalSha256V1(context.verifierPublicKey)
      !== pilotCase.private_verifier.verifier_public_key_principal_sha256) {
    fail("verifier_public_key_binding_invalid");
  }
  return { plan, pilotCase, verifierPublicKey: context.verifierPublicKey };
}

function verifyAgentModelInput(
  value,
  cell,
  pilotCase,
  runtimeContext,
  observationBodySha256,
  runtimeObservation,
) {
  const input = expectExactRecord(value, [
    "messages", "model_input_sha256", "public_prompt_sha256",
    "runtime_context_sha256", "schema_version",
  ], "pilot_result_agent_model_input");
  const expected = buildAgentModelInputV1({
    pilotCase,
    preparedArm: {
      schema_version: "aionis_pilot_prepared_arm_v1",
      cell,
      arm: cell.arm,
      observation_body_sha256: observationBodySha256,
      model_context: runtimeContext,
      runtime: cell.arm === "baseline" ? null : {
        continuation: cell.arm === "treatment" ? {
          render_content_sha256: sha256Bytes(Buffer.from(runtimeContext, "utf8")),
        } : null,
        observation: runtimeObservation,
        settlement: null,
      },
    },
  });
  if (!sameCanonical(input, expected)) fail("agent_model_input_binding_invalid");
  return input;
}

function verifyRuntimeContext(value, arm) {
  if (arm === "treatment") {
    return expectText(value, "pilot_result_runtime_context", {
      controls: true,
      maximumBytes: 1_048_576,
      trimmed: false,
    });
  }
  if (value !== null) fail("control_runtime_context_present");
  return null;
}

function verifyRuntimeObservation(value, cell, pilotCase) {
  if (cell.arm === "baseline") {
    if (value !== null) fail("baseline_runtime_observation_present");
    return null;
  }
  const observation = expectExactRecord(value, [
    "host_task_envelope_sha256",
    "operation_id",
    "operation_receipt",
    "operation_receipt_sha256",
    "operation_request_sha256",
    "request_body_sha256",
    "scope",
    "world_snapshot_id",
    "world_snapshot_sha256",
  ], "pilot_result_runtime_observation");
  const expectedOperationId = pilotCellOperationIdsV1(cell).observation;
  if (observation.operation_id !== expectedOperationId
    || observation.scope !== cell.isolation.runtime_scope
    || observation.request_body_sha256
      !== pilotCase.runtime_input.record_observations_body_sha256) {
    fail("runtime_observation_binding_invalid");
  }
  expectText(observation.operation_id, "runtime_observation_operation_id");
  expectText(observation.scope, "runtime_observation_scope");
  expectText(observation.world_snapshot_id, "runtime_observation_world_snapshot_id");
  for (const field of [
    "request_body_sha256", "operation_request_sha256", "operation_receipt_sha256",
    "world_snapshot_sha256", "host_task_envelope_sha256",
  ]) expectSha256(observation[field], `runtime_observation_${field}`);
  const receipt = expectExactRecord(observation.operation_receipt, [
    "actor_kind",
    "actor_principal_sha256",
    "completed_at",
    "operation_id",
    "operation_kind",
    "request_sha256",
    "result",
    "schema_version",
    "scope",
    "tenant_id",
  ], "runtime_observation_operation_receipt");
  if (receipt.schema_version !== "continuation_runtime_operation_receipt_v1"
    || receipt.operation_kind !== "record_observations"
    || receipt.operation_id !== observation.operation_id
    || receipt.scope !== observation.scope
    || receipt.request_sha256 !== observation.operation_request_sha256
    || canonicalSha256(receipt) !== observation.operation_receipt_sha256) {
    fail("runtime_observation_receipt_binding_invalid");
  }
  for (const field of ["tenant_id", "scope", "operation_id"]) {
    expectText(receipt[field], `runtime_observation_receipt_${field}`);
  }
  if (!new Set(["trusted_host", "operator", "worker"]).has(receipt.actor_kind)) {
    fail("runtime_observation_receipt_actor_kind_invalid");
  }
  expectSha256(
    receipt.actor_principal_sha256,
    "runtime_observation_receipt_actor_principal_sha256",
  );
  expectSha256(receipt.request_sha256, "runtime_observation_receipt_request_sha256");
  expectCanonicalTimestamp(receipt.completed_at, "runtime_observation_receipt_completed_at");
  const result = expectExactRecord(receipt.result, [
    "authority_branch_set",
    "durable_job_set",
    "memory_revision_ref",
    "observation_snapshot_ref",
    "schema_version",
  ], "runtime_observation_receipt_result");
  const snapshot = expectExactRecord(result.observation_snapshot_ref, [
    "host_task_envelope_sha256", "world_snapshot_id", "world_snapshot_sha256",
  ], "runtime_observation_receipt_snapshot_ref");
  if (result.schema_version !== "record_observations_result_v1"
    || observation.world_snapshot_id !== observation.operation_id
    || snapshot.world_snapshot_id !== observation.world_snapshot_id
    || snapshot.world_snapshot_sha256 !== observation.world_snapshot_sha256
    || snapshot.host_task_envelope_sha256 !== observation.host_task_envelope_sha256) {
    fail("runtime_observation_snapshot_binding_invalid");
  }
  return canonicalClone(observation);
}

function verifyFailureReceipt(value) {
  const receipt = expectExactRecord(value, [
    "evidence_ref_sha256",
    "failure_class",
    "failure_receipt_sha256",
    "observed_at",
    "schema_version",
    "stage",
  ], "pilot_infrastructure_failure");
  if (receipt.schema_version !== FAILURE_RECEIPT_SCHEMA_VERSION
    || !INFRASTRUCTURE_FAILURE_CLASSES.has(receipt.failure_class)
    || !FAILURE_STAGES.has(receipt.stage)) fail("infrastructure_failure_value_invalid");
  expectSha256(receipt.evidence_ref_sha256, "infrastructure_failure_evidence_ref_sha256");
  expectCanonicalTimestamp(receipt.observed_at, "infrastructure_failure_observed_at");
  expectSha256(receipt.failure_receipt_sha256, "infrastructure_failure_receipt_sha256");
  const body = Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "failure_receipt_sha256"),
  );
  if (canonicalSha256(body) !== receipt.failure_receipt_sha256) {
    fail("infrastructure_failure_receipt_sha256_mismatch");
  }
  if ((receipt.failure_class === "provider_or_network") !== (receipt.stage === "provider")
    || (receipt.failure_class === "filesystem_infrastructure")
      !== (receipt.stage === "filesystem")
    || (receipt.failure_class === "verifier_infrastructure")
      !== (receipt.stage === "verifier")) {
    fail("infrastructure_failure_stage_mismatch");
  }
  return canonicalClone(receipt);
}

export function buildPilotInfrastructureFailureV1(input) {
  const record = expectExactRecord(input, [
    "evidence_ref_sha256", "failure_class", "observed_at", "stage",
  ], "pilot_infrastructure_failure_input");
  const body = canonicalClone({
    ...record,
    schema_version: FAILURE_RECEIPT_SCHEMA_VERSION,
  });
  return verifyFailureReceipt(canonicalClone({
    ...body,
    failure_receipt_sha256: canonicalSha256(body),
  }));
}

function verifyDefiniteScoredMetrics(metrics, verdict) {
  const record = expectExactRecord(metrics, METRIC_KEYS, "pilot_result_scored_metrics");
  for (const field of [
    "accepted_direction", "action_completion", "unsafe_direct_use",
    "wrong_branch_attention", "wrong_branch_write",
  ]) {
    if (typeof record[field] !== "boolean") fail("scored_metric_missing");
  }
  expectNonNegativeInteger(record.rediscovery_steps, "scored_metric_rediscovery_steps");
  if (verdict === "passed" && record.action_completion !== true) {
    fail("scored_completion_verdict_mismatch");
  }
  return canonicalClone(record);
}

function deriveEvaluation(verifierEvidence, infrastructureFailure) {
  if (infrastructureFailure !== null) {
    return canonicalClone({
      state: "unknown",
      verdict: "inconclusive",
      failure_class: infrastructureFailure.failure_class,
      runtime_outcome: "unknown",
      evidence_sha256: infrastructureFailure.failure_receipt_sha256,
      metrics: nullMetrics(),
    });
  }
  if (verifierEvidence !== null) {
    if (verifierEvidence.verdict === "inconclusive") {
      return canonicalClone({
        state: "unknown",
        verdict: "inconclusive",
        failure_class: verifierEvidence.failure_class,
        runtime_outcome: "unknown",
        evidence_sha256: verifierEvidence.evidence_sha256,
        metrics: nullMetrics(),
      });
    }
    const metrics = verifyDefiniteScoredMetrics(
      verifierEvidence.metrics,
      verifierEvidence.verdict,
    );
    return canonicalClone({
      state: "scored",
      verdict: verifierEvidence.verdict,
      failure_class: verifierEvidence.failure_class,
      runtime_outcome: verifierEvidence.runtime_outcome_mapping.outcome,
      evidence_sha256: verifierEvidence.evidence_sha256,
      metrics,
    });
  }
  fail("infrastructure_failure_evidence_missing");
}

function verifyAgentAndVerifierEvidence({
  agentExitReceipt,
  cell,
  infrastructureFailure,
  pilotCase,
  providerResponse,
  verifierEvidence,
  verifierPublicKey,
}) {
  if (providerResponse.outcome === "inconclusive") {
    if (agentExitReceipt !== null || verifierEvidence !== null
      || infrastructureFailure === null
      || infrastructureFailure.failure_class !== "provider_or_network"
      || infrastructureFailure.stage !== "provider"
      || infrastructureFailure.evidence_ref_sha256
        !== providerResponse.response_receipt_sha256
      || infrastructureFailure.observed_at !== providerResponse.response_received_at) {
      fail("provider_inconclusive_evidence_invalid");
    }
    return { agentExitReceipt: null, verifierEvidence: null };
  }

  let agentReceipt = null;
  if (agentExitReceipt !== null) {
    agentReceipt = verifyAgentExitReceiptV1(agentExitReceipt, cell);
    if (agentReceipt.provider_response_receipt_sha256
        !== providerResponse.response_receipt_sha256
      || agentReceipt.assistant_content_sha256
        !== providerResponse.assistant_content_sha256
      || agentReceipt.workspace_before_sha256 !== pilotCase.workspace.prepared_tree_sha256
      || agentReceipt.started_at < providerResponse.response_received_at) {
      fail("agent_exit_provider_or_workspace_binding_invalid");
    }
  }

  if (verifierEvidence === null) {
    if (infrastructureFailure === null
      || infrastructureFailure.failure_class === "provider_or_network"
      || infrastructureFailure.observed_at < providerResponse.response_received_at) {
      fail("completed_provider_failure_evidence_missing");
    }
    return { agentExitReceipt: agentReceipt, verifierEvidence: null };
  }
  if (agentReceipt === null) {
    fail("signed_verifier_agent_binding_missing");
  }
  const evidence = verifySignedVerifierEvidenceV1(verifierEvidence, verifierPublicKey);
  const cellRef = evidence.cell_execution_ref;
  const authority = evidence.verifier_authority_ref;
  const fence = evidence.temporal_fence;
  if (evidence.failure_class === "provider_or_network"
    || cellRef.pilot_id !== cell.pilot_id
    || cellRef.opaque_cell_id !== cell.opaque_cell_id
    || cellRef.case_id !== cell.case_id
    || cellRef.case_sha256 !== cell.case_sha256
    || cellRef.arm !== cell.arm
    || authority.verifier_id !== pilotCase.private_verifier.verifier_id
    || authority.verifier_image_digest !== pilotCase.private_verifier.verifier_image_digest
    || authority.verifier_contract_sha256
      !== pilotCase.private_verifier.verifier_contract_sha256
    || authority.verifier_config_sha256 !== pilotCase.private_verifier.verifier_config_sha256
    || authority.public_key_principal_sha256
      !== pilotCase.private_verifier.verifier_public_key_principal_sha256
    || fence.agent_exit_receipt_sha256 !== agentReceipt.agent_exit_receipt_sha256
    || fence.verifier_runner_parent_agent_exit_receipt_sha256
      !== agentReceipt.agent_exit_receipt_sha256
    || fence.agent_exited_at !== agentReceipt.exited_at
    || fence.agent_exit_authority_principal_sha256
      !== agentReceipt.agent_exit_authority_principal_sha256
    || evidence.inputs.task_fixture_sha256 !== pilotCase.source_fixture.fixture_sha256
    || evidence.inputs.workspace_before_sha256 !== agentReceipt.workspace_before_sha256
    || evidence.inputs.workspace_after_sha256 !== agentReceipt.workspace_after_sha256
    || evidence.inputs.action_trace_sha256 !== agentReceipt.action_trace_sha256) {
    fail("signed_verifier_evidence_binding_invalid");
  }
  if (infrastructureFailure !== null
    && (cell.arm !== "treatment"
      || infrastructureFailure.failure_class !== "harness_infrastructure"
      || infrastructureFailure.stage !== "runtime_settlement"
      || infrastructureFailure.observed_at < evidence.temporal_fence.verifier_started_at)) {
    fail("post_verifier_infrastructure_failure_invalid");
  }
  return { agentExitReceipt: agentReceipt, verifierEvidence: evidence };
}

function verifyTreatmentLedger(value, evidence, cell, runtimeContextSha256) {
  if (cell.arm !== "treatment") {
    if (value !== null) fail("control_treatment_ledger_present");
    if (evidence !== null) {
      const ref = evidence.cell_execution_ref;
      if (ref.decision_id !== null || ref.contract_sha256 !== null
        || ref.render_result_sha256 !== null || ref.exposure_event_sha256 !== null) {
        fail("control_runtime_ref_present");
      }
    }
    return null;
  }
  const ledger = expectExactRecord(value, LEDGER_KEYS, "pilot_result_treatment_ledger");
  if (!new Set(["open", "closed"]).has(ledger.state)) fail("ledger_state_invalid");
  expectText(ledger.decision_id, "ledger_decision_id");
  for (const field of [
    "contract_sha256", "exposure_event_sha256", "render_content_sha256",
    "render_result_sha256",
  ]) expectSha256(ledger[field], `ledger_${field}`);
  if (ledger.render_content_sha256 !== runtimeContextSha256) {
    fail("treatment_render_content_binding_invalid");
  }
  if (evidence !== null) {
    const ref = evidence.cell_execution_ref;
    if (ref.decision_id !== ledger.decision_id
      || ref.contract_sha256 !== ledger.contract_sha256
      || ref.exposure_event_sha256 !== ledger.exposure_event_sha256
      || ref.render_result_sha256 !== ledger.render_result_sha256) {
      fail("treatment_ledger_verifier_binding_invalid");
    }
  }

  const settlementText = ["record_outcome_operation_id"];
  const settlementDigests = [
    "request_body_sha256", "operation_request_sha256", "operation_receipt_sha256",
    "use_receipt_sha256", "outcome_evidence_sha256", "ledger_head_event_sha256",
    "full_decision_response_sha256",
  ];
  if (ledger.state === "closed") {
    if (evidence === null) fail("closed_ledger_verifier_missing");
    for (const field of settlementText) expectText(ledger[field], `ledger_${field}`);
    for (const field of settlementDigests) expectSha256(ledger[field], `ledger_${field}`);
    if (ledger.effect_state !== "not_applicable"
      || ledger.outcome_evidence_sha256 !== evidence.evidence_sha256) {
      fail("closed_ledger_binding_invalid");
    }
  } else if ([...settlementText, ...settlementDigests, "effect_state"]
    .some((field) => ledger[field] !== null)) {
    fail("open_ledger_settlement_present");
  }
  return canonicalClone(ledger);
}

function verifyBody(value, options) {
  const record = expectExactRecord(value, BODY_KEYS, "pilot_cell_result_body");
  if (record.schema_version !== SCHEMA_VERSION) fail("schema_invalid");
  const cell = verifyPilotCellV1(record.cell);
  const context = verifyOptions(options, cell);
  if (record.plan_sha256 !== context.plan.plan_sha256) fail("plan_sha256_mismatch");
  expectSha256(record.observation_body_sha256, "pilot_result_observation_body_sha256");
  if (record.observation_body_sha256
      !== context.pilotCase.runtime_input.record_observations_body_sha256) {
    fail("observation_body_case_binding_invalid");
  }
  const runtimeContext = verifyRuntimeContext(record.runtime_context, cell.arm);
  const runtimeObservation = verifyRuntimeObservation(
    record.runtime_observation,
    cell,
    context.pilotCase,
  );
  const modelInput = verifyAgentModelInput(
    record.agent_model_input,
    cell,
    context.pilotCase,
    runtimeContext,
    record.observation_body_sha256,
    runtimeObservation,
  );
  const request = verifyDeepSeekRequestReceiptV1(record.provider_request_receipt, {
    cell,
    messages: modelInput.messages,
    modelProtocol: context.plan.model_protocol,
  });
  const response = verifyDeepSeekResponseReceiptV1(record.provider_response_receipt, {
    assistantMessage: record.assistant_message,
    cell,
    messages: modelInput.messages,
    modelProtocol: context.plan.model_protocol,
    requestReceipt: request,
  });
  if (request.attempt_ordinal !== cell.ordinal) fail("provider_attempt_schedule_mismatch");
  const infrastructureFailure = record.infrastructure_failure === null
    ? null
    : verifyFailureReceipt(record.infrastructure_failure);
  const evidence = verifyAgentAndVerifierEvidence({
    agentExitReceipt: record.agent_exit_receipt,
    cell,
    infrastructureFailure,
    pilotCase: context.pilotCase,
    providerResponse: response,
    verifierEvidence: record.verifier_evidence,
    verifierPublicKey: context.verifierPublicKey,
  });
  const ledger = verifyTreatmentLedger(
    record.treatment_ledger,
    evidence.verifierEvidence,
    cell,
    modelInput.runtime_context_sha256,
  );
  if (evidence.verifierEvidence !== null && infrastructureFailure !== null
    && ledger?.state !== "open") {
    fail("post_verifier_failure_ledger_state_invalid");
  }
  const evaluation = deriveEvaluation(evidence.verifierEvidence, infrastructureFailure);
  if (!sameCanonical(record.evaluation, evaluation)) fail("derived_evaluation_mismatch");
  return canonicalClone({
    ...record,
    agent_exit_receipt: evidence.agentExitReceipt,
    agent_model_input: modelInput,
    evaluation,
    infrastructure_failure: infrastructureFailure,
    provider_request_receipt: request,
    provider_response_receipt: response,
    runtime_context: runtimeContext,
    runtime_observation: runtimeObservation,
    treatment_ledger: ledger,
    verifier_evidence: evidence.verifierEvidence,
  });
}

function deriveBuildEvidence(input, options) {
  const cell = verifyPilotCellV1(input.cell);
  const context = verifyOptions(options, cell);
  const infrastructureFailure = input.infrastructure_failure === null
    ? null
    : verifyFailureReceipt(input.infrastructure_failure);
  const verifierEvidence = input.verifier_evidence === null
    ? null
    : verifySignedVerifierEvidenceV1(input.verifier_evidence, context.verifierPublicKey);
  return {
    context,
    evaluation: deriveEvaluation(verifierEvidence, infrastructureFailure),
  };
}

export function buildPilotCellResultV1(input, options) {
  const record = expectExactRecord(input, BUILD_INPUT_KEYS, "pilot_cell_result_input");
  const derived = deriveBuildEvidence(record, options);
  const body = verifyBody(canonicalClone({
    ...record,
    schema_version: SCHEMA_VERSION,
    plan_sha256: derived.context.plan.plan_sha256,
    evaluation: derived.evaluation,
  }), options);
  return verifyPilotCellResultV1(canonicalClone({
    ...body,
    cell_result_sha256: canonicalSha256(body),
  }), options);
}

export function verifyPilotCellResultV1(value, options) {
  const record = expectExactRecord(value, RESULT_KEYS, "pilot_cell_result");
  expectSha256(record.cell_result_sha256, "pilot_cell_result_sha256");
  const body = Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== "cell_result_sha256"),
  );
  if (canonicalSha256(body) !== record.cell_result_sha256) {
    fail("cell_result_sha256_mismatch");
  }
  return canonicalClone({
    ...verifyBody(body, options),
    cell_result_sha256: record.cell_result_sha256,
  });
}

export function isPilotInfrastructureFailureV1(resultValue, options) {
  return verifyPilotCellResultV1(resultValue, options).evaluation.state === "unknown";
}

export function isPilotProductFailureV1(resultValue, options) {
  return verifyPilotCellResultV1(resultValue, options).evaluation.failure_class === "product";
}
