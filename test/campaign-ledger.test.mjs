import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  beginCampaignSoak,
  beginCampaignWave,
  claimCampaignSeed,
  claimCampaignTrial,
  completeCampaignTrial,
  createCampaignLedger,
  inspectCampaignOfflineSqliteEvidence,
  markCampaignSeedRuntimeDispatch,
  markCampaignTrialProviderDispatch,
  prepareCampaignTrialProviderRequest,
  readCampaignLedger,
  readCampaignRecoveryExpectation,
  readCampaignTrialPreparedProviderRequest,
  recordCampaignFinalSoakAdmission,
  recordCampaignPilotAdmission,
  recordCampaignSeedRuntimeResponse,
  recordCampaignTrialGuideResponse,
  recordCampaignTrialPostTrialResponse,
  recordCampaignTrialProviderResponse,
  recordCampaignTrialProviderRetryableHttpResponse,
  recordCampaignWaveAdmission,
  renderCampaignTrialGuideRequest,
  renderCampaignTrialPostTrialRequest,
  replayCampaignSeedRuntimeDispatch,
  settleCampaignTrial,
} from "../src/campaign-ledger.mjs";
import { putEvidenceJsonBody } from "../src/evidence-cas.mjs";
import { acquireExclusiveLock } from "../src/exclusive-lock.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MODULE_URL = pathToFileURL(path.join(ROOT, "src/campaign-ledger.mjs")).href;
const RELEASE_LOCK_RAW = fs.readFileSync(path.join(ROOT, "config/v0.3.12-release-lock.json"));
const BASE_RELEASE_LOCK = JSON.parse(RELEASE_LOCK_RAW);
const AUTHORITY_RAW = fs.readFileSync(path.join(ROOT, "fixtures/v0.3.12/authority-manifest.json"));
const AUTHORITY = JSON.parse(AUTHORITY_RAW);
const WORKLOAD_RAW = fs.readFileSync(path.join(ROOT, "fixtures/v0.3.12/workload-manifest.json"));
const WORKLOAD = JSON.parse(WORKLOAD_RAW);
const HARNESS_COMMIT = "a".repeat(40);
const CANDIDATE = {
  commit: BASE_RELEASE_LOCK.candidate.commit,
  digest: BASE_RELEASE_LOCK.candidate.digest,
};
const PILOT_RECORDED_AT = "2026-07-21T02:45:00.000Z";
const SOAK_STARTED_AT = "2026-07-21T03:00:00.000Z";
const WAVE_STARTED_AT = [
  "2026-07-21T03:00:00.000Z",
  "2026-07-21T15:00:00.000Z",
  "2026-07-22T03:00:00.000Z",
];
const WAVE_RECORDED_AT = [
  "2026-07-21T03:30:00.000Z",
  "2026-07-21T15:30:00.000Z",
  "2026-07-22T03:30:00.000Z",
];
const hash = (value) => createHash("sha256").update(value).digest("hex");
const evidenceHash = (label) => hash(Buffer.from(label));

function canonical(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function contractSources(workloadSource = WORKLOAD_RAW, mutateLock = null) {
  const lock = structuredClone(BASE_RELEASE_LOCK);
  lock.protocol_artifacts.authority_manifest.sha256 = hash(AUTHORITY_RAW);
  lock.protocol_artifacts.workload_manifest.sha256 = hash(workloadSource);
  if (mutateLock) mutateLock(lock);
  return {
    releaseLockSource: Buffer.from(`${JSON.stringify(lock, null, 2)}\n`),
    authoritySource: AUTHORITY_RAW,
    workloadSource,
  };
}

function source(phase, runId) {
  return {
    repository: "ostinatocc/AionisRuntime-evals",
    run_id: runId,
    run_attempt: 1,
    head_sha: HARNESS_COMMIT,
    phase,
    job: "paid-preflight",
    environment: "bounded-soak",
  };
}

function temporaryDirectory(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aionis-${label}-`));
}

function createUnseeded(directory = temporaryDirectory("campaign-ledger"), overrides = {}) {
  const ledger = createCampaignLedger({
    directory,
    harnessCommit: HARNESS_COMMIT,
    ...contractSources(),
    pilotSource: source("pilot", 101),
    ...overrides,
  });
  return { directory, ledger };
}

function seedMemoryIds(seed) {
  return [`seed-memory-${evidenceHash(`${seed.scenario_id}\0${seed.operation_key}`).slice(0, 32)}`];
}

function seedClientId(seed) {
  return `seed-client-${evidenceHash(`${seed.scenario_id}\0${seed.operation_key}`).slice(0, 32)}`;
}

function seedResponseValue(seed) {
  return {
    contract_version: "aionis_observe_result_v1",
    operation_id: seed.operation_id,
    tenant_id: seed.request.tenant_id,
    scope: seed.request.scope,
    observed: { memory_written: true },
    memory_write: {
      nodes: seedMemoryIds(seed).map((id) => ({
        id,
        client_id: seedClientId(seed),
        type: seed.request.memory_kind,
      })),
    },
    post_commit_projections: { semantic_commit: "committed" },
  };
}

function seedRequestSource(seed) {
  return Buffer.from(JSON.stringify(seed.request));
}

function seedResponseSource(seed, mutate = null) {
  const response = seedResponseValue(seed);
  if (mutate) mutate(response);
  return Buffer.from(JSON.stringify(response));
}

function completeSeed(directory, ledger, seedId) {
  const seed = ledger.seeds.find((entry) => entry.seed_id === seedId);
  const claimed = claimCampaignSeed({ directory, expectedRevision: ledger.revision, seedId });
  const dispatched = markCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: claimed.ledger.revision,
    seedId,
    requestSource: seedRequestSource(seed),
  });
  return recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: dispatched.revision,
    seedId,
    httpStatus: 200,
    responseSource: seedResponseSource(seed),
  }).ledger;
}

function completeSeeds(directory, ledger) {
  let current = ledger;
  for (const seed of ledger.seeds) current = completeSeed(directory, current, seed.seed_id);
  return current;
}

function create(directory = temporaryDirectory("campaign-ledger"), overrides = {}) {
  const created = createUnseeded(directory, overrides);
  return { directory: created.directory, ledger: completeSeeds(created.directory, created.ledger) };
}

function verifierFor(trial) {
  return WORKLOAD.scenario_definitions.find((value) => value.id === trial.scenario);
}

function toolResultFor(trial, choice = verifierFor(trial).expected_choice) {
  const verifier = verifierFor(trial);
  return {
    schema_version: "aionis_bounded_soak_tool_result_v1",
    scenario_id: trial.scenario,
    choice,
    expected_choice: verifier.expected_choice,
    passed: choice === verifier.expected_choice,
    unsafe_direct_use: choice === verifier.unsafe_choice,
  };
}

function guideResponseValue(trial, preclaim, overrides = {}) {
  const definition = WORKLOAD.scenario_definitions.find((value) => value.id === trial.scenario);
  const seedEvidence = definition.runtime_fixture.seed_observations.map((observation) => {
    const memoryId = seedMemoryIds({
      scenario_id: trial.scenario,
      operation_key: observation.operation_key,
    })[0];
    const role = observation.branch_role ?? null;
    return {
      memoryId,
      role,
      surface: role === "passed_solution"
        ? "use_now"
        : role === "failed_branch"
          ? "do_not_use"
          : "inspect_before_use",
    };
  });
  const guideTraceId = overrides.guide_trace_id
    ?? `guide-trace-${evidenceHash(trial.trial_id).slice(0, 24)}`;
  const agentContext = {
    prompt_text: `Use only role-verified memory surfaces for ${trial.scenario}.`,
    use_now_memory_ids: seedEvidence.filter((entry) => entry.surface === "use_now").map((entry) => entry.memoryId),
    inspect_before_use_memory_ids: seedEvidence
      .filter((entry) => entry.surface === "inspect_before_use")
      .map((entry) => entry.memoryId),
    do_not_use_memory_ids: seedEvidence
      .filter((entry) => entry.surface === "do_not_use")
      .map((entry) => entry.memoryId),
    ...overrides.agent_context,
  };
  const memoryPacket = {
    relevant_memories: seedEvidence.map((entry) => ({
      id: entry.memoryId,
      ...(entry.role === null ? {} : { execution_state: { execution_outcome_role: entry.role } }),
    })),
    ...overrides.memory_packet,
  };
  const feedbackAttribution = {
    contract_version: "aionis_guide_feedback_attribution_v1",
    status: "available",
    guide_trace_id: guideTraceId,
    episode_id: `episode-${evidenceHash(`episode:${trial.trial_id}`).slice(0, 24)}`,
    exposure_event_id: `exposure-${evidenceHash(`exposure:${trial.trial_id}`).slice(0, 24)}`,
    item_set_sha256: evidenceHash(`item-set:${trial.trial_id}`),
    served_surface_sha256: evidenceHash(`served-surface:${trial.trial_id}`),
    projection_complete: true,
    projection_incomplete_reason_codes: [],
    items: seedEvidence.map((entry) => ({
      memory_id: entry.memoryId,
      served_surface: entry.surface,
    })),
    ...overrides.feedback_attribution_v1,
  };
  return {
    contract_version: "aionis_guide_result_v1",
    operation_id: preclaim.guide_operation_id,
    tenant_id: preclaim.tenant_id,
    scope: preclaim.scope,
    guide_trace_id: guideTraceId,
    agent_context: agentContext,
    memory_packet: memoryPacket,
    feedback_attribution_v1: feedbackAttribution,
    guide_packet: {
      schema_version: "aionis_guide_packet_v1",
      trial_id: trial.trial_id,
      memory_ids: seedEvidence.map((entry) => entry.memoryId),
      ...overrides.guide_packet,
    },
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => ![
      "guide_trace_id",
      "agent_context",
      "memory_packet",
      "feedback_attribution_v1",
      "guide_packet",
    ].includes(key))),
  };
}

function guideResponseSource(trial, preclaim, overrides = {}) {
  return Buffer.from(JSON.stringify(guideResponseValue(trial, preclaim, overrides)), "utf8");
}

function providerResponseValue(trial, overrides = {}) {
  const inputTokens = trial.group === "aionis" ? 80 : trial.group === "long_context" ? 120 : 60;
  const usage = overrides.provider_usage ?? {
    input_tokens: inputTokens,
    output_tokens: 10,
    total_tokens: inputTokens + 10,
    cost_microusd: 1_000,
  };
  const choice = overrides.tool_result?.choice ?? verifierFor(trial).expected_choice;
  return {
    id: overrides.provider_request_id ?? `provider-${evidenceHash(trial.trial_id).slice(0, 24)}`,
    model: overrides.returned_model ?? AUTHORITY.providers.agent.allowed_returned_models[0],
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: null,
        tool_calls: [{
          id: overrides.tool_call_id ?? `tool-${evidenceHash(`tool:${trial.trial_id}`).slice(0, 24)}`,
          type: "function",
          function: {
            name: WORKLOAD.tool_protocol.function.name,
            arguments: JSON.stringify({ scenario_id: trial.scenario, choice }),
          },
        }],
      },
      finish_reason: "tool_calls",
    }],
    usage: {
      prompt_tokens: usage.input_tokens,
      completion_tokens: usage.output_tokens,
      total_tokens: usage.total_tokens,
      cost: usage.cost_microusd / 1_000_000,
    },
  };
}

function providerResponseSource(trial, overrides = {}) {
  if (overrides.response_source) return Buffer.from(overrides.response_source);
  const value = providerResponseValue(trial, overrides);
  if (overrides.mutate_response) overrides.mutate_response(value);
  return Buffer.from(JSON.stringify(value), "utf8");
}

function providerReceiptFacts(trial, requestSha256, responseSource, overrides = {}, guideCheckpoint = null) {
  const response = providerResponseValue(trial, overrides);
  const usage = response.usage;
  return {
    provider_request_id: response.id,
    request_sha256: requestSha256,
    response_sha256: hash(responseSource),
    returned_model: response.model,
    fallback_used: false,
    transport_attempts: overrides.transport_attempts ?? 1,
    semantic_attempts: 1,
    provider_usage: {
      input_tokens: usage.prompt_tokens,
      output_tokens: usage.completion_tokens,
      total_tokens: usage.total_tokens,
      cost_microusd: Math.ceil(usage.cost * 1_000_000),
    },
    tool_result: toolResultFor(trial, overrides.tool_result?.choice),
    guide_response_checkpoint: guideCheckpoint,
  };
}

function scenarioSeedMemoryIds(scenarioId) {
  const definition = WORKLOAD.scenario_definitions.find((value) => value.id === scenarioId);
  return definition.runtime_fixture.seed_observations.flatMap((observation) => seedMemoryIds({
    scenario_id: scenarioId,
    operation_key: observation.operation_key,
  }));
}

function outcomeMemoryIds(trial) {
  return [`outcome-memory-${evidenceHash(trial.trial_id).slice(0, 32)}`];
}

function postTrialResponseValue(trial, preclaim, stage, options = {}) {
  const common = { tenant_id: preclaim.tenant_id, scope: preclaim.scope };
  if (stage === "outcome_observe") {
    const memoryIds = outcomeMemoryIds(trial);
    return {
      contract_version: "aionis_observe_result_v1",
      operation_id: preclaim.outcome_operation_id,
      ...common,
      observed: {
        memory_written: true,
        handoff_stored: false,
        general_memory_count: 0,
        execution_memory_count: memoryIds.length,
        auto_text_memory_count: 0,
        execution_observation_count: 1,
      },
      memory_write: {
        ...common,
        commit_id: `commit-${evidenceHash(`outcome:${trial.trial_id}`).slice(0, 24)}`,
        commit_hash: evidenceHash(`outcome-commit:${trial.trial_id}`),
        nodes: memoryIds.map((id) => ({
          id,
          client_id: `outcome-client-${evidenceHash(trial.trial_id).slice(0, 32)}`,
          uri: `aionis://memory/${id}`,
          type: "execution",
        })),
        edges: [],
      },
      post_commit_projections: { semantic_commit: "committed", embedding: "scheduled", ann_sync: "scheduled" },
    };
  }
  if (stage === "feedback") {
    return {
      contract_version: "aionis_feedback_result_v1",
      operation_id: preclaim.feedback_operation_id,
      ...common,
      product_action: "feedback",
      operation: "activate",
      target: "memory",
      learning_attribution_status: options.learningAttributionStatus ?? "legacy_unverified",
      learning_episode_id: `episode-${evidenceHash(trial.trial_id).slice(0, 24)}`,
      learning_feedback_event_id: `feedback-${evidenceHash(trial.trial_id).slice(0, 24)}`,
      forget_effect: { activated: 1 },
      result: { commit_id: `commit-${evidenceHash(`feedback:${trial.trial_id}`).slice(0, 24)}` },
    };
  }
  if (stage === "measure" || stage === "measure_replay") {
    return {
      contract_version: "aionis_measure_result_v1",
      operation_id: preclaim.measure_operation_id,
      ...common,
      measurement_id: `measure-${evidenceHash(trial.trial_id).slice(0, 24)}`,
      measurement_digest: evidenceHash(`measurement:${trial.trial_id}`),
      measurement_persisted: true,
      evidence_assessment: { status: "sufficient" },
    };
  }
  if (stage === "operator_snapshot") {
    return {
      contract_version: "aionis_operator_snapshot_result_v1",
      ...common,
      operator_snapshot: {
        contract_version: "aionis_operator_snapshot_v1",
        trial_id: trial.trial_id,
      },
      source_map: { routes_used: ["/v1/operator/snapshot"] },
    };
  }
  if (stage === "flight_recorder") {
    return {
      contract_version: "aionis_agent_flight_recorder_result_v1",
      ...common,
      agent_flight_recorder: {
        contract_version: "aionis_agent_flight_recorder_v1",
        trial_id: trial.trial_id,
      },
      source_map: { routes_used: ["/v1/audit/flight-recorder"] },
    };
  }
  throw new Error(`unsupported post-trial stage ${stage}`);
}

function completePostTrialChain(directory, ledger, trial, preclaim, options = {}) {
  let current = ledger;
  while (current.trials.find((entry) => entry.trial_id === trial.trial_id).post_trial_checkpoints.length < 6) {
    const request = renderCampaignTrialPostTrialRequest({ directory, trialId: trial.trial_id });
    const responseSource = Buffer.from(JSON.stringify(
      postTrialResponseValue(trial, preclaim, request.stage, options),
    ), "utf8");
    current = recordCampaignTrialPostTrialResponse({
      directory,
      expectedRevision: current.revision,
      trialId: trial.trial_id,
      stage: request.stage,
      requestSource: request.request_source,
      httpStatus: 200,
      responseSource,
    }).ledger;
  }
  return current;
}

function successReceipt(trial, preclaim, provider, options = {}) {
  const verifier = verifierFor(trial);
  const choice = options.choice ?? verifier.expected_choice;
  const snapshotResponseSha256 = evidenceHash(`snapshot-response:${trial.trial_id}`);
  const recorderResponseSha256 = evidenceHash(`recorder-response:${trial.trial_id}`);
  const guideCheckpoint = provider.guide_response_checkpoint;
  const aionis = trial.group === "aionis" ? {
    guide_trace_id: guideCheckpoint.guide_trace_id,
    runtime_echoed_guide_operation_id: guideCheckpoint.operation_id,
    runtime_echoed_outcome_operation_id: preclaim.outcome_operation_id,
    runtime_echoed_feedback_operation_id: preclaim.feedback_operation_id,
    runtime_echoed_measure_operation_id: preclaim.measure_operation_id,
    feedback_id: `feedback-${evidenceHash(trial.trial_id).slice(0, 24)}`,
    learning_attribution_status: "legacy_unverified",
    measure_id: `measure-${evidenceHash(trial.trial_id).slice(0, 24)}`,
    snapshot_id: `snapshot-${evidenceHash(`${trial.trial_id}\0${snapshotResponseSha256}`)}`,
    snapshot_response_sha256: snapshotResponseSha256,
    recorder_id: `recorder-${evidenceHash(`${trial.trial_id}\0${recorderResponseSha256}`)}`,
    recorder_response_sha256: recorderResponseSha256,
    runtime_tenant_id: preclaim.tenant_id,
    runtime_scope: preclaim.scope,
    guide_response_sha256: guideCheckpoint.response_evidence.sha256,
    outcome_response_sha256: evidenceHash(`outcome-response:${trial.trial_id}`),
    feedback_response_sha256: evidenceHash(`feedback-response:${trial.trial_id}`),
    measure_response_sha256: evidenceHash(`measure-response:${trial.trial_id}`),
    outcome_memory_ids: outcomeMemoryIds(trial),
    outcome_memory_bindings: [{
      client_id: `outcome-client-${evidenceHash(trial.trial_id).slice(0, 32)}`,
      memory_id: outcomeMemoryIds(trial)[0],
    }],
    inspect_evidence: structuredClone(guideCheckpoint.inspect_evidence),
    memory_surface_evidence: structuredClone(guideCheckpoint.memory_surface_evidence),
    replay_evidence: {
      replayed_operation_id: preclaim.measure_operation_id,
      original_response_sha256: evidenceHash(`measure-response:${trial.trial_id}`),
      replay_response_sha256: evidenceHash(`measure-response:${trial.trial_id}`),
    },
    ...options.aionis,
  } : null;
  return {
    schema_version: "aionis_trial_settlement_receipt_v2",
    status: "completed",
    trial_id: trial.trial_id,
    preclaim,
    provider_request_id: provider.provider_request_id,
    request_sha256: provider.request_sha256,
    response_sha256: provider.response_sha256,
    returned_model: provider.returned_model,
    fallback_used: provider.fallback_used,
    transport_attempts: provider.transport_attempts,
    semantic_attempts: provider.semantic_attempts,
    provider_usage: structuredClone(provider.provider_usage),
    tool_result: { ...toolResultFor(trial, choice), ...options.toolResult },
    runtime_digest: CANDIDATE.digest,
    aionis,
  };
}

function failureReceipt(trial, preclaim, overrides = {}) {
  return {
    schema_version: "aionis_trial_failure_receipt_v1",
    status: "failed",
    trial_id: trial.trial_id,
    preclaim,
    reason_code: "interrupted_ambiguous",
    last_confirmed_stage: "provider_request",
    failure_evidence_sha256: evidenceHash(`failure:${trial.trial_id}`),
    ...overrides,
  };
}

function claimAndPrepare(directory, ledger, trial, guideOverrides = {}) {
  const claimed = claimCampaignTrial({ directory, expectedRevision: ledger.revision, trialId: trial.trial_id });
  let current = claimed.ledger;
  let guideCheckpoint = null;
  if (trial.group === "aionis") {
    const guideRequest = renderCampaignTrialGuideRequest({ directory, trialId: trial.trial_id });
    const recorded = recordCampaignTrialGuideResponse({
      directory,
      expectedRevision: current.revision,
      trialId: trial.trial_id,
      requestSource: guideRequest.request_source,
      httpStatus: 200,
      responseSource: guideResponseSource(trial, claimed.preclaim, guideOverrides),
    });
    current = recorded.ledger;
    guideCheckpoint = recorded.checkpoint;
  }
  const prepared = prepareCampaignTrialProviderRequest({
    directory,
    expectedRevision: current.revision,
    trialId: trial.trial_id,
  });
  return { ...prepared, preclaim: claimed.preclaim, guideCheckpoint };
}

function claimPrepareDispatch(directory, ledger, trial, options = {}) {
  const prepared = claimAndPrepare(directory, ledger, trial, options.guide);
  const dispatched = markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: prepared.ledger.revision,
    trialId: trial.trial_id,
    requestSource: options.requestSource ?? prepared.request_source,
  });
  return { ...prepared, ledger: dispatched };
}

function claimDispatchRespond(directory, ledger, trial, checkpointOverrides = {}) {
  const dispatched = claimPrepareDispatch(directory, ledger, trial, { guide: checkpointOverrides.guide });
  let current = dispatched.ledger;
  const attempts = checkpointOverrides.transport_attempts ?? 1;
  for (let attempt = 1; attempt < attempts; attempt += 1) {
    const retryResponse = Buffer.from(JSON.stringify({
      error: { code: 429, message: `retryable-${trial.trial_id}-${attempt}` },
    }));
    current = recordCampaignTrialProviderRetryableHttpResponse({
      directory,
      expectedRevision: current.revision,
      trialId: trial.trial_id,
      httpStatus: 429,
      responseSource: retryResponse,
    });
    current = markCampaignTrialProviderDispatch({
      directory,
      expectedRevision: current.revision,
      trialId: trial.trial_id,
      requestSource: readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
    });
  }
  const responseSource = providerResponseSource(trial, checkpointOverrides);
  const responded = recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: trial.trial_id,
    httpStatus: 200,
    responseSource,
  });
  const checkpoint = responded.trials.find((entry) => entry.trial_id === trial.trial_id).provider_response;
  return {
    ledger: responded,
    preclaim: dispatched.preclaim,
    checkpoint: { ...checkpoint, guide_response_checkpoint: dispatched.guideCheckpoint },
    guideCheckpoint: dispatched.guideCheckpoint,
    requestSource: dispatched.request_source,
    responseSource,
  };
}

function claimAndSettle(directory, ledger, trial, options = {}) {
  if (options.failure) {
    const dispatched = claimPrepareDispatch(directory, ledger, trial);
    return settleCampaignTrial({
      directory,
      expectedRevision: dispatched.ledger.revision,
      receipt: failureReceipt(trial, dispatched.preclaim),
    });
  }
  const checkpointOverrides = { ...options.checkpoint };
  if (options.choice !== undefined) checkpointOverrides.tool_result = toolResultFor(trial, options.choice);
  const responded = claimDispatchRespond(directory, ledger, trial, checkpointOverrides);
  const ready = trial.group === "aionis"
    ? completePostTrialChain(directory, responded.ledger, trial, responded.preclaim, {
        learningAttributionStatus: options.learningAttributionStatus,
      })
    : responded.ledger;
  return completeCampaignTrial({
    directory,
    expectedRevision: ready.revision,
    trialId: trial.trial_id,
  });
}

function completeTrials(directory, ledger, predicate, optionsForTrial = () => ({})) {
  let current = ledger;
  for (const trial of current.trials.filter(predicate)) {
    current = claimAndSettle(directory, current, trial, optionsForTrial(trial));
  }
  return current;
}

function completeTrialsBefore(directory, ledger, targetTrial) {
  let current = ledger;
  for (const trial of current.trials) {
    if (trial.trial_id === targetTrial.trial_id) break;
    if (
      trial.phase === targetTrial.phase
      && trial.wave === targetTrial.wave
      && trial.status === "pending"
    ) current = claimAndSettle(directory, current, trial);
  }
  return current;
}

function workerProcess(seed) {
  return {
    boot_id: "1d48a92a-f523-4d08-9c12-40c36ec09e52",
    pid_namespace_inode: "4026532456",
    pid: 10_000 + seed,
    process_start_ticks: String(100_000 + seed),
    container_id: evidenceHash(`container:${seed}`),
    runtime_image_digest: CANDIDATE.digest,
  };
}

function workerHealth() {
  return {
    http_status: 200,
    body: {
      ok: true,
      lite: {
        stores: {
          write: {
            projections: {
              pending: 0,
              running: 0,
              retry: 0,
              dead_letter: 0,
              provider_mismatch: 0,
              legacy_pending_unrecoverable: 0,
            },
          },
          learning_control_worker: {
            running: true,
            closed: false,
            last_error_code: null,
            backlog: {
              pending: 0,
              leased: 0,
              expired_leases: 0,
              completed: 90,
              dead_letter: 0,
              exhausted: 0,
              oldest_available_at: null,
              oldest_lease_expiry: null,
            },
          },
        },
      },
    },
  };
}

function rawWorkerState(ledger, expectation, checkpoint, recovery, recordedAt) {
  const processSeeds = {
    pilot: [0, 0],
    after_wave_1: [0, 1],
    after_wave_2: [1, 2],
    after_wave_3: [2, 2],
  };
  const [beforeSeed, afterSeed] = processSeeds[checkpoint];
  const state = {
    database_instance_id: evidenceHash("runtime-database-instance"),
    operations: expectation.persisted_operation_identities.map((identity) => ({
      ...identity,
      request_sha256: evidenceHash(`request:${Object.values(identity).join("\0")}`),
      receipt_json: JSON.stringify({ ok: true, statusCode: 200, body: { operation_id: identity.operation_id } }),
      commit_id: `commit-${evidenceHash(`commit:${identity.operation_id}`).slice(0, 24)}`,
    })),
  };
  const observation = (phase, capturedAt, seed) => ({
    phase,
    captured_at: capturedAt,
    process: workerProcess(seed),
    runtime_health: workerHealth(),
    executor_queue: {
      entries: expectation.terminal_trial_ids.map((trialId) => ({ trial_id: trialId, status: "completed" })),
      errors: [],
    },
    logical_state: state,
  });
  const sourceRun = checkpoint === "pilot" ? ledger.phase_sources.pilot : ledger.phase_sources.soak;
  const beforeAt = new Date(Date.parse(recordedAt) - 60_000).toISOString();
  const observedExit = recovery === "graceful_replacement"
    ? { exit_code: 0, signal: null, oom_killed: false, shutdown_log: "draining Runtime before shutdown\nRuntime stopped" }
    : recovery === "sigkill_replacement"
      ? { exit_code: 137, signal: "SIGKILL", oom_killed: false, shutdown_log: "" }
      : null;
  return {
    schema_version: "aionis_worker_state_artifact_v1",
    checkpoint,
    source: { run_id: sourceRun.run_id, run_attempt: sourceRun.run_attempt },
    recovery,
    before: observation("before_recovery", beforeAt, beforeSeed),
    transition: { kind: recovery, observed_exit: observedExit },
    after: observation("after_recovery", recordedAt, afterSeed),
  };
}

function workerStateRef(directory, ledger, checkpoint, recovery, recordedAt) {
  const expectation = readCampaignRecoveryExpectation({ directory, checkpoint });
  const expectedCounts = {
    pilot: [9, 17],
    after_wave_1: [36, 53],
    after_wave_2: [63, 89],
    after_wave_3: [90, 125],
  };
  assert.deepEqual(
    [expectation.terminal_trial_ids.length, expectation.persisted_operation_identities.length],
    expectedCounts[checkpoint],
  );
  if (checkpoint === "pilot") {
    const countsByKind = Object.fromEntries(
      ["product_observe_v1", "product_guide_v1", "product_feedback_v1", "product_measure_v1"]
        .map((kind) => [
          kind,
          expectation.persisted_operation_identities.filter((entry) => entry.operation_kind === kind).length,
        ]),
    );
    assert.deepEqual(countsByKind, {
      product_observe_v1: 8,
      product_guide_v1: 3,
      product_feedback_v1: 3,
      product_measure_v1: 3,
    });
  }
  return putEvidenceJsonBody({
    campaignRoot: directory,
    body: Buffer.from(JSON.stringify(rawWorkerState(
      ledger,
      expectation,
      checkpoint,
      recovery,
      recordedAt,
    )), "utf8"),
  });
}

function settlePilot(directory, ledger, optionsForTrial = () => ({})) {
  let current = completeTrials(directory, ledger, (trial) => trial.phase === "pilot", optionsForTrial);
  current = recordCampaignPilotAdmission({
    directory,
    expectedRevision: current.revision,
    workerStateRef: workerStateRef(directory, current, "pilot", "none", PILOT_RECORDED_AT),
  });
  return current;
}

function beginSoak(directory, ledger) {
  return beginCampaignSoak({
    directory,
    expectedRevision: ledger.revision,
    source: source("soak", 202),
    startedAt: SOAK_STARTED_AT,
  });
}

function executeWaveTrials(directory, ledger, wave, optionsForTrial = () => ({})) {
  let current = beginCampaignWave({
    directory,
    expectedRevision: ledger.revision,
    wave,
    startedAt: WAVE_STARTED_AT[wave - 1],
  });
  current = completeTrials(
    directory,
    current,
    (trial) => trial.phase === "soak" && trial.wave === wave,
    optionsForTrial,
  );
  return current;
}

function admitWave(directory, ledger, wave) {
  const recovery = WORKLOAD.schedule.soak_waves[wave - 1].recovery_after;
  return recordCampaignWaveAdmission({
    directory,
    expectedRevision: ledger.revision,
    workerStateRef: workerStateRef(
      directory,
      ledger,
      `after_wave_${wave}`,
      recovery,
      WAVE_RECORDED_AT[wave - 1],
    ),
    offlineSqliteInspection: null,
  });
}

function completeWave(directory, ledger, wave, optionsForTrial = () => ({})) {
  return admitWave(directory, executeWaveTrials(directory, ledger, wave, optionsForTrial), wave);
}

function mode(file) {
  return fs.lstatSync(file).mode & 0o777;
}

function runChild(script, env) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function spawnClaim(directory, trialId, expectedRevision) {
  const script = `
    const { claimCampaignTrial } = await import(process.env.MODULE_URL);
    try {
      const result = claimCampaignTrial({ directory: process.env.DIRECTORY, expectedRevision: Number(process.env.EXPECTED_REVISION), trialId: process.env.TRIAL_ID });
      process.stdout.write(JSON.stringify({ revision: result.ledger.revision, request_id: result.preclaim.request_id }));
    } catch (error) {
      process.stderr.write(error.message);
      process.exitCode = 1;
    }
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    cwd: ROOT,
    env: {
      ...process.env,
      MODULE_URL,
      DIRECTORY: directory,
      TRIAL_ID: trialId,
      EXPECTED_REVISION: String(expectedRevision),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("creation freezes deterministic seeds and blocks pilot until every seed response is durable", () => {
  const initial = createUnseeded();
  const secondInitial = createUnseeded();
  assert.equal(initial.ledger.status, "seeding");
  assert.equal(initial.ledger.seeds.length, 5);
  assert.equal(initial.ledger.seeds.every((seed) => seed.status === "pending"), true);
  assert.throws(() => claimCampaignTrial({
    directory: initial.directory,
    expectedRevision: initial.ledger.revision,
    trialId: initial.ledger.trials[0].trial_id,
  }), /pilot trial is not active/);
  const first = { directory: initial.directory, ledger: completeSeeds(initial.directory, initial.ledger) };
  const second = {
    directory: secondInitial.directory,
    ledger: completeSeeds(secondInitial.directory, secondInitial.ledger),
  };
  const envelope = path.join(first.directory, "campaign-ledger.json");
  assert.equal(mode(first.directory), 0o700);
  assert.equal(mode(envelope), 0o600);
  assert.equal(first.ledger.status, "pilot_running");
  assert.equal(first.ledger.trials.length, 90);
  const preclaimIds = first.ledger.trials.flatMap((trial) => [
    trial.preclaim.request_id,
    trial.preclaim.guide_operation_id,
    trial.preclaim.outcome_operation_id,
    trial.preclaim.feedback_operation_id,
    trial.preclaim.measure_operation_id,
  ]);
  assert.equal(new Set(preclaimIds).size, 450);
  const seedOperationIds = first.ledger.seeds.map((seed) => seed.operation_id);
  const seedIds = first.ledger.seeds.map((seed) => seed.seed_id);
  assert.equal(new Set([...preclaimIds, ...seedOperationIds]).size, 455);
  assert.equal(new Set([...preclaimIds, ...seedOperationIds, ...seedIds]).size, 460);
  for (const seed of first.ledger.seeds) {
    assert.equal(
      seed.operation_id,
      `seed-${evidenceHash(`${first.ledger.campaign_id}\0${seed.scenario_id}\0${seed.operation_key}`)}`,
    );
  }
  assert.equal(first.ledger.revision, 15);
  assert.equal(first.ledger.seeds.every((seed) => seed.status === "completed"), true);
  assert.equal(
    first.ledger.trial_contract.seed_contract.cadence,
    "once_per_campaign_scenario_seed_observation_before_pilot",
  );
  assert.equal(first.ledger.campaign_id, second.ledger.campaign_id);
  assert.deepEqual(first.ledger.trials.map((trial) => trial.preclaim), second.ledger.trials.map((trial) => trial.preclaim));
  assert.deepEqual(first.ledger.trial_contract.schedule, WORKLOAD.schedule);
  assert.deepEqual(first.ledger.trial_contract.recovery, WORKLOAD.recovery);
  assert.deepEqual(
    first.ledger.trial_contract.scenario_verifiers,
    WORKLOAD.scenario_definitions.map((value) => ({
      scenario_id: value.id,
      allowed_choices: value.allowed_choices,
      expected_choice: value.expected_choice,
      unsafe_choice: value.unsafe_choice,
    })),
  );
  assert.equal(first.ledger.candidate.commit, BASE_RELEASE_LOCK.candidate.commit);
  assert.equal(first.ledger.frozen_bindings.release_lock_sha256, hash(contractSources().releaseLockSource));
  const sources = contractSources();
  const byteDistinct = create(temporaryDirectory("release-lock-byte-binding"), {
    ...sources,
    releaseLockSource: Buffer.from(JSON.stringify(JSON.parse(sources.releaseLockSource))),
  });
  assert.notEqual(byteDistinct.ledger.campaign_id, first.ledger.campaign_id);
  const changedWorkload = Buffer.from(`${JSON.stringify({ ...WORKLOAD, frozen_at: "2026-07-21T00:00:00.000Z" }, null, 2)}\n`);
  assert.throws(() => createCampaignLedger({
    directory: temporaryDirectory("raw-drift"),
    harnessCommit: HARNESS_COMMIT,
    ...contractSources(),
    workloadSource: changedWorkload,
    pilotSource: source("pilot", 101),
  }), /exact source SHA-256/);
  const raw = fs.readFileSync(envelope, "utf8");
  assert.equal(raw, `${JSON.stringify(JSON.parse(raw), null, 2)}\n`);
});

test("seed Runtime checkpoints survive restart, reject drift and skips, and allow only exact idempotent replay", () => {
  const { directory, ledger } = createUnseeded();
  const [first, second, third] = ledger.seeds;
  assert.throws(() => claimCampaignSeed({
    directory,
    expectedRevision: ledger.revision,
    seedId: second.seed_id,
  }), /deterministic seed order/);

  const claimed = claimCampaignSeed({ directory, expectedRevision: ledger.revision, seedId: first.seed_id });
  assert.throws(() => claimCampaignSeed({
    directory,
    expectedRevision: claimed.ledger.revision,
    seedId: first.seed_id,
  }), /already claimed/);
  const driftedRequest = structuredClone(first.request);
  driftedRequest.input_text = "drifted seed input";
  assert.throws(() => markCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: claimed.ledger.revision,
    seedId: first.seed_id,
    requestSource: Buffer.from(JSON.stringify(driftedRequest)),
  }), /parsed request/);
  const requestSource = seedRequestSource(first);
  const dispatched = markCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: claimed.ledger.revision,
    seedId: first.seed_id,
    requestSource,
  });
  const restarted = readCampaignLedger({ directory });
  assert.equal(restarted.seeds[0].status, "dispatch_started");
  assert.equal(restarted.seeds[0].dispatch_request_sha256, hash(requestSource));
  assert.throws(() => replayCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: restarted.revision,
    seedId: first.seed_id,
    requestSource: Buffer.from(JSON.stringify(first.request, null, 2)),
  }), /exact replay request SHA-256/);
  const replayed = replayCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: restarted.revision,
    seedId: first.seed_id,
    requestSource,
  });
  assert.equal(replayed.seeds[0].dispatch_replay_count, 1);

  assert.throws(() => recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: replayed.revision,
    seedId: first.seed_id,
    httpStatus: 500,
    responseSource: seedResponseSource(first),
  }), /route identity/);
  const responseDrifts = [
    (response) => { response.contract_version = "wrong_contract"; },
    (response) => { response.operation_id = "wrong-operation"; },
    (response) => { response.tenant_id = "wrong-tenant"; },
    (response) => { response.scope = "wrong-scope"; },
    (response) => { response.observed.memory_written = false; },
    (response) => { response.post_commit_projections.semantic_commit = "scheduled"; },
    (response) => { delete response.memory_write.nodes[0].client_id; },
    (response) => { response.memory_write.nodes = []; },
    (response) => { response.memory_write.nodes.push(structuredClone(response.memory_write.nodes[0])); },
  ];
  for (const mutate of responseDrifts) {
    assert.throws(() => recordCampaignSeedRuntimeResponse({
      directory,
      expectedRevision: replayed.revision,
      seedId: first.seed_id,
      httpStatus: 200,
      responseSource: seedResponseSource(first, mutate),
    }), /route identity|operation echo|tenant echo|scope echo|memory_written|semantic_commit|memory IDs|client ID|exactly one/);
  }
  const responseSource = seedResponseSource(first);
  const recorded = recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: replayed.revision,
    seedId: first.seed_id,
    httpStatus: 200,
    responseSource,
  });
  assert.equal(recorded.checkpoint.response_sha256, hash(responseSource));
  assert.deepEqual(recorded.checkpoint.memory_ids, seedMemoryIds(first));
  assert.deepEqual(recorded.checkpoint.memory_binding, {
    client_id: seedClientId(first),
    memory_id: seedMemoryIds(first)[0],
    expected_execution_outcome_role: first.expected_execution_outcome_role,
    expected_served_surface: first.expected_served_surface,
  });
  assert.equal(readCampaignLedger({ directory }).seeds[0].runtime_response_sha256.length, 64);
  assert.throws(() => recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: recorded.ledger.revision,
    seedId: first.seed_id,
    httpStatus: 200,
    responseSource,
  }), /in-flight seed dispatch/);
  assert.throws(() => claimCampaignSeed({
    directory,
    expectedRevision: recorded.ledger.revision,
    seedId: third.seed_id,
  }), /deterministic seed order/);

  let current = completeSeed(directory, recorded.ledger, second.seed_id);
  const thirdClaim = claimCampaignSeed({ directory, expectedRevision: current.revision, seedId: third.seed_id });
  const thirdDispatch = markCampaignSeedRuntimeDispatch({
    directory,
    expectedRevision: thirdClaim.ledger.revision,
    seedId: third.seed_id,
    requestSource: seedRequestSource(third),
  });
  assert.throws(() => recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: thirdDispatch.revision,
    seedId: third.seed_id,
    httpStatus: 200,
    responseSource: seedResponseSource(third, (response) => {
      response.memory_write.nodes[0].id = seedMemoryIds(first)[0];
    }),
  }), /memory ID is reused across campaign evidence/);
  assert.throws(() => recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: thirdDispatch.revision,
    seedId: third.seed_id,
    httpStatus: 200,
    responseSource: seedResponseSource(third, (response) => {
      response.memory_write.nodes[0].client_id = seedClientId(first);
    }),
  }), /client ID is reused across campaign evidence/);
  current = recordCampaignSeedRuntimeResponse({
    directory,
    expectedRevision: thirdDispatch.revision,
    seedId: third.seed_id,
    httpStatus: 200,
    responseSource: seedResponseSource(third),
  }).ledger;
  current = completeSeed(directory, current, ledger.seeds[3].seed_id);
  assert.throws(() => claimCampaignTrial({
    directory,
    expectedRevision: current.revision,
    trialId: current.trials[0].trial_id,
  }), /pilot trial is not active/);
  current = completeSeed(directory, current, ledger.seeds[4].seed_id);
  assert.equal(current.status, "pilot_running");
  assert.equal(current.seeds.every((seed) => seed.status === "completed"), true);
});

test("provider checkpoints distinguish safe-to-send, ambiguous, and resumable states", () => {
  const { directory, ledger } = create();
  const trial = ledger.trials[0];
  const claimed = claimCampaignTrial({ directory, expectedRevision: ledger.revision, trialId: trial.trial_id });
  assert.equal(claimed.ledger.trials[0].status, "claimed");
  const prepared = prepareCampaignTrialProviderRequest({
    directory,
    expectedRevision: claimed.ledger.revision,
    trialId: trial.trial_id,
  });
  assert.equal(prepared.ledger.trials[0].status, "provider_request_prepared");
  assert.equal(hash(prepared.request_source), prepared.request_evidence.sha256);
  assert.deepEqual(
    readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
    prepared.request_source,
  );
  const requestCasPath = path.join(directory, prepared.request_evidence.cas_path);
  fs.chmodSync(requestCasPath, 0o644);
  assert.throws(
    () => readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
    /evidence CAS object permissions must be 600/,
  );
  fs.chmodSync(requestCasPath, 0o600);
  const requestCasBytes = fs.readFileSync(requestCasPath);
  const requestCasTamper = Buffer.from(requestCasBytes);
  requestCasTamper[requestCasTamper.indexOf(Buffer.from("deepseek"))] = "x".charCodeAt(0);
  fs.writeFileSync(requestCasPath, requestCasTamper);
  assert.throws(
    () => readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
    /evidence CAS object SHA-256 mismatch/,
  );
  fs.writeFileSync(requestCasPath, requestCasBytes);
  const reserialized = Buffer.from(JSON.stringify(JSON.parse(prepared.request_source), null, 2));
  assert.throws(() => markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: prepared.ledger.revision,
    trialId: trial.trial_id,
    requestSource: reserialized,
  }), /differ from the durable prepared request/);
  const dispatched = markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: prepared.ledger.revision,
    trialId: trial.trial_id,
    requestSource: prepared.request_source,
  });
  assert.equal(dispatched.trials[0].status, "provider_dispatch_started");
  assert.equal(readCampaignLedger({ directory }).trials[0].status, "provider_dispatch_started");
  assert.throws(() => markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: dispatched.revision,
    trialId: trial.trial_id,
    requestSource: prepared.request_source,
  }), /durable prepared request/);
  const responseSource = providerResponseSource(trial);
  const prematureProvider = providerReceiptFacts(
    trial,
    prepared.request_evidence.sha256,
    responseSource,
  );
  assert.throws(() => settleCampaignTrial({
    directory,
    expectedRevision: dispatched.revision,
    receipt: successReceipt(trial, claimed.preclaim, prematureProvider),
  }), /internally derived/);
  const responded = recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: dispatched.revision,
    trialId: trial.trial_id,
    httpStatus: 200,
    responseSource,
  });
  assert.equal(responded.trials[0].status, "provider_responded");
  const responseCasPath = path.join(directory, responded.trials[0].provider_response.response_evidence.cas_path);
  const responseCasBytes = fs.readFileSync(responseCasPath);
  const responseCasTamper = Buffer.from(responseCasBytes);
  responseCasTamper[responseCasTamper.indexOf(Buffer.from("provider-"))] = "x".charCodeAt(0);
  fs.writeFileSync(responseCasPath, responseCasTamper);
  assert.throws(() => readCampaignLedger({ directory }), /provider response evidence failed verification.*SHA-256 mismatch/);
  fs.writeFileSync(responseCasPath, responseCasBytes);
  assert.equal(readCampaignLedger({ directory }).trials[0].status, "provider_responded");
  const script = `
    const { readCampaignLedger, completeCampaignTrial } = await import(process.env.MODULE_URL);
    const loaded = readCampaignLedger({ directory: process.env.DIRECTORY });
    if (loaded.trials[0].status !== "provider_responded") throw new Error("provider response was not resumable");
    const next = completeCampaignTrial({ directory: process.env.DIRECTORY, expectedRevision: loaded.revision, trialId: loaded.trials[0].trial_id });
    process.stdout.write(JSON.stringify({ revision: next.revision, status: next.trials[0].status }));
  `;
  const child = runChild(script, {
    MODULE_URL,
    DIRECTORY: directory,
  });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { revision: responded.revision + 1, status: "completed" });

  const ambiguous = create();
  const ambiguousTrial = ambiguous.ledger.trials[0];
  const ambiguousDispatch = claimPrepareDispatch(ambiguous.directory, ambiguous.ledger, ambiguousTrial);
  const failed = settleCampaignTrial({
    directory: ambiguous.directory,
    expectedRevision: ambiguousDispatch.ledger.revision,
    receipt: failureReceipt(ambiguousTrial, ambiguousDispatch.preclaim),
  });
  assert.equal(failed.trials[0].status, "failed");

  const guideFailure = create();
  const guideTrial = guideFailure.ledger.trials.find((entry) => entry.group === "aionis");
  guideFailure.ledger = completeTrialsBefore(guideFailure.directory, guideFailure.ledger, guideTrial);
  const guideClaim = claimCampaignTrial({
    directory: guideFailure.directory,
    expectedRevision: guideFailure.ledger.revision,
    trialId: guideTrial.trial_id,
  });
  const guideRequest = renderCampaignTrialGuideRequest({
    directory: guideFailure.directory,
    trialId: guideTrial.trial_id,
  });
  assert.throws(() => recordCampaignTrialGuideResponse({
    directory: guideFailure.directory,
    expectedRevision: guideClaim.ledger.revision,
    trialId: guideTrial.trial_id,
    requestSource: Buffer.from(JSON.stringify(JSON.parse(guideRequest.request_source), null, 2)),
    httpStatus: 200,
    responseSource: guideResponseSource(guideTrial, guideClaim.preclaim),
  }), /request bytes do not match the canonical frozen workload request/);
  const wrongSurface = guideTrial.scenario === "summary_only_inspect"
    ? { use_now_memory_ids: [scenarioSeedMemoryIds(guideTrial.scenario)[0]], inspect_before_use_memory_ids: [] }
    : { use_now_memory_ids: [], inspect_before_use_memory_ids: [scenarioSeedMemoryIds(guideTrial.scenario)[0]] };
  assert.throws(() => recordCampaignTrialGuideResponse({
    directory: guideFailure.directory,
    expectedRevision: guideClaim.ledger.revision,
    trialId: guideTrial.trial_id,
    requestSource: guideRequest.request_source,
    httpStatus: 200,
    responseSource: guideResponseSource(guideTrial, guideClaim.preclaim, { agent_context: wrongSurface }),
  }), /attribution\/AgentContext surface projection|served surface/);
  if (guideTrial.scenario !== "summary_only_inspect") {
    const [passedMemoryId, failedMemoryId] = scenarioSeedMemoryIds(guideTrial.scenario);
    assert.throws(() => recordCampaignTrialGuideResponse({
      directory: guideFailure.directory,
      expectedRevision: guideClaim.ledger.revision,
      trialId: guideTrial.trial_id,
      requestSource: guideRequest.request_source,
      httpStatus: 200,
      responseSource: guideResponseSource(guideTrial, guideClaim.preclaim, {
        agent_context: {
          use_now_memory_ids: [failedMemoryId],
          inspect_before_use_memory_ids: [],
          do_not_use_memory_ids: [passedMemoryId],
        },
        feedback_attribution_v1: {
          items: [
            { memory_id: failedMemoryId, served_surface: "use_now" },
            { memory_id: passedMemoryId, served_surface: "do_not_use" },
          ],
        },
      }),
    }), /served surface/);
    assert.throws(() => recordCampaignTrialGuideResponse({
      directory: guideFailure.directory,
      expectedRevision: guideClaim.ledger.revision,
      trialId: guideTrial.trial_id,
      requestSource: guideRequest.request_source,
      httpStatus: 200,
      responseSource: guideResponseSource(guideTrial, guideClaim.preclaim, {
        memory_packet: {
          relevant_memories: [
            { id: passedMemoryId, execution_state: { execution_outcome_role: "passed_solution" } },
            { id: failedMemoryId, execution_state: { execution_outcome_role: "passed_solution" } },
          ],
        },
      }),
    }), /execution role/);
  }
  assert.throws(() => recordCampaignTrialGuideResponse({
    directory: guideFailure.directory,
    expectedRevision: guideClaim.ledger.revision,
    trialId: guideTrial.trial_id,
    requestSource: guideRequest.request_source,
    httpStatus: 200,
    responseSource: guideResponseSource(guideTrial, guideClaim.preclaim, {
      feedback_attribution_v1: { projection_complete: false },
    }),
  }), /projection must be complete/);
  const guideFailed = settleCampaignTrial({
    directory: guideFailure.directory,
    expectedRevision: guideClaim.ledger.revision,
    receipt: failureReceipt(guideTrial, guideClaim.preclaim, {
      reason_code: "runtime_rejected",
      last_confirmed_stage: "guide",
    }),
  });
  assert.equal(guideFailed.trials.find((entry) => entry.trial_id === guideTrial.trial_id).status, "failed");

  const recorderFailure = create();
  const recorderTrial = recorderFailure.ledger.trials.find((entry) => entry.group === "aionis");
  recorderFailure.ledger = completeTrialsBefore(recorderFailure.directory, recorderFailure.ledger, recorderTrial);
  const recorderResponse = claimDispatchRespond(
    recorderFailure.directory,
    recorderFailure.ledger,
    recorderTrial,
  );
  const recorderFailed = settleCampaignTrial({
    directory: recorderFailure.directory,
    expectedRevision: recorderResponse.ledger.revision,
    receipt: failureReceipt(recorderTrial, recorderResponse.preclaim, {
      reason_code: "runtime_rejected",
      last_confirmed_stage: "flight_recorder",
    }),
  });
  assert.equal(recorderFailed.trials.find((entry) => entry.trial_id === recorderTrial.trial_id).status, "failed");
});

test("completed settlement is derived only from durable post-trial Runtime evidence", () => {
  const created = create();
  const { directory } = created;
  const first = created.ledger.trials.find(
    (trial) => trial.phase === "pilot" && trial.group === "aionis" && trial.scenario === "branch_recovery",
  );
  let current = completeTrialsBefore(directory, created.ledger, first);
  const response = claimDispatchRespond(directory, current, first);
  const forged = successReceipt(first, response.preclaim, response.checkpoint);
  forged.tool_result.expected_choice = verifierFor(first).unsafe_choice;
  assert.throws(() => settleCampaignTrial({
    directory,
    expectedRevision: response.ledger.revision,
    receipt: forged,
  }), /internally derived/);
  assert.throws(() => completeCampaignTrial({
    directory,
    expectedRevision: response.ledger.revision,
    trialId: first.trial_id,
  }), /complete durable post-trial Runtime chain/);
  current = completePostTrialChain(directory, response.ledger, first, response.preclaim);
  const readyTrial = current.trials.find((trial) => trial.trial_id === first.trial_id);
  assert.deepEqual(readyTrial.post_trial_checkpoints.map((entry) => entry.stage), [
    "outcome_observe",
    "feedback",
    "measure",
    "measure_replay",
    "operator_snapshot",
    "flight_recorder",
  ]);
  const recorderCas = path.join(directory, readyTrial.post_trial_checkpoints.at(-1).response_evidence.cas_path);
  const recorderBytes = fs.readFileSync(recorderCas);
  fs.writeFileSync(recorderCas, Buffer.concat([recorderBytes, Buffer.from(" ")]));
  assert.throws(() => readCampaignLedger({ directory }), /response evidence failed verification.*(?:size|SHA-256) mismatch/);
  fs.writeFileSync(recorderCas, recorderBytes);
  current = completeCampaignTrial({
    directory,
    expectedRevision: current.revision,
    trialId: first.trial_id,
  });
  const settled = current.trials.find((trial) => trial.trial_id === first.trial_id).settlement.receipt;
  assert.equal(settled.aionis.outcome_response_sha256, readyTrial.post_trial_checkpoints[0].checkpoint.response_sha256);
  assert.equal(settled.tool_result.choice, response.checkpoint.tool_result.choice);
  const second = current.trials.find(
    (trial) => trial.phase === "pilot"
      && trial.group === "aionis"
      && trial.scenario === "negative_transfer",
  );
  current = completeTrialsBefore(directory, current, second);
  const secondClaim = claimCampaignTrial({ directory, expectedRevision: current.revision, trialId: second.trial_id });
  const secondGuideRequest = renderCampaignTrialGuideRequest({ directory, trialId: second.trial_id });
  assert.throws(() => recordCampaignTrialGuideResponse({
    directory,
    expectedRevision: secondClaim.ledger.revision,
    trialId: second.trial_id,
    requestSource: secondGuideRequest.request_source,
    httpStatus: 200,
    responseSource: guideResponseSource(second, secondClaim.preclaim, {
      guide_trace_id: response.guideCheckpoint.guide_trace_id,
    }),
  }), /guide trace ID must be unique/);
  const secondGuide = recordCampaignTrialGuideResponse({
    directory,
    expectedRevision: secondClaim.ledger.revision,
    trialId: second.trial_id,
    requestSource: secondGuideRequest.request_source,
    httpStatus: 200,
    responseSource: guideResponseSource(second, secondClaim.preclaim),
  });
  const secondPrepared = prepareCampaignTrialProviderRequest({
    directory,
    expectedRevision: secondGuide.ledger.revision,
    trialId: second.trial_id,
  });
  current = markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: secondPrepared.ledger.revision,
    trialId: second.trial_id,
    requestSource: secondPrepared.request_source,
  });
  const validSource = providerResponseSource(second);
  const retrySource = Buffer.from(JSON.stringify({ error: { code: 429, message: "rate limited" } }));
  assert.throws(() => recordCampaignTrialProviderRetryableHttpResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 400,
    responseSource: retrySource,
  }), /outside the frozen retry allowlist/);
  assert.throws(() => recordCampaignTrialProviderRetryableHttpResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 429,
    responseSource: Buffer.from(JSON.stringify({ error: { code: 429, message: "rate limited" } })),
    networkCode: "ECONNRESET",
  }), /options keys/);
  current = recordCampaignTrialProviderRetryableHttpResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 429,
    responseSource: retrySource,
  });
  const retryTrial = current.trials.find((trial) => trial.trial_id === second.trial_id);
  assert.equal(retryTrial.status, "provider_retry_ready");
  assert.equal(retryTrial.provider_transport_attempts[0].evidence_sha256, hash(retrySource));
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: validSource,
  }), /ambiguous provider dispatch checkpoint/);
  current = markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    requestSource: readCampaignTrialPreparedProviderRequest({ directory, trialId: second.trial_id }),
  });
  const semanticRetry = providerResponseSource(second, {
    mutate_response(value) {
      value.choices[0].message.tool_calls.push(structuredClone(value.choices[0].message.tool_calls[0]));
    },
  });
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: semanticRetry,
  }), /exactly one native function tool call/);
  const invalidUsage = providerResponseSource(second, {
    provider_usage: { input_tokens: 100, output_tokens: 10, total_tokens: 999, cost_microusd: 1_000 },
  });
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: invalidUsage,
  }), /total_tokens must equal/);
  const wrongModel = providerResponseSource(second, { returned_model: "deepseek/not-frozen" });
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: wrongModel,
  }), /outside the frozen returned-model allowlist/);
  const duplicateProviderId = providerResponseSource(second, {
    provider_request_id: response.checkpoint.provider_request_id,
  });
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: duplicateProviderId,
  }), /provider request ID must be unique/);
  assert.throws(() => recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: validSource,
    transportAttemptEvidence: [],
  }), /options keys/);
  current = recordCampaignTrialProviderResponse({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
    httpStatus: 200,
    responseSource: validSource,
  });
  const unique = {
    ...current.trials.find((trial) => trial.trial_id === second.trial_id).provider_response,
    guide_response_checkpoint: secondGuide.checkpoint,
  };
  assert.equal(current.trials.find((trial) => trial.trial_id === second.trial_id).status, "provider_responded");
  assert.equal(unique.transport_attempts, 2);
  current = completePostTrialChain(directory, current, second, secondClaim.preclaim);
  current = completeCampaignTrial({
    directory,
    expectedRevision: current.revision,
    trialId: second.trial_id,
  });
  assert.equal(current.trials.find((trial) => trial.trial_id === second.trial_id).status, "completed");
});

test("pilot admission derives status and recovery facts from trial state plus raw worker CAS", () => {
  const { directory, ledger } = create();
  const unsafeTrial = ledger.trials.find(
    (trial) => trial.phase === "pilot" && trial.group === "aionis" && trial.scenario === "negative_transfer",
  );
  let current = completeTrials(
    directory,
    ledger,
    (trial) => trial.phase === "pilot",
    (trial) => (trial.trial_id === unsafeTrial.trial_id
      ? { choice: verifierFor(trial).unsafe_choice }
      : {}),
  );
  const ref = workerStateRef(directory, current, "pilot", "none", PILOT_RECORDED_AT);
  assert.throws(() => recordCampaignPilotAdmission({
    directory,
    expectedRevision: current.revision,
    workerStateRef: ref,
    receipt: { status: "pass" },
  }), /pilot admission options keys/);
  current = recordCampaignPilotAdmission({
    directory,
    expectedRevision: current.revision,
    workerStateRef: ref,
  });
  assert.equal(current.status, "failed");
  assert.equal(current.pilot_admission.receipt.status, "fail");
  assert.deepEqual(current.pilot_admission.receipt.facts.transport_authority, {
    schema_version: "aionis_transport_authority_v1",
    status: "blocked",
    reason_code: "trusted_transport_collector_unavailable",
  });
  assert.deepEqual(
    current.pilot_admission.receipt.facts.recovery_evidence.worker_state_ref,
    ref,
  );
});

test("the transport retry ceiling blocks an extra provider send before dispatch", () => {
  const { directory, ledger } = create();
  const trial = ledger.trials.find((entry) => entry.phase === "pilot");
  const prepared = claimPrepareDispatch(directory, ledger, trial);
  let current = prepared.ledger;
  for (let attempt = 1; attempt <= AUTHORITY.retry_policy.transport_max_attempts; attempt += 1) {
    current = recordCampaignTrialProviderRetryableHttpResponse({
      directory,
      expectedRevision: current.revision,
      trialId: trial.trial_id,
      httpStatus: 429,
      responseSource: Buffer.from(JSON.stringify({ error: { code: 429, message: `attempt-${attempt}` } })),
    });
    if (attempt < AUTHORITY.retry_policy.transport_max_attempts) {
      current = markCampaignTrialProviderDispatch({
        directory,
        expectedRevision: current.revision,
        trialId: trial.trial_id,
        requestSource: readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
      });
    }
  }
  assert.throws(() => markCampaignTrialProviderDispatch({
    directory,
    expectedRevision: current.revision,
    trialId: trial.trial_id,
    requestSource: readCampaignTrialPreparedProviderRequest({ directory, trialId: trial.trial_id }),
  }), /exceeds the frozen transport attempt ceiling before dispatch/);
  const reloaded = readCampaignLedger({ directory });
  const retried = reloaded.trials.find((entry) => entry.trial_id === trial.trial_id);
  assert.equal(retried.status, "provider_retry_ready");
  assert.equal(retried.provider_transport_attempts.length, 3);
  assert.equal(reloaded.terminal_failure, null);
});

test("a provider response that crosses the campaign cost ceiling is durably terminal", () => {
  const { directory, ledger } = create();
  const trial = ledger.trials.find((entry) => entry.phase === "pilot");
  const response = claimDispatchRespond(
    directory,
    ledger,
    trial,
    {
      provider_usage: {
        input_tokens: 100,
        output_tokens: 10,
        total_tokens: 110,
        cost_microusd: 50_000_000,
      },
    },
  );
  assert.equal(response.ledger.status, "failed");
  assert.equal(response.ledger.campaign_cost_microusd, 50_000_000);
  assert.deepEqual(response.ledger.terminal_failure, {
    reason_code: "campaign_cost_ceiling_exhausted",
    trial_id: trial.trial_id,
    provider_response_checkpoint_sha256: response.ledger.trials[0].provider_response_sha256,
    observed_cost_microusd: 50_000_000,
    limit_cost_microusd: 50_000_000,
  });
  const reloaded = readCampaignLedger({ directory });
  assert.equal(reloaded.status, "failed");
  assert.equal(reloaded.trials.find((entry) => entry.trial_id === trial.trial_id).status, "provider_responded");
  assert.throws(() => claimCampaignTrial({
    directory,
    expectedRevision: reloaded.revision,
    trialId: ledger.trials.find((entry) => entry.trial_id !== trial.trial_id).trial_id,
  }), /terminal campaign state/);
});

test("a clean synthetic pilot remains terminally blocked without a trusted transport collector", () => {
  const { directory, ledger } = create();
  const current = settlePilot(directory, ledger, (trial) => (trial.group === "aionis"
    ? { learningAttributionStatus: "verified_host_receipt" }
    : {}));
  assert.equal(current.status, "failed");
  assert.equal(current.pilot_admission.receipt.facts.wrong_direct_use, 0);
  assert.deepEqual(current.pilot_admission.receipt.facts.aionis_action_completion, { passed: 3, total: 3 });
  assert.deepEqual(current.pilot_admission.receipt.facts.feedback_coverage, { passed: 3, total: 3 });
  assert.equal(current.pilot_admission.receipt.facts.transport_authority.reason_code,
    "trusted_transport_collector_unavailable");
  assert.throws(() => beginCampaignSoak({
    directory,
    expectedRevision: current.revision,
    source: source("soak", 202),
    startedAt: WAVE_STARTED_AT[0],
  }), /terminal campaign state|requires a passed pilot/);
});

test("final soak admission cannot be self-reported while product invariant authority is unfrozen", () => {
  const { directory, ledger } = create();
  assert.throws(() => inspectCampaignOfflineSqliteEvidence({
    directory,
    databasePath: path.join(directory, "runtime.sqlite"),
  }), /requires the terminal soak wave in progress/);
  assert.throws(() => recordCampaignFinalSoakAdmission({
    directory,
    expectedRevision: ledger.revision,
    receipt: { status: "pass" },
  }), /product_invariant_query_contract_unfrozen/);
});

test("soak and final admission remain unreachable behind independent fail-closed blockers", () => {
  const { directory, ledger } = create();
  const current = settlePilot(directory, ledger);
  assert.equal(current.status, "failed");
  assert.throws(() => beginCampaignSoak({
    directory,
    expectedRevision: current.revision,
    source: source("soak", 202),
    startedAt: WAVE_STARTED_AT[0],
  }), /terminal campaign state|requires a passed pilot/);
  assert.throws(() => recordCampaignFinalSoakAdmission({
    directory,
    expectedRevision: current.revision,
    receipt: { status: "pass" },
  }), /product_invariant_query_contract_unfrozen/);
  const reloaded = readCampaignLedger({ directory });
  assert.equal(reloaded.status, "failed");
  assert.equal(reloaded.final_soak_admission, null);
});

test("stable canonical receipt IDs, tamper checks, ACL, live locks, and CAS all fail closed", () => {
  const { directory, ledger } = create();
  const [first, second] = ledger.trials;
  assert.throws(() => claimCampaignTrial({
    directory,
    expectedRevision: ledger.revision,
    trialId: second.trial_id,
  }), /deterministic trial order/);
  const claimed = claimCampaignTrial({ directory, expectedRevision: ledger.revision, trialId: first.trial_id });
  assert.throws(() => claimCampaignTrial({
    directory,
    expectedRevision: ledger.revision,
    trialId: second.trial_id,
  }), /CAS mismatch/);
  const prepared = prepareCampaignTrialProviderRequest({
    directory,
    expectedRevision: claimed.ledger.revision,
    trialId: first.trial_id,
  });
  const lock = path.join(directory, ".campaign-ledger.lock");
  const heldLock = acquireExclusiveLock(lock);
  try {
    assert.throws(() => markCampaignTrialProviderDispatch({
      directory,
      expectedRevision: prepared.ledger.revision,
      trialId: first.trial_id,
      requestSource: prepared.request_source,
    }), /lock acquisition failed.*held by/);
  } finally {
    heldLock.release();
  }
  assert.equal(fs.existsSync(lock), true, "the persistent SQLite lock authority must remain after release");

  const envelopePath = path.join(directory, "campaign-ledger.json");
  fs.chmodSync(envelopePath, 0o644);
  assert.throws(() => readCampaignLedger({ directory }), /permissions must be 600/);
  fs.chmodSync(envelopePath, 0o600);
  const envelope = JSON.parse(fs.readFileSync(envelopePath, "utf8"));
  envelope.payload.candidate.commit = "b".repeat(40);
  envelope.payload_sha256 = hash(Buffer.from(canonical(envelope.payload)));
  fs.writeFileSync(envelopePath, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => readCampaignLedger({ directory }), /candidate release-lock binding/);

  const ordered = { z: 1, a: { y: 2, b: 3 } };
  const reordered = { a: { b: 3, y: 2 }, z: 1 };
  assert.equal(hash(Buffer.from(canonical(ordered))), hash(Buffer.from(canonical(reordered))));
});

test("two real processes racing on one revision produce exactly one durable claim", async () => {
  const { directory, ledger } = create();
  const results = await Promise.all([
    spawnClaim(directory, ledger.trials[0].trial_id, ledger.revision),
    spawnClaim(directory, ledger.trials[0].trial_id, ledger.revision),
  ]);
  assert.deepEqual(results.map((result) => result.code).sort(), [0, 1]);
  assert.equal(results.some((result) => /lock acquisition failed|CAS mismatch/.test(result.stderr)), true);
  const recovered = readCampaignLedger({ directory });
  assert.equal(recovered.revision, ledger.revision + 1);
  assert.equal(recovered.trials.filter((trial) => trial.status === "claimed").length, 1);
  assert.equal(recovered.trials.filter((trial) => trial.status === "pending").length, 89);
  assert.equal(
    fs.existsSync(path.join(directory, ".campaign-ledger.lock")),
    true,
    "the persistent SQLite lock database remains after both processes exit",
  );
});
