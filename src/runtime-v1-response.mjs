import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectArray,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectPositiveInteger,
  expectSha256,
  expectText,
} from "./canonical.mjs";

const RECEIPT_KEYS = Object.freeze([
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
]);

const CONTRACT_KEYS = Object.freeze([
  "authority",
  "compiler",
  "contract_sha256",
  "coverage_certificate",
  "excluded_capsules",
  "identity",
  "obligations",
  "safe_fallback",
  "schema_version",
  "selected_capsules",
]);

const EVENT_KEYS = Object.freeze([
  "capsule_fact_count",
  "capsule_fact_set_sha256",
  "cause_event_ref",
  "context",
  "created_at",
  "effect_certificate_sha256",
  "effect_member_sequence",
  "episode_id",
  "event_id",
  "event_kind",
  "event_sequence",
  "event_sha256",
  "payload",
  "payload_sha256",
  "previous_event_ref",
  "render_result_sha256",
  "schema_version",
  "scope",
  "source_operation",
  "tenant_id",
]);

function fail(code) {
  throw new Error(`aionis_eval_runtime_response_${code}`);
}

function expectNullableSha256(value, field) {
  if (value !== null) expectSha256(value, field);
}

function verifyEventRef(value, field, expectedKind = null) {
  const record = expectExactRecord(value, [
    "event_id", "event_kind", "event_sequence", "event_sha256",
  ], field);
  expectPositiveInteger(record.event_sequence, `${field}_sequence`);
  expectText(record.event_id, `${field}_id`);
  if (!new Set([
    "contract_exposed", "capsule_use_observed", "outcome_observed", "effect_certified",
  ]).has(record.event_kind)) fail(`${field}_kind_invalid`);
  if (expectedKind !== null && record.event_kind !== expectedKind) {
    fail(`${field}_kind_mismatch`);
  }
  expectSha256(record.event_sha256, `${field}_sha256`);
  return record;
}

function eventRef(event) {
  return canonicalClone({
    event_sequence: event.event_sequence,
    event_id: event.event_id,
    event_kind: event.event_kind,
    event_sha256: event.event_sha256,
  });
}

function verifyDecisionEvent(value, field, expected) {
  const event = expectExactRecord(value, EVENT_KEYS, field);
  if (event.schema_version !== "episode_event_v1"
    || event.event_kind !== expected.kind
    || event.source_operation?.operation_kind !== expected.operationKind
    || event.source_operation?.operation_id !== expected.operationId
    || event.context?.context_kind !== "decision"
    || event.context?.decision_id !== expected.decisionId
    || event.episode_id !== expected.episodeId
    || event.scope !== expected.scope) {
    fail(`${field}_binding_invalid`);
  }
  expectPositiveInteger(event.event_sequence, `${field}_sequence`);
  expectText(event.event_id, `${field}_id`);
  expectText(event.tenant_id, `${field}_tenant_id`);
  expectCanonicalTimestamp(event.created_at, `${field}_created_at`);
  expectSha256(event.render_result_sha256, `${field}_render_result_sha256`);
  expectSha256(event.payload_sha256, `${field}_payload_sha256`);
  expectSha256(event.event_sha256, `${field}_event_sha256`);
  expectSha256(event.source_operation.request_sha256, `${field}_source_request_sha256`);
  if (canonicalSha256(event.payload) !== event.payload_sha256) {
    fail(`${field}_payload_sha256_mismatch`);
  }
  const body = Object.fromEntries(
    Object.entries(event).filter(([key]) => key !== "event_sha256"),
  );
  if (canonicalSha256(body) !== event.event_sha256) {
    fail(`${field}_event_sha256_mismatch`);
  }
  return event;
}

function verifyOperationReceipt(response, expected) {
  expectSha256(response.operation_receipt_sha256, "operation_receipt_sha256");
  const receipt = expectExactRecord(
    response.operation_receipt,
    RECEIPT_KEYS,
    "operation_receipt",
  );
  if (receipt.schema_version !== "continuation_runtime_operation_receipt_v1"
    || receipt.operation_kind !== expected.kind
    || receipt.operation_id !== expected.operationId
    || (expected.scope !== undefined && receipt.scope !== expected.scope)) {
    fail("operation_receipt_binding_invalid");
  }
  for (const field of ["tenant_id", "scope", "operation_id"]) {
    expectText(receipt[field], `operation_receipt_${field}`);
  }
  if (!new Set(["trusted_host", "operator", "worker"]).has(receipt.actor_kind)) {
    fail("operation_receipt_actor_kind_invalid");
  }
  expectSha256(receipt.actor_principal_sha256, "operation_receipt_actor_sha256");
  expectSha256(receipt.request_sha256, "operation_receipt_request_sha256");
  expectCanonicalTimestamp(receipt.completed_at, "operation_receipt_completed_at");
  if (canonicalSha256(receipt) !== response.operation_receipt_sha256) {
    fail("operation_receipt_sha256_mismatch");
  }
  return receipt;
}

function verifySet(value, field) {
  const record = expectExactRecord(value, ["count", "refs", "set_sha256"], field);
  const refs = expectArray(record.refs, `${field}_refs`, { maximum: 4_096 });
  if (!Number.isSafeInteger(record.count) || record.count < 0 || record.count !== refs.length) {
    fail(`${field}_count_invalid`);
  }
  expectSha256(record.set_sha256, `${field}_set_sha256`);
  if (canonicalSha256(refs) !== record.set_sha256) fail(`${field}_set_sha256_mismatch`);
  return record;
}

function verifySnapshotRef(value) {
  const record = expectExactRecord(value, [
    "host_task_envelope_sha256", "world_snapshot_id", "world_snapshot_sha256",
  ], "observation_snapshot_ref");
  expectText(record.world_snapshot_id, "world_snapshot_id");
  expectSha256(record.world_snapshot_sha256, "world_snapshot_sha256");
  expectSha256(record.host_task_envelope_sha256, "host_task_envelope_sha256");
  return record;
}

export function decodeRecordObservationsResponseV1(value, expected) {
  const response = expectExactRecord(value, [
    "observation_batch_id",
    "operation_receipt",
    "operation_receipt_sha256",
    "result",
    "schema_version",
  ], "record_observations_response");
  if (response.schema_version !== "record_observations_response_v1"
    || response.observation_batch_id !== expected.operationId) {
    fail("record_observations_binding_invalid");
  }
  const result = expectExactRecord(response.result, [
    "authority_branch_set",
    "durable_job_set",
    "memory_revision_ref",
    "observation_snapshot_ref",
    "schema_version",
  ], "record_observations_result");
  if (result.schema_version !== "record_observations_result_v1") {
    fail("record_observations_result_schema_invalid");
  }
  const snapshotRef = verifySnapshotRef(result.observation_snapshot_ref);
  if (snapshotRef.world_snapshot_id !== expected.operationId) {
    fail("world_snapshot_operation_binding_invalid");
  }
  verifySet(result.authority_branch_set, "authority_branch_set");
  verifySet(result.durable_job_set, "durable_job_set");
  const receipt = verifyOperationReceipt(response, {
    kind: "record_observations",
    operationId: expected.operationId,
    scope: expected.scope,
  });
  if (canonicalJson(receipt.result) !== canonicalJson(result)) {
    fail("record_observations_result_receipt_mismatch");
  }
  return canonicalClone({ response, snapshotRef });
}

function verifyCapsuleRef(value, field) {
  const record = expectExactRecord(value, [
    "capsule_id", "capsule_revision", "capsule_sha256",
  ], field);
  expectText(record.capsule_id, `${field}_id`);
  expectPositiveInteger(record.capsule_revision, `${field}_revision`);
  expectSha256(record.capsule_sha256, `${field}_sha256`);
  return record;
}

function verifySelectedCapsule(value, index) {
  const field = `selected_capsule_${index}`;
  const record = expectExactRecord(value, [
    "capsule", "coverage_bindings", "satisfied_probe_ids", "selection_reason_codes", "surface",
  ], field);
  const capsule = verifyCapsuleRef(record.capsule, `${field}_ref`);
  if (!new Set(["use_now", "inspect_before_use", "do_not_use", "rehydrate"])
    .has(record.surface)) fail(`${field}_surface_invalid`);
  const bindings = expectArray(record.coverage_bindings, `${field}_coverage_bindings`, {
    minimum: 1,
    maximum: 256,
  });
  for (const [bindingIndex, bindingValue] of bindings.entries()) {
    const binding = expectExactRecord(bindingValue, [
      "coverage_claim_sha256", "obligation_id",
    ], `${field}_coverage_binding_${bindingIndex}`);
    expectText(binding.obligation_id, `${field}_coverage_binding_${bindingIndex}_obligation`);
    expectSha256(
      binding.coverage_claim_sha256,
      `${field}_coverage_binding_${bindingIndex}_sha256`,
    );
  }
  expectArray(record.satisfied_probe_ids, `${field}_satisfied_probe_ids`, { maximum: 256 });
  expectArray(record.selection_reason_codes, `${field}_selection_reason_codes`, { maximum: 256 });
  return canonicalClone({ capsule, surface: record.surface });
}

function verifyContract(value) {
  const contract = expectExactRecord(value, CONTRACT_KEYS, "continuation_contract");
  if (contract.schema_version !== "continuation_contract_v1") {
    fail("continuation_contract_schema_invalid");
  }
  expectSha256(contract.contract_sha256, "contract_sha256");
  const body = Object.fromEntries(
    Object.entries(contract).filter(([key]) => key !== "contract_sha256"),
  );
  if (canonicalSha256(body) !== contract.contract_sha256) {
    fail("contract_sha256_mismatch");
  }
  const identity = expectExactRecord(contract.identity, [
    "collection_principal_sha256",
    "consumer_agent_id",
    "consumer_team_id",
    "decision_id",
    "episode_id",
    "host_task_envelope_sha256",
    "host_task_id",
    "run_id",
    "scope",
    "source_event_sha256",
    "source_task_sha256",
    "task_family",
    "task_signature",
    "tenant_id",
    "workflow_signature",
    "workspace_signature",
    "world_snapshot_id",
    "world_snapshot_sha256",
  ], "continuation_identity");
  for (const field of [
    "decision_id", "episode_id", "host_task_id", "run_id", "scope", "task_family",
    "task_signature", "tenant_id", "workspace_signature", "world_snapshot_id",
  ]) expectText(identity[field], `continuation_identity_${field}`);
  for (const field of [
    "collection_principal_sha256", "host_task_envelope_sha256", "source_event_sha256",
    "source_task_sha256", "world_snapshot_sha256",
  ]) expectSha256(identity[field], `continuation_identity_${field}`);

  const authority = expectExactRecord(contract.authority, [
    "authoritative_learning_head",
    "authority_subject_sha256",
    "compiler_policy_ref",
    "evidence_policy_ref",
    "experiment_cohort_ref",
    "memory_scope_head_revision",
    "memory_scope_head_sha256",
    "served_learning_branch",
    "serving_assignment_receipt",
    "serving_mode",
  ], "continuation_authority");
  if (authority.serving_mode !== "authoritative_unassigned"
    || authority.experiment_cohort_ref !== null
    || authority.serving_assignment_receipt !== null) {
    fail("pilot_cohort_boundary_violated");
  }
  expectSha256(authority.authority_subject_sha256, "authority_subject_sha256");
  expectPositiveInteger(authority.memory_scope_head_revision, "memory_scope_head_revision");
  expectSha256(authority.memory_scope_head_sha256, "memory_scope_head_sha256");

  const obligations = expectArray(contract.obligations, "continuation_obligations", {
    minimum: 1,
    maximum: 64,
  });
  const obligationById = new Map();
  for (const [index, obligationValue] of obligations.entries()) {
    const obligation = expectExactRecord(obligationValue, [
      "evidence_requirement", "kind", "obligation_id", "required_probe_ids",
      "requirement", "source_refs", "statement", "target_refs",
    ], `continuation_obligation_${index}`);
    expectText(obligation.obligation_id, `continuation_obligation_${index}_id`);
    if (!new Set(["hard", "advisory"]).has(obligation.requirement)
      || obligationById.has(obligation.obligation_id)) {
      fail("continuation_obligation_invalid");
    }
    obligationById.set(obligation.obligation_id, obligation);
  }
  if (![...obligationById.values()].some((obligation) =>
    obligation.requirement === "hard")) fail("continuation_hard_obligation_missing");

  const selectedCapsules = expectArray(contract.selected_capsules, "selected_capsules", {
    minimum: 1,
    maximum: 256,
  }).map(verifySelectedCapsule);
  const coverage = expectExactRecord(contract.coverage_certificate, [
    "budget_satisfied",
    "candidate_partition",
    "candidate_universe_sha256",
    "certificate_sha256",
    "certificate_version",
    "compilation_input_sha256",
    "conflict_free",
    "coverage",
    "direct_use_preconditions_complete",
    "hard_obligation_coverage_complete",
    "obligation_universe_sha256",
    "reason_codes",
    "required_render_bytes",
    "selected_surface_sha256",
    "status",
    "world_snapshot_sha256",
  ], "coverage_certificate");
  expectSha256(coverage.certificate_sha256, "coverage_certificate_sha256");
  const coverageRows = expectArray(coverage.coverage, "coverage_rows", {
    minimum: obligations.length,
    maximum: obligations.length,
  });
  for (const [index, coverageValue] of coverageRows.entries()) {
    const row = expectExactRecord(coverageValue, [
      "capsule_refs", "obligation_id", "reason_codes", "satisfied_probe_ids", "status",
    ], `coverage_row_${index}`);
    const obligation = obligations[index];
    if (row.obligation_id !== obligation.obligation_id
      || !new Set(["covered", "uncovered", "conflicted"]).has(row.status)
      || (obligation.requirement === "hard" && row.status !== "covered")) {
      fail("coverage_obligation_binding_invalid");
    }
    const capsuleRefs = expectArray(row.capsule_refs, `coverage_row_${index}_capsule_refs`, {
      minimum: obligation.requirement === "hard" ? 1 : 0,
      maximum: 256,
    });
    for (const [refIndex, ref] of capsuleRefs.entries()) {
      verifyCapsuleRef(ref, `coverage_row_${index}_capsule_ref_${refIndex}`);
    }
    expectArray(row.reason_codes, `coverage_row_${index}_reason_codes`, { maximum: 256 });
    expectArray(row.satisfied_probe_ids, `coverage_row_${index}_probe_ids`, { maximum: 256 });
  }
  const partition = expectExactRecord(coverage.candidate_partition, [
    "candidate_count", "excluded_capsule_set_sha256", "excluded_count",
    "selected_capsule_set_sha256", "selected_count",
  ], "coverage_candidate_partition");
  if (partition.selected_count !== selectedCapsules.length
    || !Number.isSafeInteger(partition.candidate_count)
    || !Number.isSafeInteger(partition.excluded_count)
    || partition.candidate_count !== partition.selected_count + partition.excluded_count) {
    fail("coverage_candidate_partition_invalid");
  }
  expectSha256(partition.selected_capsule_set_sha256, "selected_capsule_set_sha256");
  expectSha256(partition.excluded_capsule_set_sha256, "excluded_capsule_set_sha256");
  const coverageBody = Object.fromEntries(
    Object.entries(coverage).filter(([key]) => key !== "certificate_sha256"),
  );
  if (canonicalSha256(coverageBody) !== coverage.certificate_sha256) {
    fail("coverage_certificate_sha256_mismatch");
  }
  if (coverage.status !== "complete") fail("coverage_status_incomplete");
  if (coverage.hard_obligation_coverage_complete !== true) {
    fail("coverage_hard_obligation_incomplete");
  }
  if (coverage.direct_use_preconditions_complete !== true) {
    fail("coverage_direct_use_precondition_incomplete");
  }
  if (coverage.conflict_free !== true) fail("coverage_conflict_detected");
  if (coverage.budget_satisfied !== true) fail("coverage_budget_unsatisfied");
  return canonicalClone({ contract, identity, authority, selectedCapsules, coverage });
}

function verifyRenderResult(value) {
  const render = expectExactRecord(value, [
    "budget_bytes", "content", "format", "projection_sha256", "render_result_sha256",
    "required_bytes", "status",
  ], "render_result");
  if (render.status !== "rendered" || render.format !== "aionis-agent-context-v1") {
    fail("render_result_not_rendered");
  }
  expectText(render.content, "render_result_content", {
    controls: true,
    maximumBytes: 1_048_576,
    trimmed: false,
  });
  expectSha256(render.projection_sha256, "render_projection_sha256");
  expectSha256(render.render_result_sha256, "render_result_sha256");
  const body = Object.fromEntries(
    Object.entries(render).filter(([key]) => key !== "render_result_sha256"),
  );
  if (canonicalSha256(body) !== render.render_result_sha256) {
    fail("render_result_sha256_mismatch");
  }
  return render;
}

export function decodeCreateContinuationResponseV1(value, expected) {
  const response = expectExactRecord(value, [
    "continuation_contract",
    "decision_id",
    "exposure_receipt",
    "operation_receipt",
    "operation_receipt_sha256",
    "render_result",
    "schema_version",
  ], "create_continuation_response");
  if (response.schema_version !== "create_continuation_response_v1") {
    fail("create_continuation_schema_invalid");
  }
  const verified = verifyContract(response.continuation_contract);
  const render = verifyRenderResult(response.render_result);
  const exposureReceipt = verifyEventRef(
    response.exposure_receipt,
    "exposure_receipt",
    "contract_exposed",
  );
  if (response.decision_id !== verified.identity.decision_id) {
    fail("continuation_decision_binding_invalid");
  }
  const receipt = verifyOperationReceipt(response, {
    kind: "create_continuation",
    operationId: expected.operationId,
    scope: expected.scope,
  });
  const result = expectExactRecord(receipt.result, [
    "decision_id", "episode_id", "event_refs", "schema_version",
  ], "create_continuation_result");
  if (result.schema_version !== "create_continuation_result_v1"
    || result.decision_id !== response.decision_id
    || result.episode_id !== verified.identity.episode_id) {
    fail("create_continuation_result_binding_invalid");
  }
  const refs = expectArray(result.event_refs, "create_continuation_event_refs", {
    minimum: 1,
    maximum: 1,
  });
  verifyEventRef(refs[0], "create_continuation_event_ref", "contract_exposed");
  if (canonicalJson(refs[0]) !== canonicalJson(exposureReceipt)) {
    fail("create_continuation_exposure_receipt_mismatch");
  }
  return canonicalClone({
    response,
    contract: verified.contract,
    identity: verified.identity,
    authority: verified.authority,
    selectedCapsules: verified.selectedCapsules,
    coverage: verified.coverage,
    render,
    exposureReceipt,
  });
}

export function decodeRecordOutcomeResponseV1(value, expected) {
  const response = expectExactRecord(value, [
    "decision_id", "episode_id", "event_refs", "events", "ledger_head",
    "operation_receipt", "operation_receipt_sha256", "schema_version",
  ], "record_outcome_response");
  if (response.schema_version !== "record_outcome_response_v1"
    || response.decision_id !== expected.decisionId) fail("record_outcome_binding_invalid");
  expectText(response.episode_id, "record_outcome_episode_id");
  const refs = expectArray(response.event_refs, "record_outcome_event_refs", {
    minimum: 2,
    maximum: 2,
  });
  verifyEventRef(refs[0], "outcome_use_event_ref", "capsule_use_observed");
  verifyEventRef(refs[1], "outcome_observed_event_ref", "outcome_observed");
  const events = expectArray(response.events, "record_outcome_events", {
    minimum: refs.length,
    maximum: refs.length,
  });
  const useEvent = verifyDecisionEvent(events[0], "record_outcome_use_event", {
    kind: "capsule_use_observed",
    operationKind: "record_outcome",
    operationId: expected.operationId,
    decisionId: expected.decisionId,
    episodeId: response.episode_id,
    scope: expected.scope,
  });
  const outcomeEvent = verifyDecisionEvent(events[1], "record_outcome_outcome_event", {
    kind: "outcome_observed",
    operationKind: "record_outcome",
    operationId: expected.operationId,
    decisionId: expected.decisionId,
    episodeId: response.episode_id,
    scope: expected.scope,
  });
  if (canonicalJson(eventRef(useEvent)) !== canonicalJson(refs[0])
    || canonicalJson(eventRef(outcomeEvent)) !== canonicalJson(refs[1])
    || canonicalJson(outcomeEvent.previous_event_ref) !== canonicalJson(refs[0])
    || canonicalJson(outcomeEvent.cause_event_ref) !== canonicalJson(refs[0])) {
    fail("record_outcome_event_chain_invalid");
  }
  const usePayload = expectExactRecord(useEvent.payload, [
    "payload_kind", "use_receipt",
  ], "record_outcome_use_payload");
  const outcomePayload = expectExactRecord(outcomeEvent.payload, [
    "outcome_receipt", "payload_kind",
  ], "record_outcome_outcome_payload");
  if (usePayload.payload_kind !== "capsule_use_observed_v1"
    || outcomePayload.payload_kind !== "outcome_observed_v1"
    || canonicalJson(usePayload.use_receipt) !== canonicalJson(expected.useReceipt)
    || canonicalJson(outcomePayload.outcome_receipt)
      !== canonicalJson(expected.outcomeReceipt)) {
    fail("record_outcome_event_payload_binding_invalid");
  }
  const ledgerHead = verifyEventRef(response.ledger_head, "ledger_head");
  if (canonicalJson(ledgerHead) !== canonicalJson(refs.at(-1))) {
    fail("ledger_head_mismatch");
  }
  const receipt = verifyOperationReceipt(response, {
    kind: "record_outcome",
    operationId: expected.operationId,
    scope: expected.scope,
  });
  const result = expectExactRecord(receipt.result, [
    "decision_id", "episode_id", "event_refs", "schema_version",
  ], "record_outcome_result");
  if (result.schema_version !== "record_outcome_result_v1"
    || result.decision_id !== response.decision_id
    || result.episode_id !== response.episode_id
    || canonicalJson(result.event_refs) !== canonicalJson(refs)) {
    fail("record_outcome_receipt_result_mismatch");
  }
  return canonicalClone({ response, ledgerHead, eventRefs: refs, events });
}

export function decodeFullDecisionResponseV1(value, expected) {
  const response = expectExactRecord(value, [
    "authority_revisions",
    "continuation_contract",
    "effect_certificates",
    "events",
    "query_sha256",
    "render_result",
    "response_sha256",
    "schema_version",
    "summary",
  ], "decision_full_response");
  if (response.schema_version !== "continuation_decision_full_v1") {
    fail("decision_full_schema_invalid");
  }
  expectSha256(response.response_sha256, "decision_response_sha256");
  const responseBody = Object.fromEntries(
    Object.entries(response).filter(([key]) => key !== "response_sha256"),
  );
  if (canonicalSha256(responseBody) !== response.response_sha256) {
    fail("decision_response_sha256_mismatch");
  }
  const verified = verifyContract(response.continuation_contract);
  verifyRenderResult(response.render_result);
  const summary = expectExactRecord(response.summary, [
    "authority", "contract_sha256", "coverage_certificate_sha256", "coverage_status",
    "decision_id", "effect", "episode_id", "excluded_capsules", "exposure_event_ref",
    "outcome", "query_sha256", "render", "run_id", "safe_fallback", "schema_version",
    "selected_capsules", "task_identity",
  ], "decision_summary");
  if (summary.schema_version !== "continuation_decision_summary_v1"
    || summary.decision_id !== expected.decisionId
    || summary.decision_id !== verified.identity.decision_id
    || summary.contract_sha256 !== verified.contract.contract_sha256
    || summary.coverage_status !== "complete") {
    fail("decision_summary_binding_invalid");
  }
  const effect = expectExactRecord(summary.effect, ["certificate_refs", "state"],
    "decision_effect");
  if (effect.state !== "not_applicable"
    || expectArray(effect.certificate_refs, "effect_certificate_refs", { maximum: 0 }).length !== 0) {
    fail("pilot_effect_state_invalid");
  }
  const outcome = expectExactRecord(summary.outcome, [
    "outcome_event_ref", "state", "use_event_ref",
  ], "decision_outcome");
  if (outcome.state !== "outcome_observed") fail("decision_outcome_state_invalid");
  const useRef = verifyEventRef(
    outcome.use_event_ref,
    "decision_use_event_ref",
    "capsule_use_observed",
  );
  const outcomeRef = verifyEventRef(
    outcome.outcome_event_ref,
    "decision_outcome_event_ref",
    "outcome_observed",
  );
  const events = expectArray(response.events, "decision_events", {
    minimum: 3,
    maximum: 3,
  });
  const exposureEvent = verifyDecisionEvent(events[0], "decision_exposure_event", {
    kind: "contract_exposed",
    operationKind: "create_continuation",
    operationId: expected.decisionId,
    decisionId: expected.decisionId,
    episodeId: verified.identity.episode_id,
    scope: verified.identity.scope,
  });
  const useEvent = verifyDecisionEvent(events[1], "decision_use_event", {
    kind: "capsule_use_observed",
    operationKind: "record_outcome",
    operationId: expected.outcomeOperationId,
    decisionId: expected.decisionId,
    episodeId: verified.identity.episode_id,
    scope: verified.identity.scope,
  });
  const outcomeEvent = verifyDecisionEvent(events[2], "decision_outcome_event", {
    kind: "outcome_observed",
    operationKind: "record_outcome",
    operationId: expected.outcomeOperationId,
    decisionId: expected.decisionId,
    episodeId: verified.identity.episode_id,
    scope: verified.identity.scope,
  });
  const exposurePayload = expectExactRecord(exposureEvent.payload, [
    "continuation_contract", "payload_kind", "render_result",
  ], "decision_exposure_payload");
  const outcomePayload = expectExactRecord(outcomeEvent.payload, [
    "outcome_receipt", "payload_kind",
  ], "decision_outcome_payload");
  if (exposurePayload.payload_kind !== "contract_exposed_v1"
    || canonicalJson(exposurePayload.continuation_contract)
      !== canonicalJson(response.continuation_contract)
    || canonicalJson(exposurePayload.render_result) !== canonicalJson(response.render_result)
    || canonicalJson(eventRef(useEvent)) !== canonicalJson(useRef)
    || canonicalJson(eventRef(outcomeEvent)) !== canonicalJson(outcomeRef)
    || canonicalJson(useEvent.previous_event_ref) !== canonicalJson(eventRef(exposureEvent))
    || canonicalJson(outcomeEvent.previous_event_ref) !== canonicalJson(useRef)
    || canonicalJson(outcomeEvent.cause_event_ref) !== canonicalJson(useRef)
    || outcomePayload.payload_kind !== "outcome_observed_v1"
    || outcomePayload.outcome_receipt?.outcome !== expected.outcome) {
    fail("decision_event_chain_or_outcome_invalid");
  }
  if (expectArray(response.effect_certificates, "effect_certificates", {
    maximum: 0,
  }).length !== 0) fail("pilot_effect_certificates_invalid");
  expectNullableSha256(
    response.authority_revisions?.authoritative?.manifest?.manifest_sha256 ?? null,
    "authoritative_manifest_sha256",
  );
  return canonicalClone({ response, summary, effect, outcome });
}
