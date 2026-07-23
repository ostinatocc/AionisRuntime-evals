import { buildAgentModelInputV1 } from "./agent-action.mjs";
import {
  canonicalClone,
  canonicalJson,
  canonicalSha256,
  expectCanonicalTimestamp,
  expectExactRecord,
  expectNonNegativeInteger,
  expectPositiveInteger,
  expectSha256,
} from "./canonical.mjs";
import {
  verifyPilotCaseV1,
  verifyPilotCellV1,
  verifyPilotPlanV1,
} from "./pilot-contract.mjs";

const EVENT_KEYS = Object.freeze([
  "cell_ref",
  "event_kind",
  "event_sha256",
  "execution_authorization_sha256",
  "observed_at",
  "payload_sha256",
  "pilot_id",
  "plan_sha256",
  "previous_event_sha256",
  "schema_version",
  "sequence",
]);

const RESERVATION_KEYS = Object.freeze([
  "attempt_ordinal",
  "canonical_request_sha256",
  "cell_sha256",
  "execution_authorization_sha256",
  "isolation_sha256",
  "model_input_sha256",
  "opaque_cell_id",
  "pilot_id",
  "plan_sha256",
  "previous_cell_result_event_sha256",
  "reservation_sha256",
  "schema_version",
  "state",
]);

const REQUEST_STARTED_KEYS = Object.freeze([
  "attempt_ordinal",
  "canonical_request_sha256",
  "execution_authorization_sha256",
  "opaque_cell_id",
  "pilot_id",
  "plan_sha256",
  "request_started_sha256",
  "reservation_event_sha256",
  "reservation_sha256",
  "schema_version",
  "state",
]);

const COMPLETION_KEYS = Object.freeze([
  "assistant_message",
  "attempt_completion_sha256",
  "attempt_ordinal",
  "execution_authorization_sha256",
  "messages",
  "opaque_cell_id",
  "pilot_id",
  "plan_sha256",
  "request_receipt",
  "request_started_event_sha256",
  "reservation_sha256",
  "response_receipt",
  "schema_version",
  "state",
]);

const RUN_ABORTED_KEYS = Object.freeze([
  "active_attempt_ordinal",
  "active_provider_attempt_state",
  "cleanup_confirmed",
  "cleanup_receipt",
  "cleanup_receipt_sha256",
  "completed_cell_count",
  "execution_authorization_sha256",
  "failing_cell_ref",
  "failure_class",
  "failure_evidence_ref_sha256",
  "failure_stage",
  "next_attempt_ordinal",
  "pilot_id",
  "plan_sha256",
  "provider_attempt_completion_count",
  "provider_attempt_reservation_count",
  "schema_version",
  "state",
]);

const OWNER_CLEANUP_RECEIPT_KEYS = Object.freeze([
  "cleanup_confirmed",
  "cleanup_receipt_sha256",
  "close_attempt_count",
  "closed_owner_kinds",
  "failed_owner_kinds",
  "owner_count",
  "schema_version",
  "state",
]);

const RESOURCE_CLEANUP_RECEIPT_KEYS = Object.freeze([
  "cleanup_confirmed",
  "cleanup_receipt_sha256",
  "close_attempt_count",
  "closed_resource_ordinals",
  "failed_resource_ordinals",
  "owner_cleanup_receipt",
  "owner_cleanup_receipt_sha256",
  "resource_count",
  "schema_version",
  "state",
]);

const RESOURCE_CLEANUP_CONFIRMED_KEYS = Object.freeze([
  "cleanup_receipt",
  "cleanup_receipt_sha256",
  "execution_authorization_sha256",
  "pilot_id",
  "plan_sha256",
  "schema_version",
  "state",
]);

export const RELEASE_CLEANUP_OWNER_KINDS_V1 = Object.freeze([
  "runtime_owner",
  "workspace_owner",
]);

const CLEANUP_OWNER_KIND_SET = new Set(RELEASE_CLEANUP_OWNER_KINDS_V1);

export const PILOT_RUN_ABORT_FAILURE_STAGES_V1 = Object.freeze([
  "ledger",
  "cell_preparation",
  "provider",
  "provider_completion",
  "agent_execution",
  "verifier",
  "runtime_settlement",
  "cell_result",
  "scoring",
  "verdict",
  "run_close",
  "eval_provenance",
  "final_signer",
  "final_manifest_persist",
  "resource_cleanup",
  "harness",
]);

export const PILOT_RUN_ABORT_FAILURE_CLASSES_V1 = Object.freeze([
  "provider_or_network",
  "harness_infrastructure",
  "filesystem_infrastructure",
  "runtime_infrastructure",
  "verifier_infrastructure",
  "signature_infrastructure",
  "resource_cleanup_infrastructure",
  "provenance_invalid",
]);

const ACTIVE_PROVIDER_ATTEMPT_STATES = new Set([
  "no_active_attempt",
  "prepared_not_reserved",
  "request_may_have_started_burned",
  "provider_completed_pending_cell_result",
]);

function fail(code) {
  throw new Error(`aionis_eval_pilot_run_event_contract_${code}`);
}

function sameCanonical(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function nullableSha256(value, field) {
  if (value === null) return null;
  return expectSha256(value, field);
}

function verifySelfHash(record, hashField, field) {
  expectSha256(record[hashField], `${field}_${hashField}`);
  const body = Object.fromEntries(
    Object.entries(record).filter(([key]) => key !== hashField),
  );
  if (canonicalSha256(body) !== record[hashField]) fail(`${field}_self_hash_invalid`);
}

function verifyPlanCell(planValue, cellValue) {
  const plan = verifyPilotPlanV1(planValue);
  const cell = verifyPilotCellV1(cellValue);
  if (cell.pilot_id !== plan.pilot_id
    || cell.ordinal > plan.schedule.length
    || !sameCanonical(cell, plan.schedule[cell.ordinal - 1])) {
    fail("plan_cell_binding_invalid");
  }
  return { cell, plan };
}

function eventCellRef(cell) {
  return canonicalClone({
    ordinal: cell.ordinal,
    opaque_cell_id: cell.opaque_cell_id,
    cell_sha256: canonicalSha256(cell),
  });
}

function verifyResourceOrdinalSet(value, field, resourceCount) {
  if (!Array.isArray(value)) fail(`${field}_invalid`);
  const seen = new Set();
  for (const [index, ordinal] of value.entries()) {
    expectPositiveInteger(ordinal, field);
    if (ordinal > resourceCount || seen.has(ordinal)
      || (index > 0 && value[index - 1] >= ordinal)) fail(`${field}_invalid`);
    seen.add(ordinal);
  }
  return seen;
}

function verifyCleanupOwnerKinds(value, field) {
  if (!Array.isArray(value)) fail(`${field}_invalid`);
  const kinds = [...value];
  if (kinds.some((kind) => typeof kind !== "string"
      || !CLEANUP_OWNER_KIND_SET.has(kind))
    || new Set(kinds).size !== kinds.length
    || kinds.some((kind, index) => index > 0 && kinds[index - 1] >= kind)) {
    fail(`${field}_invalid`);
  }
  return kinds;
}

export function buildOwnerCleanupReceiptV1(inputValue) {
  const input = expectExactRecord(inputValue, [
    "closedOwnerKinds", "failedOwnerKinds", "ownerKinds",
  ], "owner_cleanup_receipt_build_input");
  if (!Array.isArray(input.ownerKinds)
    || !Array.isArray(input.closedOwnerKinds)
    || !Array.isArray(input.failedOwnerKinds)) {
    fail("owner_cleanup_build_kinds_invalid");
  }
  const ownerKinds = verifyCleanupOwnerKinds(
    [...input.ownerKinds].sort(),
    "owner_cleanup_build_owner_kinds",
  );
  const closed = verifyCleanupOwnerKinds(
    [...input.closedOwnerKinds].sort(),
    "owner_cleanup_build_closed_owner_kinds",
  );
  const failed = verifyCleanupOwnerKinds(
    [...input.failedOwnerKinds].sort(),
    "owner_cleanup_build_failed_owner_kinds",
  );
  if ([...closed, ...failed].some((kind) => !ownerKinds.includes(kind))
    || new Set([...closed, ...failed]).size !== closed.length + failed.length) {
    fail("owner_cleanup_build_binding_invalid");
  }
  const cleanupConfirmed = failed.length === 0 && closed.length === ownerKinds.length;
  const body = canonicalClone({
    schema_version: "aionis_pilot_owner_cleanup_receipt_v1",
    owner_count: ownerKinds.length,
    close_attempt_count: closed.length + failed.length,
    closed_owner_kinds: closed,
    failed_owner_kinds: failed,
    cleanup_confirmed: cleanupConfirmed,
    state: cleanupConfirmed ? "cleanup_confirmed" : "cleanup_incomplete",
  });
  return verifyOwnerCleanupReceiptV1({
    ...body,
    cleanup_receipt_sha256: canonicalSha256(body),
  }, { ownerKinds });
}

export function verifyOwnerCleanupReceiptV1(value, options) {
  const expected = expectExactRecord(options, [
    "ownerKinds",
  ], "owner_cleanup_receipt_options");
  if (!Array.isArray(expected.ownerKinds)) fail("owner_cleanup_expected_owner_kinds_invalid");
  const ownerKinds = verifyCleanupOwnerKinds(
    [...expected.ownerKinds].sort(),
    "owner_cleanup_expected_owner_kinds",
  );
  const receipt = expectExactRecord(
    value,
    OWNER_CLEANUP_RECEIPT_KEYS,
    "owner_cleanup_receipt",
  );
  if (receipt.schema_version !== "aionis_pilot_owner_cleanup_receipt_v1"
    || !Number.isSafeInteger(receipt.owner_count) || receipt.owner_count < 0
    || !Number.isSafeInteger(receipt.close_attempt_count)
    || receipt.close_attempt_count < 0
    || typeof receipt.cleanup_confirmed !== "boolean") {
    fail("owner_cleanup_shape_invalid");
  }
  const closed = verifyCleanupOwnerKinds(
    receipt.closed_owner_kinds,
    "owner_cleanup_closed_owner_kinds",
  );
  const failed = verifyCleanupOwnerKinds(
    receipt.failed_owner_kinds,
    "owner_cleanup_failed_owner_kinds",
  );
  const observed = [...closed, ...failed].sort();
  const expectedConfirmed = failed.length === 0
    && closed.length === ownerKinds.length
    && closed.every((kind, index) => kind === ownerKinds[index]);
  if (receipt.owner_count !== ownerKinds.length
    || receipt.close_attempt_count !== observed.length
    || receipt.close_attempt_count !== receipt.owner_count
    || observed.some((kind, index) => kind !== ownerKinds[index])
    || new Set(observed).size !== observed.length
    || receipt.cleanup_confirmed !== expectedConfirmed
    || receipt.state !== (expectedConfirmed ? "cleanup_confirmed" : "cleanup_incomplete")) {
    fail("owner_cleanup_binding_invalid");
  }
  verifySelfHash(receipt, "cleanup_receipt_sha256", "owner_cleanup_receipt");
  return canonicalClone(receipt);
}

export function buildResourceCleanupReceiptV1(inputValue) {
  const input = expectExactRecord(inputValue, [
    "closedResourceOrdinals", "failedResourceOrdinals", "ownerCleanupReceipt",
    "ownerKinds", "resourceCount",
  ], "resource_cleanup_receipt_build_input");
  expectPositiveInteger(input.resourceCount, "resource_cleanup_build_resource_count");
  if (!Array.isArray(input.closedResourceOrdinals)
    || !Array.isArray(input.failedResourceOrdinals)) {
    fail("resource_cleanup_build_ordinals_invalid");
  }
  const closed = [...input.closedResourceOrdinals].sort((left, right) => left - right);
  const failed = [...input.failedResourceOrdinals].sort((left, right) => left - right);
  const ownerCleanupReceipt = verifyOwnerCleanupReceiptV1(input.ownerCleanupReceipt, {
    ownerKinds: input.ownerKinds,
  });
  const cleanupConfirmed = failed.length === 0 && closed.length === input.resourceCount
    && ownerCleanupReceipt.cleanup_confirmed;
  const body = canonicalClone({
    schema_version: "aionis_pilot_resource_cleanup_receipt_v1",
    resource_count: input.resourceCount,
    close_attempt_count: closed.length + failed.length,
    closed_resource_ordinals: closed,
    failed_resource_ordinals: failed,
    owner_cleanup_receipt: ownerCleanupReceipt,
    owner_cleanup_receipt_sha256: ownerCleanupReceipt.cleanup_receipt_sha256,
    cleanup_confirmed: cleanupConfirmed,
    state: cleanupConfirmed ? "cleanup_confirmed" : "cleanup_incomplete",
  });
  return verifyResourceCleanupReceiptV1({
    ...body,
    cleanup_receipt_sha256: canonicalSha256(body),
  }, { ownerKinds: input.ownerKinds, resourceCount: input.resourceCount });
}

export function verifyResourceCleanupReceiptV1(value, options) {
  const expected = expectExactRecord(options, [
    "ownerKinds", "resourceCount",
  ], "resource_cleanup_receipt_options");
  expectPositiveInteger(expected.resourceCount, "resource_cleanup_expected_resource_count");
  const receipt = expectExactRecord(
    value,
    RESOURCE_CLEANUP_RECEIPT_KEYS,
    "resource_cleanup_receipt",
  );
  if (receipt.schema_version !== "aionis_pilot_resource_cleanup_receipt_v1") {
    fail("resource_cleanup_schema_invalid");
  }
  expectPositiveInteger(receipt.resource_count, "resource_cleanup_resource_count");
  expectNonNegativeInteger(
    receipt.close_attempt_count,
    "resource_cleanup_close_attempt_count",
  );
  if (typeof receipt.cleanup_confirmed !== "boolean") {
    fail("resource_cleanup_confirmed_invalid");
  }
  const closed = verifyResourceOrdinalSet(
    receipt.closed_resource_ordinals,
    "resource_cleanup_closed_resource_ordinals",
    receipt.resource_count,
  );
  const failed = verifyResourceOrdinalSet(
    receipt.failed_resource_ordinals,
    "resource_cleanup_failed_resource_ordinals",
    receipt.resource_count,
  );
  if ([...closed].some((ordinal) => failed.has(ordinal))) {
    fail("resource_cleanup_ordinal_overlap");
  }
  const ownerCleanupReceipt = verifyOwnerCleanupReceiptV1(
    receipt.owner_cleanup_receipt,
    { ownerKinds: expected.ownerKinds },
  );
  const expectedConfirmed = failed.size === 0
    && closed.size === receipt.resource_count
    && receipt.close_attempt_count === receipt.resource_count
    && ownerCleanupReceipt.cleanup_confirmed;
  if (receipt.resource_count !== expected.resourceCount
    || receipt.close_attempt_count !== closed.size + failed.size
    || receipt.close_attempt_count !== receipt.resource_count
    || receipt.owner_cleanup_receipt_sha256
      !== ownerCleanupReceipt.cleanup_receipt_sha256
    || receipt.cleanup_confirmed !== expectedConfirmed
    || receipt.state !== (expectedConfirmed ? "cleanup_confirmed" : "cleanup_incomplete")) {
    fail("resource_cleanup_binding_invalid");
  }
  verifySelfHash(receipt, "cleanup_receipt_sha256", "resource_cleanup_receipt");
  return canonicalClone({ ...receipt, owner_cleanup_receipt: ownerCleanupReceipt });
}

export function verifyResourceCleanupConfirmedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256", "ownerKinds", "plan",
  ], "resource_cleanup_confirmed_payload_options");
  const plan = verifyPilotPlanV1(expected.plan);
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "resource_cleanup_confirmed_authorization_sha256",
  );
  const payload = expectExactRecord(
    value,
    RESOURCE_CLEANUP_CONFIRMED_KEYS,
    "resource_cleanup_confirmed_payload",
  );
  const receipt = verifyResourceCleanupReceiptV1(payload.cleanup_receipt, {
    ownerKinds: expected.ownerKinds,
    resourceCount: plan.schedule.length,
  });
  if (payload.schema_version !== "aionis_pilot_resource_cleanup_confirmed_v1"
    || payload.pilot_id !== plan.pilot_id
    || payload.plan_sha256 !== plan.plan_sha256
    || payload.execution_authorization_sha256 !== authorizationSha256
    || payload.cleanup_receipt_sha256 !== receipt.cleanup_receipt_sha256
    || payload.state !== "claim_required_cleanup_confirmed"
    || !receipt.cleanup_confirmed) {
    fail("resource_cleanup_confirmed_binding_invalid");
  }
  return canonicalClone({ ...payload, cleanup_receipt: receipt });
}

export function verifyRunAbortedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256", "cell", "ownerKinds", "plan",
  ], "run_aborted_payload_options");
  const plan = verifyPilotPlanV1(expected.plan);
  const cell = expected.cell === null ? null : verifyPlanCell(plan, expected.cell).cell;
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "run_aborted_authorization_sha256",
  );
  const payload = expectExactRecord(value, RUN_ABORTED_KEYS, "run_aborted_payload");
  if (payload.schema_version !== "aionis_pilot_run_aborted_v1"
    || payload.pilot_id !== plan.pilot_id
    || payload.plan_sha256 !== plan.plan_sha256
    || payload.execution_authorization_sha256 !== authorizationSha256
    || payload.state !== "aborted_claim_ineligible_no_resume"
    || !PILOT_RUN_ABORT_FAILURE_STAGES_V1.includes(payload.failure_stage)
    || !PILOT_RUN_ABORT_FAILURE_CLASSES_V1.includes(payload.failure_class)) {
    fail("run_aborted_binding_invalid");
  }
  expectSha256(
    payload.failure_evidence_ref_sha256,
    "run_aborted_failure_evidence_ref_sha256",
  );
  expectNonNegativeInteger(payload.completed_cell_count, "run_aborted_completed_cell_count");
  expectPositiveInteger(payload.next_attempt_ordinal, "run_aborted_next_attempt_ordinal");
  expectNonNegativeInteger(
    payload.provider_attempt_reservation_count,
    "run_aborted_provider_attempt_reservation_count",
  );
  expectNonNegativeInteger(
    payload.provider_attempt_completion_count,
    "run_aborted_provider_attempt_completion_count",
  );
  if (payload.active_attempt_ordinal !== null) {
    expectPositiveInteger(payload.active_attempt_ordinal, "run_aborted_active_attempt_ordinal");
  }
  if (!ACTIVE_PROVIDER_ATTEMPT_STATES.has(payload.active_provider_attempt_state)
    || payload.completed_cell_count > plan.schedule.length
    || payload.next_attempt_ordinal !== payload.completed_cell_count + 1
    || payload.next_attempt_ordinal > plan.schedule.length + 1
    || payload.provider_attempt_completion_count
      > payload.provider_attempt_reservation_count) {
    fail("run_aborted_attempt_counts_invalid");
  }
  const completed = payload.completed_cell_count;
  const activeState = payload.active_provider_attempt_state;
  const expectedCounts = activeState === "request_may_have_started_burned"
    ? { reservations: completed + 1, completions: completed }
    : activeState === "provider_completed_pending_cell_result"
      ? { reservations: completed + 1, completions: completed + 1 }
      : { reservations: completed, completions: completed };
  const expectedActiveOrdinal = activeState === "no_active_attempt"
    ? null
    : payload.next_attempt_ordinal;
  if (payload.provider_attempt_reservation_count !== expectedCounts.reservations
    || payload.provider_attempt_completion_count !== expectedCounts.completions
    || payload.active_attempt_ordinal !== expectedActiveOrdinal
    || (expectedActiveOrdinal !== null && expectedActiveOrdinal > plan.schedule.length)) {
    fail("run_aborted_attempt_state_invalid");
  }
  const expectedCellRef = cell === null ? null : eventCellRef(cell);
  if (!sameCanonical(payload.failing_cell_ref, expectedCellRef)) {
    fail("run_aborted_cell_binding_invalid");
  }
  const cleanupReceipt = verifyResourceCleanupReceiptV1(payload.cleanup_receipt, {
    ownerKinds: expected.ownerKinds,
    resourceCount: plan.schedule.length,
  });
  if (payload.cleanup_receipt_sha256 !== cleanupReceipt.cleanup_receipt_sha256
    || payload.cleanup_confirmed !== cleanupReceipt.cleanup_confirmed) {
    fail("run_aborted_cleanup_binding_invalid");
  }
  return canonicalClone({ ...payload, cleanup_receipt: cleanupReceipt });
}

export function verifyPilotRunEventEnvelopeV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256",
    "cell",
    "eventKind",
    "plan",
    "previousEventSha256",
    "sequence",
  ], "pilot_run_event_envelope_options");
  const plan = verifyPilotPlanV1(expected.plan);
  const cell = expected.cell === null ? null : verifyPlanCell(plan, expected.cell).cell;
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "pilot_run_event_authorization_sha256",
  );
  expectPositiveInteger(expected.sequence, "pilot_run_event_expected_sequence");
  nullableSha256(
    expected.previousEventSha256,
    "pilot_run_event_expected_previous_event_sha256",
  );
  const event = expectExactRecord(value, EVENT_KEYS, "pilot_run_event");
  expectPositiveInteger(event.sequence, "pilot_run_event_sequence");
  expectSha256(event.payload_sha256, "pilot_run_event_payload_sha256");
  expectCanonicalTimestamp(event.observed_at, "pilot_run_event_observed_at");
  expectSha256(event.event_sha256, "pilot_run_event_sha256");
  if (event.schema_version !== "aionis_pilot_run_event_v1"
    || event.sequence !== expected.sequence
    || event.event_kind !== expected.eventKind
    || event.pilot_id !== plan.pilot_id
    || event.plan_sha256 !== plan.plan_sha256
    || event.execution_authorization_sha256 !== authorizationSha256
    || event.previous_event_sha256 !== expected.previousEventSha256
    || !sameCanonical(event.cell_ref, cell === null ? null : eventCellRef(cell))) {
    fail("event_binding_invalid");
  }
  verifySelfHash(event, "event_sha256", "event");
  return canonicalClone(event);
}

export async function verifyCellArmPreparedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "cell", "pilotCase", "plan",
  ], "cell_arm_prepared_payload_options");
  const { cell, plan } = verifyPlanCell(expected.plan, expected.cell);
  const pilotCase = verifyPilotCaseV1(expected.pilotCase);
  if (pilotCase.case_id !== cell.case_id || pilotCase.case_sha256 !== cell.case_sha256) {
    fail("prepared_case_binding_invalid");
  }
  const preparedArm = canonicalClone(value);
  const modelInput = buildAgentModelInputV1({ pilotCase, preparedArm });
  if (!sameCanonical(preparedArm.cell, cell)
    || modelInput.public_prompt_sha256
      !== pilotCase.public_agent_input.task_prompt_sha256
    || cell.pilot_id !== plan.pilot_id) {
    fail("prepared_cell_binding_invalid");
  }
  return preparedArm;
}

export async function verifyModelInputFrozenPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "cell", "pilotCase", "plan", "preparedArm", "preparedArmEventSha256",
  ], "model_input_frozen_payload_options");
  const preparedArm = await verifyCellArmPreparedPayloadV1(expected.preparedArm, {
    cell: expected.cell,
    pilotCase: expected.pilotCase,
    plan: expected.plan,
  });
  const preparedArmEventSha256 = expectSha256(
    expected.preparedArmEventSha256,
    "model_input_prepared_arm_event_sha256",
  );
  const payload = expectExactRecord(value, [
    "agent_model_input", "prepared_arm_event_sha256", "schema_version",
  ], "model_input_frozen_payload");
  const recomputed = buildAgentModelInputV1({
    pilotCase: expected.pilotCase,
    preparedArm,
  });
  if (payload.schema_version !== "aionis_pilot_model_input_frozen_v1"
    || payload.prepared_arm_event_sha256 !== preparedArmEventSha256
    || !sameCanonical(payload.agent_model_input, recomputed)) {
    fail("model_input_binding_invalid");
  }
  return canonicalClone(payload);
}

export async function verifyProviderAttemptReservationPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256",
    "cell",
    "modelInput",
    "plan",
    "previousCellResultEventSha256",
  ], "provider_attempt_reservation_payload_options");
  const { cell, plan } = verifyPlanCell(expected.plan, expected.cell);
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "reservation_authorization_sha256",
  );
  nullableSha256(
    expected.previousCellResultEventSha256,
    "reservation_previous_cell_result_event_sha256",
  );
  const { deepSeekCanonicalRequestSha256V1 } = await import("./deepseek-provider.mjs");
  const canonicalRequestSha256 = deepSeekCanonicalRequestSha256V1(
    expected.modelInput.messages,
    plan.model_protocol,
  );
  if (expected.modelInput.model_input_sha256
      !== canonicalSha256(expected.modelInput.messages)) {
    fail("reservation_model_input_self_hash_invalid");
  }
  const reservation = expectExactRecord(
    value,
    RESERVATION_KEYS,
    "provider_attempt_reservation_payload",
  );
  if (reservation.schema_version !== "aionis_pilot_provider_attempt_reservation_v1"
    || reservation.pilot_id !== plan.pilot_id
    || reservation.plan_sha256 !== plan.plan_sha256
    || reservation.execution_authorization_sha256 !== authorizationSha256
    || reservation.attempt_ordinal !== cell.ordinal
    || reservation.opaque_cell_id !== cell.opaque_cell_id
    || reservation.cell_sha256 !== canonicalSha256(cell)
    || reservation.isolation_sha256 !== cell.isolation.isolation_sha256
    || reservation.model_input_sha256 !== expected.modelInput.model_input_sha256
    || reservation.canonical_request_sha256 !== canonicalRequestSha256
    || reservation.previous_cell_result_event_sha256
      !== expected.previousCellResultEventSha256
    || reservation.state !== "reserved_fail_closed") {
    fail("reservation_binding_invalid");
  }
  verifySelfHash(reservation, "reservation_sha256", "reservation");
  return canonicalClone(reservation);
}

export async function verifyProviderRequestStartedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256",
    "cell",
    "plan",
    "reservation",
    "reservationEventSha256",
  ], "provider_request_started_payload_options");
  const { cell, plan } = verifyPlanCell(expected.plan, expected.cell);
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "request_started_authorization_sha256",
  );
  const reservationEventSha256 = expectSha256(
    expected.reservationEventSha256,
    "request_started_reservation_event_sha256",
  );
  const requestStarted = expectExactRecord(
    value,
    REQUEST_STARTED_KEYS,
    "provider_request_started_payload",
  );
  if (requestStarted.schema_version !== "aionis_pilot_provider_request_started_v1"
    || requestStarted.pilot_id !== plan.pilot_id
    || requestStarted.plan_sha256 !== plan.plan_sha256
    || requestStarted.execution_authorization_sha256 !== authorizationSha256
    || requestStarted.attempt_ordinal !== cell.ordinal
    || requestStarted.opaque_cell_id !== cell.opaque_cell_id
    || requestStarted.reservation_sha256 !== expected.reservation.reservation_sha256
    || requestStarted.reservation_event_sha256 !== reservationEventSha256
    || requestStarted.canonical_request_sha256
      !== expected.reservation.canonical_request_sha256
    || requestStarted.state !== "http_may_start_after_this_event") {
    fail("request_started_binding_invalid");
  }
  verifySelfHash(requestStarted, "request_started_sha256", "request_started");
  return canonicalClone(requestStarted);
}

export async function verifyProviderAttemptCompletedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "authorizationSha256",
    "cell",
    "modelInput",
    "plan",
    "requestStartedEventSha256",
    "reservation",
  ], "provider_attempt_completed_payload_options");
  const { cell, plan } = verifyPlanCell(expected.plan, expected.cell);
  const authorizationSha256 = expectSha256(
    expected.authorizationSha256,
    "completion_authorization_sha256",
  );
  const requestStartedEventSha256 = expectSha256(
    expected.requestStartedEventSha256,
    "completion_request_started_event_sha256",
  );
  const completion = expectExactRecord(
    value,
    COMPLETION_KEYS,
    "provider_attempt_completed_payload",
  );
  if (completion.schema_version !== "aionis_pilot_provider_attempt_completed_v1"
    || completion.pilot_id !== plan.pilot_id
    || completion.plan_sha256 !== plan.plan_sha256
    || completion.execution_authorization_sha256 !== authorizationSha256
    || completion.attempt_ordinal !== cell.ordinal
    || completion.opaque_cell_id !== cell.opaque_cell_id
    || completion.reservation_sha256 !== expected.reservation.reservation_sha256
    || completion.request_started_event_sha256 !== requestStartedEventSha256
    || completion.state !== "completed"
    || !sameCanonical(completion.messages, expected.modelInput.messages)) {
    fail("completion_binding_invalid");
  }
  const {
    verifyDeepSeekRequestReceiptV1,
    verifyDeepSeekResponseReceiptV1,
  } = await import("./deepseek-provider.mjs");
  const requestReceipt = verifyDeepSeekRequestReceiptV1(completion.request_receipt, {
    cell,
    messages: completion.messages,
    modelProtocol: plan.model_protocol,
  });
  const responseReceipt = verifyDeepSeekResponseReceiptV1(completion.response_receipt, {
    assistantMessage: completion.assistant_message,
    cell,
    messages: completion.messages,
    modelProtocol: plan.model_protocol,
    requestReceipt,
  });
  if (requestReceipt.attempt_ordinal !== cell.ordinal
    || responseReceipt.attempt_ordinal !== cell.ordinal
    || requestReceipt.execution_authorization_sha256 !== authorizationSha256
    || requestReceipt.provider_attempt_reservation_sha256
      !== expected.reservation.reservation_sha256
    || requestReceipt.provider_request_started_event_sha256
      !== requestStartedEventSha256
    || requestReceipt.canonical_request_sha256
      !== expected.reservation.canonical_request_sha256
    || responseReceipt.canonical_request_sha256
      !== expected.reservation.canonical_request_sha256) {
    fail("completion_receipt_binding_invalid");
  }
  verifySelfHash(completion, "attempt_completion_sha256", "completion");
  return canonicalClone({
    ...completion,
    request_receipt: requestReceipt,
    response_receipt: responseReceipt,
  });
}

export async function verifyCellResultRecordedPayloadV1(value, options) {
  const expected = expectExactRecord(options, [
    "cell",
    "completion",
    "completionEventSha256",
    "modelInput",
    "pilotCase",
    "plan",
    "verifierPublicKey",
  ], "cell_result_recorded_payload_options");
  const { cell, plan } = verifyPlanCell(expected.plan, expected.cell);
  const completionEventSha256 = expectSha256(
    expected.completionEventSha256,
    "cell_result_completion_event_sha256",
  );
  const payload = expectExactRecord(value, [
    "cell_result", "provider_attempt_completion_event_sha256", "schema_version",
  ], "cell_result_recorded_payload");
  if (payload.schema_version !== "aionis_pilot_cell_result_recorded_v1"
    || payload.provider_attempt_completion_event_sha256 !== completionEventSha256) {
    fail("cell_result_event_binding_invalid");
  }
  const { verifyPilotCellResultV1 } = await import("./pilot-result.mjs");
  const result = verifyPilotCellResultV1(payload.cell_result, {
    plan,
    pilotCase: expected.pilotCase,
    verifierPublicKey: expected.verifierPublicKey,
  });
  if (!sameCanonical(result.cell, cell)
    || !sameCanonical(result.agent_model_input, expected.modelInput)
    || !sameCanonical(
      result.provider_request_receipt,
      expected.completion.request_receipt,
    )
    || !sameCanonical(
      result.provider_response_receipt,
      expected.completion.response_receipt,
    )
    || !sameCanonical(result.assistant_message, expected.completion.assistant_message)) {
    fail("cell_result_completion_binding_invalid");
  }
  return canonicalClone({ ...payload, cell_result: result });
}
